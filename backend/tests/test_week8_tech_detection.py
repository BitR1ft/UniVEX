"""
Week 8 Test Suite – Technology Detection & Fingerprinting

Covers:
  Day 49 – WappalyzerOrchestrator: config, header fingerprinting,
            TLS/security-header analysis, normalisation, package export
  Day 50 – ShodanOrchestrator: config, InternetDB normalisation,
            port→Endpoint, CPE→Technology, CVE→Finding, phase B export
"""
from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.recon.canonical_schemas import Endpoint, Finding, ReconResult, Severity, Technology
from app.recon.http_probing.wappalyzer_orchestrator import (
    WappalyzerOrchestrator,
    WappalyzerOrchestratorConfig,
    _fingerprint_headers,
    analyse_security_headers,
)
from app.recon.port_scanning.shodan_orchestrator import (
    ShodanOrchestrator,
    ShodanOrchestratorConfig,
)


# ===========================================================================
# ===========================================================================

class TestWappalyzerOrchestratorConfig:
    def test_defaults(self):
        cfg = WappalyzerOrchestratorConfig()
        assert cfg.use_wappalyzer_cli is True
        assert cfg.use_header_fingerprinting is True
        assert cfg.analyse_security_headers is True
        assert cfg.timeout == 30

    def test_wappalyzer_optional(self):
        cfg = WappalyzerOrchestratorConfig(use_wappalyzer_cli=False)
        assert cfg.use_wappalyzer_cli is False


class TestWappalyzerOrchestratorInit:
    def test_valid_url_accepted(self):
        orch = WappalyzerOrchestrator("https://example.com")
        assert orch.target == "https://example.com"
        assert orch.TOOL_NAME == "wappalyzer"

    def test_invalid_target_raises(self):
        with pytest.raises(ValueError):
            WappalyzerOrchestrator("not-a-valid-target!!")

    def test_custom_config_stored(self):
        cfg = WappalyzerOrchestratorConfig(timeout=10)
        orch = WappalyzerOrchestrator("https://example.com", config=cfg)
        assert orch.wap_config.timeout == 10


class TestHeaderFingerprinting:
    def test_nginx_detected_from_server(self):
        headers = {"server": "nginx/1.24.0"}
        techs = _fingerprint_headers(headers)
        names = [t.name for t in techs]
        assert "nginx" in names

    def test_apache_detected(self):
        headers = {"server": "Apache/2.4.51 (Ubuntu)"}
        techs = _fingerprint_headers(headers)
        names = [t.name for t in techs]
        assert any("Apache" in n for n in names)

    def test_php_detected_from_x_powered_by(self):
        headers = {"x-powered-by": "PHP/8.1.0"}
        techs = _fingerprint_headers(headers)
        names = [t.name for t in techs]
        assert "PHP" in names

    def test_express_detected(self):
        headers = {"x-powered-by": "Express"}
        techs = _fingerprint_headers(headers)
        names = [t.name for t in techs]
        assert "Express.js" in names

    def test_empty_headers_returns_empty(self):
        techs = _fingerprint_headers({})
        assert techs == []

    def test_unknown_server_returns_empty(self):
        techs = _fingerprint_headers({"server": "CustomPrivateServer/99.0"})
        assert techs == []


class TestSecurityHeaderAnalysis:
    def test_hsts_present(self):
        headers = {"strict-transport-security": "max-age=31536000; includeSubDomains"}
        result = analyse_security_headers(headers)
        assert result["Strict-Transport-Security"]["present"] is True

    def test_csp_absent(self):
        result = analyse_security_headers({})
        assert result["Content-Security-Policy"]["present"] is False

    def test_all_six_headers_checked(self):
        result = analyse_security_headers({})
        assert len(result) == 6


class TestWappalyzerNormalisation:
    def test_header_techs_in_result(self):
        raw = {
            "wap_techs": [],
            "headers": {"server": "nginx/1.24.0"},
        }
        cfg = WappalyzerOrchestratorConfig(use_wappalyzer_cli=False)
        orch = WappalyzerOrchestrator("https://example.com", config=cfg)
        result = orch._normalise(raw)
        assert isinstance(result, ReconResult)
        assert result.technology_count >= 1

    def test_wappalyzer_cli_techs_merged(self):
        wap_tech = Technology(
            name="WordPress", version="6.0", category="CMS",
            url="https://example.com",
        )
        raw = {"wap_techs": [wap_tech], "headers": {}}
        cfg = WappalyzerOrchestratorConfig(use_wappalyzer_cli=True)
        orch = WappalyzerOrchestrator("https://example.com", config=cfg)
        result = orch._normalise(raw)
        assert result.technology_count == 1
        assert result.technologies[0].name == "WordPress"

    def test_deduplication_by_name(self):
        """Same technology from Wappalyzer CLI and header should appear once."""
        wap_tech = Technology(
            name="nginx", version="1.24", category="Web Server",
            url="https://example.com",
        )
        raw = {
            "wap_techs": [wap_tech],
            "headers": {"server": "nginx/1.24.0"},
        }
        cfg = WappalyzerOrchestratorConfig()
        orch = WappalyzerOrchestrator("https://example.com", config=cfg)
        result = orch._normalise(raw)
        names = [t.name.lower() for t in result.technologies]
        assert names.count("nginx") == 1

    def test_empty_raw_returns_empty_result(self):
        cfg = WappalyzerOrchestratorConfig(use_wappalyzer_cli=False, use_header_fingerprinting=False)
        orch = WappalyzerOrchestrator("https://example.com", config=cfg)
        result = orch._normalise({"wap_techs": [], "headers": {}})
        assert result.technology_count == 0

    @pytest.mark.asyncio
    async def test_pre_run_does_not_raise(self):
        """WappalyzerOrchestrator._pre_run() should not require a binary."""
        orch = WappalyzerOrchestrator("https://example.com")
        await orch._pre_run()  # must not raise

    @pytest.mark.asyncio
    async def test_fingerprint_targets_concurrent(self):
        targets = ["https://a.example.com", "https://b.example.com"]
        cfg = WappalyzerOrchestratorConfig(
            use_wappalyzer_cli=False, use_header_fingerprinting=False
        )
        # Mock _execute to return empty
        with patch.object(
            WappalyzerOrchestrator, "_execute", AsyncMock(return_value={"wap_techs": [], "headers": {}})
        ):
            results = await WappalyzerOrchestrator.fingerprint_targets(targets, config=cfg)
        assert len(results) == 2


# ===========================================================================
# ===========================================================================

_INTERNETDB_RESPONSE = {
    "ip": "203.0.113.1",
    "ports": [80, 443, 8080],
    "cpes": ["cpe:/a:nginx:nginx:1.24", "cpe:/a:openssl:openssl:1.1.1"],
    "hostnames": ["www.example.com"],
    "tags": [],
    "vulns": ["CVE-2021-44228", "CVE-2022-0778"],
}


class TestShodanOrchestratorConfig:
    def test_defaults(self):
        cfg = ShodanOrchestratorConfig()
        assert cfg.use_internetdb is True
        assert cfg.use_full_api is False
        assert cfg.api_key is None
        assert cfg.max_concurrent == 5

    def test_full_api_requires_key(self):
        cfg = ShodanOrchestratorConfig(api_key="test-key", use_full_api=True)
        assert cfg.use_full_api is True
        assert cfg.api_key == "test-key"


class TestShodanOrchestratorInit:
    def test_valid_ip_accepted(self):
        orch = ShodanOrchestrator("203.0.113.1")
        assert orch.target == "203.0.113.1"
        assert orch.TOOL_NAME == "shodan"

    def test_invalid_target_raises(self):
        with pytest.raises(ValueError):
            ShodanOrchestrator("")

    def test_custom_config_stored(self):
        cfg = ShodanOrchestratorConfig(timeout=5)
        orch = ShodanOrchestrator("203.0.113.1", config=cfg)
        assert orch.shodan_config.timeout == 5

    @pytest.mark.asyncio
    async def test_pre_run_does_not_raise(self):
        """ShodanOrchestrator requires no binary."""
        orch = ShodanOrchestrator("203.0.113.1")
        await orch._pre_run()


class TestShodanNormalisationInternetDB:
    def test_ports_become_endpoints(self):
        orch = ShodanOrchestrator("203.0.113.1")
        result = orch._normalise({"internetdb": _INTERNETDB_RESPONSE, "full_api": {}})
        assert result.endpoint_count == 3

    def test_endpoint_urls_contain_port(self):
        orch = ShodanOrchestrator("203.0.113.1")
        result = orch._normalise({"internetdb": _INTERNETDB_RESPONSE, "full_api": {}})
        urls = [ep.url for ep in result.endpoints]
        assert "tcp://203.0.113.1:80" in urls
        assert "tcp://203.0.113.1:443" in urls

    def test_endpoints_are_live(self):
        orch = ShodanOrchestrator("203.0.113.1")
        result = orch._normalise({"internetdb": _INTERNETDB_RESPONSE, "full_api": {}})
        assert all(ep.is_live is True for ep in result.endpoints)

    def test_cpes_become_technologies(self):
        orch = ShodanOrchestrator("203.0.113.1")
        result = orch._normalise({"internetdb": _INTERNETDB_RESPONSE, "full_api": {}})
        assert result.technology_count == 2

    def test_technology_has_cpe(self):
        orch = ShodanOrchestrator("203.0.113.1")
        result = orch._normalise({"internetdb": _INTERNETDB_RESPONSE, "full_api": {}})
        cpes = [t.cpe for t in result.technologies]
        assert "cpe:/a:nginx:nginx:1.24" in cpes

    def test_vulns_become_findings(self):
        orch = ShodanOrchestrator("203.0.113.1")
        result = orch._normalise({"internetdb": _INTERNETDB_RESPONSE, "full_api": {}})
        assert result.finding_count == 2

    def test_findings_have_cve_ids(self):
        orch = ShodanOrchestrator("203.0.113.1")
        result = orch._normalise({"internetdb": _INTERNETDB_RESPONSE, "full_api": {}})
        all_cves = [cve for f in result.findings for cve in (f.cve_ids or [])]
        assert "CVE-2021-44228" in all_cves
        assert "CVE-2022-0778" in all_cves

    def test_findings_severity_high(self):
        orch = ShodanOrchestrator("203.0.113.1")
        result = orch._normalise({"internetdb": _INTERNETDB_RESPONSE, "full_api": {}})
        for f in result.findings:
            assert f.severity == Severity.HIGH

    def test_empty_internetdb_returns_empty_result(self):
        orch = ShodanOrchestrator("203.0.113.1")
        result = orch._normalise({"internetdb": {}, "full_api": {}})
        assert result.endpoint_count == 0
        assert result.finding_count == 0

    @pytest.mark.asyncio
    async def test_run_returns_recon_result(self):
        """Full pipeline test with mocked httpx."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = _INTERNETDB_RESPONSE

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch("httpx.AsyncClient", return_value=mock_client):
            orch = ShodanOrchestrator("203.0.113.1")
            result = await orch.run()

        assert isinstance(result, ReconResult)
        assert result.success is True
        assert result.endpoint_count == 3

    @pytest.mark.asyncio
    async def test_scan_ips_concurrent(self):
        ips = ["203.0.113.1", "203.0.113.2"]
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = _INTERNETDB_RESPONSE

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)

        cfg = ShodanOrchestratorConfig(rate_limit_delay=0.0)
        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await ShodanOrchestrator.scan_ips(ips, config=cfg)
        assert len(results) == 2


# ===========================================================================
# ===========================================================================

class TestWeek8PackageExports:
    def test_wappalyzer_orchestrator_exported_from_http_probing(self):
        from app.recon.http_probing import WappalyzerOrchestrator as Exported
        assert Exported is WappalyzerOrchestrator

    def test_shodan_orchestrator_exported_from_port_scanning(self):
        from app.recon.port_scanning import ShodanOrchestrator as Exported
        assert Exported is ShodanOrchestrator
