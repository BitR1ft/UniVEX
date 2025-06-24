"""
Week 6 Test Suite – Vulnerability Scanning

Covers:
  Day 35 – NucleiOrchestratorConfig & NucleiOrchestrator setup
  Day 36 – Async execution, rate limiting, command building
  Day 37 – NucleiTemplateUpdater versioning & state persistence
  Day 38 – Nuclei results normalisation → canonical Finding / ReconResult
  Day 39 – /api/scans/nuclei endpoint contracts
  Day 40 – InteractshClient payload generation, OOBInteraction model
  Day 41 – Vulnerability scanning documentation contract (README, exports)
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.recon.canonical_schemas import Finding, ReconResult, Severity
from app.recon.vuln_scanning.nuclei_orchestrator import (
    NucleiOrchestrator,
    NucleiOrchestratorConfig,
    _extract_cves,
    _extract_cwes,
    _SEVERITY_MAP,
)
from app.recon.vuln_scanning.template_updater import (
    NucleiTemplateUpdater,
    TemplateVersionInfo,
)
from app.recon.vuln_scanning.interactsh_client import (
    InteractshClient,
    OOBInteraction,
)
from app.recon.vuln_scanning import (
    NucleiOrchestrator as ExportedOrchestrator,
    NucleiOrchestratorConfig as ExportedConfig,
    NucleiTemplateUpdater as ExportedUpdater,
    InteractshClient as ExportedInteractsh,
)


# ===========================================================================
# ===========================================================================

class TestNucleiOrchestratorConfig:
    def test_default_severity_filter(self):
        cfg = NucleiOrchestratorConfig()
        assert "critical" in cfg.severity_filter
        assert "high" in cfg.severity_filter

    def test_default_excludes_dos(self):
        cfg = NucleiOrchestratorConfig()
        assert "dos" in cfg.exclude_tags

    def test_interactsh_disabled_by_default(self):
        cfg = NucleiOrchestratorConfig()
        assert cfg.interactsh_enabled is False

    def test_auto_update_disabled_by_default(self):
        # auto_update is handled externally by TemplateUpdater
        cfg = NucleiOrchestratorConfig()
        assert cfg.auto_update_templates is False


class TestNucleiOrchestratorInit:
    def test_valid_target_accepted(self):
        orch = NucleiOrchestrator("https://example.com")
        assert orch.target == "https://example.com"
        assert orch.TOOL_NAME == "nuclei"
        assert orch.BINARY == "nuclei"

    def test_invalid_target_raises(self):
        with pytest.raises(ValueError):
            NucleiOrchestrator("not a valid target!!")

    def test_custom_config_stored(self):
        cfg = NucleiOrchestratorConfig(rate_limit=50)
        orch = NucleiOrchestrator("example.com", config=cfg)
        assert orch.nuclei_config.rate_limit == 50


# ===========================================================================
# ===========================================================================

class TestNucleiCommandBuilding:
    def test_command_starts_with_nuclei(self):
        orch = NucleiOrchestrator("https://example.com")
        cmd = orch._build_command()
        assert cmd[0] == "nuclei"

    def test_single_target_uses_u_flag(self):
        orch = NucleiOrchestrator("https://example.com")
        cmd = orch._build_command()
        assert "-u" in cmd
        u_idx = cmd.index("-u")
        assert cmd[u_idx + 1] == "https://example.com"

    def test_severity_filter_in_command(self):
        cfg = NucleiOrchestratorConfig(severity_filter=["critical"])
        orch = NucleiOrchestrator("https://example.com", config=cfg)
        cmd = orch._build_command()
        assert "-s" in cmd
        idx = cmd.index("-s")
        assert "critical" in cmd[idx + 1]

    def test_exclude_tags_in_command(self):
        cfg = NucleiOrchestratorConfig(exclude_tags=["dos", "fuzz"])
        orch = NucleiOrchestrator("https://example.com", config=cfg)
        cmd = orch._build_command()
        assert "-exclude-tags" in cmd

    def test_json_output_flag_present(self):
        orch = NucleiOrchestrator("https://example.com")
        cmd = orch._build_command()
        assert "-json" in cmd

    def test_interactsh_flag_added_when_enabled(self):
        cfg = NucleiOrchestratorConfig(interactsh_enabled=True)
        orch = NucleiOrchestrator("https://example.com", config=cfg)
        cmd = orch._build_command()
        assert "-interactsh" in cmd

    def test_custom_interactsh_server_in_command(self):
        cfg = NucleiOrchestratorConfig(
            interactsh_enabled=True, interactsh_server="https://my.interact.sh"
        )
        orch = NucleiOrchestrator("https://example.com", config=cfg)
        cmd = orch._build_command()
        assert "-interactsh-url" in cmd
        url_idx = cmd.index("-interactsh-url")
        assert cmd[url_idx + 1] == "https://my.interact.sh"

    def test_rate_limit_in_command(self):
        cfg = NucleiOrchestratorConfig(rate_limit=50)
        orch = NucleiOrchestrator("https://example.com", config=cfg)
        cmd = orch._build_command()
        assert "-rate-limit" in cmd
        idx = cmd.index("-rate-limit")
        assert cmd[idx + 1] == "50"


# ===========================================================================
# ===========================================================================

class TestTemplateVersionInfo:
    def test_to_dict_and_from_dict_roundtrip(self):
        from datetime import datetime, timezone
        ts = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        info = TemplateVersionInfo(
            version="v9.8.7", updated_at=ts, success=True, message="OK"
        )
        d = info.to_dict()
        restored = TemplateVersionInfo.from_dict(d)
        assert restored.version == "v9.8.7"
        assert restored.success is True


class TestNucleiTemplateUpdater:
    def test_current_version_none_when_no_history(self, tmp_path):
        state = tmp_path / "state.json"
        updater = NucleiTemplateUpdater(state_file=state)
        assert updater.current_version() is None

    def test_history_preserved_after_reload(self, tmp_path):
        from datetime import datetime, timezone
        state = tmp_path / "state.json"
        updater = NucleiTemplateUpdater(state_file=state)
        ts = datetime.now(tz=timezone.utc)
        updater._history.append(
            TemplateVersionInfo(version="v1.0", updated_at=ts, success=True)
        )
        updater._save_state()

        # Reload
        updater2 = NucleiTemplateUpdater(state_file=state)
        assert len(updater2.update_history()) == 1
        assert updater2.current_version().version == "v1.0"

    def test_update_history_empty_by_default(self, tmp_path):
        state = tmp_path / "state.json"
        updater = NucleiTemplateUpdater(state_file=state)
        assert updater.update_history() == []

    @pytest.mark.asyncio
    async def test_update_records_failure_when_nuclei_missing(self, tmp_path):
        state = tmp_path / "state.json"
        updater = NucleiTemplateUpdater(state_file=state)
        # Simulate nuclei not being installed
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b"not found"))
        mock_proc.returncode = 127
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            info = await updater.update()
        assert isinstance(info, TemplateVersionInfo)
        assert len(updater.update_history()) == 1


# ===========================================================================
# ===========================================================================

_NUCLEI_JSON_FINDING = json.dumps({
    "template-id": "CVE-2021-44228",
    "info": {
        "name": "Log4Shell Remote Code Execution",
        "severity": "critical",
        "description": "Apache Log4j2 JNDI injection vulnerability.",
        "tags": ["cve", "rce", "log4j"],
        "reference": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228"],
        "remediation": "Upgrade Log4j to 2.15.0 or later.",
        "classification": {
            "cve-id": ["CVE-2021-44228"],
            "cwe-id": ["CWE-502"],
            "cvss-score": 10.0,
        },
    },
    "matched-at": "https://target.example.com:8080",
    "type": "http",
    "curl-command": "curl -X GET https://target.example.com:8080",
})

_NUCLEI_JSON_INFO_FINDING = json.dumps({
    "template-id": "tech-detect",
    "info": {
        "name": "Tech Detection",
        "severity": "info",
        "tags": ["tech"],
    },
    "matched-at": "https://target.example.com",
})


def _mock_nuclei_proc(output: str, returncode: int = 0):
    proc = AsyncMock()
    proc.communicate = AsyncMock(return_value=(output.encode(), b""))
    proc.returncode = returncode
    return proc


class TestNucleiCVEExtraction:
    def test_cve_extracted_from_template_id(self):
        record = {"template-id": "CVE-2021-44228", "info": {}}
        assert "CVE-2021-44228" in _extract_cves(record)

    def test_cve_extracted_from_classification(self):
        record = {
            "template-id": "other-template",
            "info": {"classification": {"cve-id": ["CVE-2023-9999"]}},
        }
        assert "CVE-2023-9999" in _extract_cves(record)

    def test_no_cve_when_none_present(self):
        record = {"template-id": "tech-detect", "info": {}}
        assert _extract_cves(record) == []


class TestNucleiCWEExtraction:
    def test_cwe_extracted_from_classification(self):
        record = {
            "template-id": "x",
            "info": {"classification": {"cwe-id": ["CWE-79"]}},
        }
        assert "CWE-79" in _extract_cwes(record)

    def test_no_cwe_when_not_present(self):
        record = {"template-id": "x", "info": {}}
        assert _extract_cwes(record) == []


class TestNucleiSeverityMapping:
    def test_critical_mapped_correctly(self):
        assert _SEVERITY_MAP["critical"] == Severity.CRITICAL

    def test_high_mapped_correctly(self):
        assert _SEVERITY_MAP["high"] == Severity.HIGH

    def test_info_mapped_correctly(self):
        assert _SEVERITY_MAP["info"] == Severity.INFO


class TestNucleiOrchestratorNormalisation:
    def test_normalise_finding_from_json(self):
        orch = NucleiOrchestrator("https://target.example.com")
        record = json.loads(_NUCLEI_JSON_FINDING)
        result = orch._normalise([record])
        assert result.finding_count == 1

    def test_normalise_finding_severity(self):
        orch = NucleiOrchestrator("https://target.example.com")
        record = json.loads(_NUCLEI_JSON_FINDING)
        result = orch._normalise([record])
        assert result.findings[0].severity == Severity.CRITICAL

    def test_normalise_finding_has_cve(self):
        orch = NucleiOrchestrator("https://target.example.com")
        record = json.loads(_NUCLEI_JSON_FINDING)
        result = orch._normalise([record])
        assert "CVE-2021-44228" in result.findings[0].cve_ids

    def test_normalise_finding_has_cwe(self):
        orch = NucleiOrchestrator("https://target.example.com")
        record = json.loads(_NUCLEI_JSON_FINDING)
        result = orch._normalise([record])
        assert "CWE-502" in result.findings[0].cwe_ids

    def test_normalise_finding_has_remediation(self):
        orch = NucleiOrchestrator("https://target.example.com")
        record = json.loads(_NUCLEI_JSON_FINDING)
        result = orch._normalise([record])
        assert result.findings[0].remediation is not None

    def test_normalise_finding_has_references(self):
        orch = NucleiOrchestrator("https://target.example.com")
        record = json.loads(_NUCLEI_JSON_FINDING)
        result = orch._normalise([record])
        assert len(result.findings[0].references) > 0

    def test_normalise_finding_has_tags(self):
        orch = NucleiOrchestrator("https://target.example.com")
        record = json.loads(_NUCLEI_JSON_FINDING)
        result = orch._normalise([record])
        assert "rce" in result.findings[0].tags

    def test_normalise_empty_raw_returns_empty_result(self):
        orch = NucleiOrchestrator("https://target.example.com")
        result = orch._normalise([])
        assert result.finding_count == 0

    def test_normalise_cvss_score_populated(self):
        orch = NucleiOrchestrator("https://target.example.com")
        record = json.loads(_NUCLEI_JSON_FINDING)
        result = orch._normalise([record])
        assert result.findings[0].cvss_score == 10.0

    @pytest.mark.asyncio
    async def test_run_with_mock_subprocess(self):
        ndjson = _NUCLEI_JSON_FINDING + "\n" + _NUCLEI_JSON_INFO_FINDING
        with patch("shutil.which", return_value="/usr/bin/nuclei"), \
             patch(
                "asyncio.create_subprocess_exec",
                return_value=_mock_nuclei_proc(ndjson),
            ):
            orch = NucleiOrchestrator("https://target.example.com")
            result = await orch.run()

        assert result.success is True
        assert result.finding_count == 2

    @pytest.mark.asyncio
    async def test_critical_count_correct(self):
        with patch("shutil.which", return_value="/usr/bin/nuclei"), \
             patch(
                "asyncio.create_subprocess_exec",
                return_value=_mock_nuclei_proc(_NUCLEI_JSON_FINDING),
            ):
            orch = NucleiOrchestrator("https://target.example.com")
            result = await orch.run()

        assert result.critical_count == 1

    @pytest.mark.asyncio
    async def test_scan_targets_concurrent(self):
        targets = [
            "https://target1.example.com",
            "https://target2.example.com",
        ]
        with patch("shutil.which", return_value="/usr/bin/nuclei"), \
             patch(
                "asyncio.create_subprocess_exec",
                return_value=_mock_nuclei_proc(_NUCLEI_JSON_FINDING),
            ):
            results = await NucleiOrchestrator.scan_targets(targets)
        assert len(results) == 2
        for r in results:
            assert isinstance(r, ReconResult)


# ===========================================================================
# ===========================================================================

class TestNucleiScanAPIContracts:
    def test_router_prefix(self):
        from app.api.scans_nuclei import router
        assert router.prefix == "/api/scans/nuclei"

    def test_router_has_post_start_route(self):
        from app.api.scans_nuclei import router
        all_methods: set = set()
        for r in router.routes:
            all_methods.update(r.methods or set())
        assert "POST" in all_methods

    def test_router_has_get_routes(self):
        from app.api.scans_nuclei import router
        all_methods: set = set()
        for r in router.routes:
            all_methods.update(r.methods or set())
        assert "GET" in all_methods

    def test_request_schema_defaults(self):
        from app.api.scans_nuclei import NucleiScanCreateRequest
        req = NucleiScanCreateRequest(targets=["https://example.com"])
        assert "critical" in req.severity_filter
        assert req.rate_limit == 100
        assert req.interactsh_enabled is False


# ===========================================================================
# ===========================================================================

class TestOOBInteraction:
    def test_to_dict_contains_all_fields(self):
        from datetime import datetime, timezone
        ix = OOBInteraction(
            correlation_id="abc123",
            interaction_type="dns",
            remote_address="1.2.3.4",
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
        )
        d = ix.to_dict()
        assert d["correlation_id"] == "abc123"
        assert d["interaction_type"] == "dns"
        assert d["remote_address"] == "1.2.3.4"
        assert "timestamp" in d


class TestInteractshClient:
    def test_payload_url_contains_correlation_id(self):
        client = InteractshClient(server_url="https://interact.sh", correlation_id="test123")
        assert "test123" in client.payload_url

    def test_payload_url_contains_server_host(self):
        client = InteractshClient(server_url="https://interact.sh", correlation_id="abc")
        assert "interact.sh" in client.payload_url

    def test_correlation_id_auto_generated(self):
        c1 = InteractshClient()
        c2 = InteractshClient()
        assert c1.correlation_id != c2.correlation_id

    def test_correlation_id_length(self):
        client = InteractshClient()
        assert len(client.correlation_id) > 10

    def test_dns_payload_format(self):
        client = InteractshClient(server_url="https://interact.sh", correlation_id="test123")
        payload = client.dns_payload("prefix")
        assert payload.startswith("prefix.")
        assert "test123" in payload

    def test_http_payload_format(self):
        client = InteractshClient(server_url="https://interact.sh", correlation_id="test123")
        payload = client.http_payload("/probe")
        assert payload.startswith("http://")
        assert "/probe" in payload

    def test_log4shell_payload_contains_jndi(self):
        client = InteractshClient(correlation_id="test123")
        payload = client.log4shell_payload()
        assert "${jndi:ldap://" in payload

    def test_ssrf_payload_is_http(self):
        client = InteractshClient(correlation_id="test123")
        payload = client.ssrf_payload()
        assert payload.startswith("http://")

    def test_decode_dict_interaction(self):
        data = {"protocol": "dns", "raw-request": "query"}
        result = InteractshClient._decode_interaction(data)
        assert result["protocol"] == "dns"

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """InteractshClient should work as an async context manager."""
        async with InteractshClient() as client:
            assert client.correlation_id is not None


# ===========================================================================
# ===========================================================================

class TestVulnScanDocumentation:
    def test_readme_exists(self):
        readme = (
            Path(__file__).parent.parent
            / "app"
            / "recon"
            / "vuln_scanning"
            / "README.md"
        )
        assert readme.exists(), "vuln_scanning/README.md should exist"

    def test_nuclei_orchestrator_exported_from_package(self):
        assert ExportedOrchestrator is NucleiOrchestrator
        assert ExportedConfig is NucleiOrchestratorConfig

    def test_template_updater_exported_from_package(self):
        assert ExportedUpdater is NucleiTemplateUpdater

    def test_interactsh_client_exported_from_package(self):
        assert ExportedInteractsh is InteractshClient
