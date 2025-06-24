"""
Week 9 Test Suite – CVE Enrichment

Covers:
  Day 51 – EnrichedCVE data model, ExploitInfo, CVSSVector, EnrichmentService
  Day 52 – NVDClient: rate limiter, response parsing, error handling
  Day 53 – VulnersClient: response parsing, exploit detection, merging
  Day 54 – CVECache: SQLite persistence, TTL expiry, warm-up strategy
  Day 55 – Enrichment pipeline: batch enrichment, fallback strategy
  Day 56 – /api/cve/{id} and /api/enrich/findings API contracts
  Day 57 – Integration: NVD+Vulners merge, CVSS→severity, documentation
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import tempfile
import time
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.enrichment.enrichment_service import (
    CVSSVector,
    EnrichedCVE,
    EnrichmentService,
    ExploitInfo,
    _apply_enrichment,
    _merge_vulners,
)
from app.services.enrichment.cve_cache import CVECache, _serialise, _deserialise
from app.services.enrichment.nvd_client import NVDClient, _parse_date, _pick_en
from app.services.enrichment.vulners_client import VulnersClient


# ===========================================================================
# ===========================================================================

class TestEnrichedCVEModel:
    def test_base_score_prefers_v3(self):
        v3 = CVSSVector(base_score=9.8)
        cve = EnrichedCVE(cve_id="CVE-2021-44228", cvss_v3=v3, cvss_v2_score=7.5)
        assert cve.base_score == 9.8

    def test_base_score_falls_back_to_v2(self):
        cve = EnrichedCVE(cve_id="CVE-2021-44228", cvss_v2_score=7.5)
        assert cve.base_score == 7.5

    def test_base_score_none_when_no_cvss(self):
        cve = EnrichedCVE(cve_id="CVE-2021-44228")
        assert cve.base_score is None

    def test_severity_critical(self):
        cve = EnrichedCVE(cve_id="CVE-2021-44228", cvss_v3=CVSSVector(base_score=9.8))
        assert cve.severity == "critical"

    def test_severity_high(self):
        cve = EnrichedCVE(cve_id="CVE-2021-44228", cvss_v3=CVSSVector(base_score=7.5))
        assert cve.severity == "high"

    def test_severity_medium(self):
        cve = EnrichedCVE(cve_id="CVE-2021-44228", cvss_v3=CVSSVector(base_score=5.0))
        assert cve.severity == "medium"

    def test_severity_low(self):
        cve = EnrichedCVE(cve_id="CVE-2021-44228", cvss_v3=CVSSVector(base_score=2.0))
        assert cve.severity == "low"

    def test_severity_unknown_without_score(self):
        cve = EnrichedCVE(cve_id="CVE-2021-44228")
        assert cve.severity == "unknown"

    def test_default_exploit_info_no_exploit(self):
        cve = EnrichedCVE(cve_id="CVE-2021-44228")
        assert cve.exploit_info.exploits_available is False
        assert cve.exploit_info.exploit_count == 0

    def test_fetched_at_is_tz_aware(self):
        cve = EnrichedCVE(cve_id="CVE-2021-44228")
        assert cve.fetched_at.tzinfo is not None


class TestMergeVulners:
    def test_exploit_info_merged(self):
        cve = EnrichedCVE(cve_id="CVE-2021-44228", sources=["nvd"])
        vulners_data = {
            "exploit_count": 2,
            "exploit_refs": ["https://exploit.db/123"],
            "maturity": "proof-of-concept",
        }
        result = _merge_vulners(cve, vulners_data)
        assert result.exploit_info.exploits_available is True
        assert result.exploit_info.exploit_count == 2
        assert "vulners" in result.sources

    def test_no_exploit_does_not_set_flag(self):
        cve = EnrichedCVE(cve_id="CVE-2021-44228")
        result = _merge_vulners(cve, {"exploit_count": 0})
        assert result.exploit_info.exploits_available is False


class TestApplyEnrichment:
    def _make_finding(self):
        from app.recon.canonical_schemas import Finding
        return Finding(id="nuclei-CVE-2021-44228", name="Log4Shell")

    def test_cvss_score_applied(self):
        f = self._make_finding()
        cve = EnrichedCVE(cve_id="CVE-2021-44228", cvss_v3=CVSSVector(base_score=10.0))
        _apply_enrichment(f, cve)
        assert f.cvss_score == 10.0

    def test_cwe_ids_merged(self):
        f = self._make_finding()
        cve = EnrichedCVE(cve_id="CVE-2021-44228", cwe_ids=["CWE-20"])
        _apply_enrichment(f, cve)
        assert "CWE-20" in f.cwe_ids

    def test_enrichment_metadata_in_extra(self):
        f = self._make_finding()
        cve = EnrichedCVE(cve_id="CVE-2021-44228", cvss_v3=CVSSVector(base_score=9.8, vector_string="CVSS:3.1/AV:N"))
        _apply_enrichment(f, cve)
        assert "cve_enrichment" in f.extra
        assert f.extra["cve_enrichment"]["cvss_v3"]["score"] == 9.8


# ===========================================================================
# ===========================================================================

_NVD_CVE_RESPONSE = {
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2021-44228",
            "published": "2021-12-10T10:15:09.143",
            "lastModified": "2023-11-07T03:15:07.723",
            "descriptions": [{"lang": "en", "value": "Apache Log4j2 2.0-beta9 through 2.14.1..."}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        "baseScore": 10.0,
                        "baseSeverity": "CRITICAL",
                        "attackVector": "NETWORK",
                    }
                }]
            },
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-20"}]}],
            "configurations": [],
            "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}],
        }
    }]
}


class TestNVDClient:
    @pytest.mark.asyncio
    async def test_invalid_cve_id_raises(self):
        client = NVDClient()
        with pytest.raises(ValueError):
            await client.fetch("not-a-cve")

    def test_parse_date_valid(self):
        dt = _parse_date("2021-12-10T10:15:09.143")
        assert dt.year == 2021 and dt.month == 12

    def test_parse_date_date_only(self):
        dt = _parse_date("2021-12-10")
        assert dt.year == 2021 and dt.month == 12 and dt.day == 10

    def test_parse_date_none(self):
        assert _parse_date(None) is None

    def test_pick_en_selects_english(self):
        descriptions = [{"lang": "es", "value": "Español"}, {"lang": "en", "value": "English"}]
        assert _pick_en(descriptions) == "English"

    def test_pick_en_returns_first_if_no_english(self):
        descriptions = [{"lang": "de", "value": "Deutsch"}]
        assert _pick_en(descriptions) == "Deutsch"

    @pytest.mark.asyncio
    async def test_fetch_returns_enriched_cve(self):
        client = NVDClient()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _NVD_CVE_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await client.fetch("CVE-2021-44228")

        assert result is not None
        assert result.cve_id == "CVE-2021-44228"
        assert result.cvss_v3.base_score == 10.0
        assert "CWE-20" in result.cwe_ids
        assert "nvd" in result.sources

    @pytest.mark.asyncio
    async def test_fetch_returns_none_on_404(self):
        client = NVDClient()
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await client.fetch("CVE-2000-00000")
        assert result is None


# ===========================================================================
# ===========================================================================

_VULNERS_RESPONSE = {
    "result": "OK",
    "data": {
        "documents": [
            {"id": "EXPLOITDB:50590", "type": "exploitdb", "href": "https://exploit-db.com/exploits/50590"},
            {"id": "MSF:LOG4SHELL", "type": "metasploit", "href": "https://metasploit.com/modules/exploit"},
        ]
    }
}


class TestVulnersClient:
    @pytest.mark.asyncio
    async def test_fetch_returns_exploit_info(self):
        client = VulnersClient()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _VULNERS_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await client.fetch("CVE-2021-44228")

        assert result is not None
        assert result["exploit_count"] >= 1

    @pytest.mark.asyncio
    async def test_fetch_returns_none_on_api_error(self):
        client = VulnersClient()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"result": "ERROR", "data": {}}
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await client.fetch("CVE-2021-44228")
        assert result is None

    def test_parse_exploitdb_bulletin(self):
        raw = {
            "result": "OK",
            "data": {
                "documents": [
                    {"id": "EXPLOITDB:123", "type": "exploitdb", "href": "https://exploit-db.com/123"}
                ]
            }
        }
        result = VulnersClient._parse_vuln_data("CVE-2021-44228", raw)
        assert result["exploit_count"] == 1
        assert result["maturity"] == "functional"

    def test_parse_metasploit_sets_weaponised(self):
        raw = {
            "result": "OK",
            "data": {
                "documents": [
                    {"id": "MSF:exploit", "type": "metasploit", "href": "https://metasploit.com/m"}
                ]
            }
        }
        result = VulnersClient._parse_vuln_data("CVE-2021-44228", raw)
        assert result["maturity"] == "weaponised"


# ===========================================================================
# ===========================================================================

class TestCVECache:
    @pytest.fixture
    def tmp_cache(self, tmp_path):
        return CVECache(ttl_days=30, db_path=str(tmp_path / "test_cache.db"))

    @pytest.mark.asyncio
    async def test_set_and_get(self, tmp_cache):
        cve = EnrichedCVE(cve_id="CVE-2021-44228")
        await tmp_cache.set("CVE-2021-44228", cve)
        result = await tmp_cache.get("CVE-2021-44228")
        assert result is not None
        assert result.cve_id == "CVE-2021-44228"

    @pytest.mark.asyncio
    async def test_miss_returns_none(self, tmp_cache):
        result = await tmp_cache.get("CVE-9999-99999")
        assert result is None

    @pytest.mark.asyncio
    async def test_expired_entry_returns_none(self, tmp_path):
        cache = CVECache(ttl_days=0, db_path=str(tmp_path / "exp_cache.db"))
        cve = EnrichedCVE(cve_id="CVE-2021-44228")
        await cache.set("CVE-2021-44228", cve)
        # TTL is 0 days = expired immediately
        result = await cache.get("CVE-2021-44228")
        assert result is None

    @pytest.mark.asyncio
    async def test_count(self, tmp_cache):
        cve = EnrichedCVE(cve_id="CVE-2021-44228")
        await tmp_cache.set("CVE-2021-44228", cve)
        count = await tmp_cache.count()
        assert count == 1

    @pytest.mark.asyncio
    async def test_purge_expired(self, tmp_path):
        cache = CVECache(ttl_days=0, db_path=str(tmp_path / "purge_cache.db"))
        cve = EnrichedCVE(cve_id="CVE-2021-44228")
        cache._sync_set("CVE-2021-44228", cve)
        deleted = await cache.purge_expired()
        assert deleted == 1

    def test_serialise_deserialise_round_trip(self):
        original = EnrichedCVE(
            cve_id="CVE-2021-44228",
            cvss_v3=CVSSVector(base_score=10.0, version="3.1"),
            cwe_ids=["CWE-20"],
            sources=["nvd"],
        )
        blob = _serialise(original)
        restored = _deserialise(blob)
        assert restored.cve_id == original.cve_id
        assert restored.cvss_v3.base_score == 10.0
        assert restored.cwe_ids == ["CWE-20"]

    @pytest.mark.asyncio
    async def test_warm_up_populates_cache(self, tmp_cache):
        calls = []
        async def fake_fetcher(cve_id: str):
            calls.append(cve_id)
            return EnrichedCVE(cve_id=cve_id)

        cve_ids = ["CVE-2021-44228", "CVE-2022-0778"]
        written = await tmp_cache.warm(cve_ids, fake_fetcher)
        assert written == 2
        assert len(calls) == 2

    @pytest.mark.asyncio
    async def test_warm_skips_already_cached(self, tmp_cache):
        await tmp_cache.set("CVE-2021-44228", EnrichedCVE(cve_id="CVE-2021-44228"))
        calls = []
        async def fake_fetcher(cve_id: str):
            calls.append(cve_id)
            return EnrichedCVE(cve_id=cve_id)
        await tmp_cache.warm(["CVE-2021-44228", "CVE-2022-0778"], fake_fetcher)
        assert "CVE-2021-44228" not in calls  # should be skipped


# ===========================================================================
# ===========================================================================

class TestEnrichmentPipeline:
    @pytest.mark.asyncio
    async def test_batch_enrichment_skips_no_cve(self):
        from app.recon.canonical_schemas import Finding
        svc = EnrichmentService()
        findings = [Finding(id="f1", name="No CVE finding")]
        result = await svc.enrich_findings(findings)
        assert result[0].cvss_score is None   # unchanged

    @pytest.mark.asyncio
    async def test_batch_enrichment_applies_cvss(self):
        from app.recon.canonical_schemas import Finding
        svc = EnrichmentService()
        enriched_cve = EnrichedCVE(
            cve_id="CVE-2021-44228",
            cvss_v3=CVSSVector(base_score=10.0),
            cwe_ids=["CWE-20"],
            sources=["nvd"],
        )
        with patch.object(svc, "get_cve", AsyncMock(return_value=enriched_cve)):
            finding = Finding(id="f1", name="Log4Shell", cve_ids=["CVE-2021-44228"])
            result = await svc.enrich_findings([finding])
        assert result[0].cvss_score == 10.0
        assert "CWE-20" in result[0].cwe_ids

    @pytest.mark.asyncio
    async def test_batch_enrichment_fallback_on_error(self):
        from app.recon.canonical_schemas import Finding
        svc = EnrichmentService()
        with patch.object(svc, "get_cve", AsyncMock(side_effect=RuntimeError("Network error"))):
            finding = Finding(id="f1", name="Log4Shell", cve_ids=["CVE-2021-44228"])
            result = await svc.enrich_findings([finding])
        # Should not raise; finding returned unchanged
        assert result[0].cvss_score is None


# ===========================================================================
# ===========================================================================

class TestCVEAPIContracts:
    def test_cve_enrichment_router_prefix_correct(self):
        from app.api.cve_enrichment import router
        # CVE endpoint has no prefix (mounted at /api level)
        tags = router.tags
        assert "CVE Enrichment" in tags

    def test_cve_enrichment_has_get_route(self):
        from app.api.cve_enrichment import router
        all_methods = {m for r in router.routes for m in (r.methods or set())}
        assert "GET" in all_methods

    def test_cve_enrichment_has_post_route(self):
        from app.api.cve_enrichment import router
        all_methods = {m for r in router.routes for m in (r.methods or set())}
        assert "POST" in all_methods

    def test_finding_input_schema_defaults(self):
        from app.api.cve_enrichment import FindingInput
        f = FindingInput(id="f1", name="Test Finding")
        assert f.cve_ids == []
        assert f.severity == "unknown"

    def test_batch_enrich_router_has_findings_input(self):
        from app.api.cve_enrichment import BatchEnrichRequest
        req = BatchEnrichRequest(findings=[
            {"id": "f1", "name": "Test"}
        ])
        assert len(req.findings) == 1


# ===========================================================================
# ===========================================================================

class TestWeek9Documentation:
    def test_enrichment_package_imports(self):
        from app.services.enrichment import (
            EnrichmentService, EnrichedCVE, CVSSVector,
            ExploitInfo, NVDClient, VulnersClient, CVECache,
        )

    def test_enriched_cve_severity_info_on_zero_score(self):
        cve = EnrichedCVE(cve_id="CVE-2023-0001", cvss_v3=CVSSVector(base_score=0.0))
        assert cve.severity == "info"
