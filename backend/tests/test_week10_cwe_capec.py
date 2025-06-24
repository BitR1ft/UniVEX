"""
Week 10 Test Suite – CWE & CAPEC Mapping

Covers:
  Day 58 – CWEService: built-in dataset, lookup, XML fallback
  Day 59 – CAPECService: built-in dataset, lookup, by_cwe query
  Day 60 – CWECAPECMapper: build, CWE→CAPEC, CAPEC→CWE, attack enrichment
  Day 61 – VulnCWEMapper: CWE extraction from text, keyword heuristics, categorisation
  Day 62 – RiskScorer: compute_risk_score, normalise_severity, prioritise_findings
  Day 63 – UpdateScheduler: job listing, manual trigger, audit logging
  Day 64 – /api/enrichment contract tests
  Day 65 – Package exports, documentation
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from app.services.cwe_capec.cwe_service import CWEService, CWEEntry, _parse_cwe_xml
from app.services.cwe_capec.capec_service import CAPECService, CAPECEntry
from app.services.cwe_capec.cwe_capec_mapper import CWECAPECMapper
from app.services.cwe_capec.vuln_cwe_mapper import (
    apply_cwe_to_finding,
    categorise_finding_by_cwe,
    extract_cwe_from_text,
)
from app.services.cwe_capec.risk_scorer import (
    compute_risk_score,
    normalise_severity,
    prioritise_findings,
    score_finding,
)
from app.services.cwe_capec.update_scheduler import UpdateScheduler, read_audit_log
from app.recon.canonical_schemas import Finding, Severity


# ===========================================================================
# ===========================================================================

class TestCWEService:
    @pytest.mark.asyncio
    async def test_builtin_data_loaded(self):
        svc = CWEService()
        await svc.load()
        assert svc.count() > 0
        assert svc.is_loaded()

    @pytest.mark.asyncio
    async def test_lookup_by_full_id(self):
        svc = CWEService()
        await svc.load()
        entry = svc.lookup("CWE-79")
        assert entry is not None
        assert entry.id == "CWE-79"

    @pytest.mark.asyncio
    async def test_lookup_by_number_only(self):
        svc = CWEService()
        await svc.load()
        entry = svc.lookup("79")
        assert entry is not None
        assert "Cross-site Scripting" in entry.name or "Neutralization" in entry.name

    @pytest.mark.asyncio
    async def test_lookup_case_insensitive(self):
        svc = CWEService()
        await svc.load()
        entry = svc.lookup("cwe-79")
        assert entry is not None

    @pytest.mark.asyncio
    async def test_lookup_unknown_returns_none(self):
        svc = CWEService()
        await svc.load()
        assert svc.lookup("CWE-99999") is None

    @pytest.mark.asyncio
    async def test_all_returns_list(self):
        svc = CWEService()
        await svc.load()
        entries = svc.all()
        assert isinstance(entries, list)
        assert len(entries) == svc.count()

    @pytest.mark.asyncio
    async def test_sql_injection_has_capec(self):
        svc = CWEService()
        await svc.load()
        entry = svc.lookup("CWE-89")
        assert entry is not None
        assert len(entry.capec_ids) > 0

    @pytest.mark.asyncio
    async def test_xml_fallback_used_on_missing_file(self):
        svc = CWEService(xml_path="/nonexistent/path.xml")
        await svc.load()
        assert svc.is_loaded()  # falls back to built-in


# ===========================================================================
# ===========================================================================

class TestCAPECService:
    @pytest.mark.asyncio
    async def test_builtin_data_loaded(self):
        svc = CAPECService()
        await svc.load()
        assert svc.count() > 0

    @pytest.mark.asyncio
    async def test_lookup_by_full_id(self):
        svc = CAPECService()
        await svc.load()
        entry = svc.lookup("CAPEC-66")
        assert entry is not None
        assert entry.id == "CAPEC-66"
        assert "SQL Injection" in entry.name

    @pytest.mark.asyncio
    async def test_lookup_by_number(self):
        svc = CAPECService()
        await svc.load()
        entry = svc.lookup("66")
        assert entry is not None

    @pytest.mark.asyncio
    async def test_lookup_case_insensitive(self):
        svc = CAPECService()
        await svc.load()
        entry = svc.lookup("capec-62")
        assert entry is not None

    @pytest.mark.asyncio
    async def test_lookup_unknown_returns_none(self):
        svc = CAPECService()
        await svc.load()
        assert svc.lookup("CAPEC-99999") is None

    @pytest.mark.asyncio
    async def test_by_cwe_returns_patterns(self):
        svc = CAPECService()
        await svc.load()
        patterns = svc.by_cwe("CWE-89")
        assert len(patterns) > 0
        names = [p.name for p in patterns]
        assert any("SQL" in n for n in names)

    @pytest.mark.asyncio
    async def test_by_cwe_accepts_numeric_id(self):
        svc = CAPECService()
        await svc.load()
        patterns = svc.by_cwe("89")
        assert len(patterns) > 0

    @pytest.mark.asyncio
    async def test_xml_fallback_on_missing_file(self):
        svc = CAPECService(xml_path="/nonexistent/capec.xml")
        await svc.load()
        assert svc.is_loaded()


# ===========================================================================
# ===========================================================================

class TestCWECAPECMapper:
    @pytest.fixture
    def mapper(self):
        """Synchronous fixture that builds the mapper using asyncio.run."""
        cwe_svc = CWEService()
        capec_svc = CAPECService()
        m = CWECAPECMapper(cwe_svc, capec_svc)
        asyncio.run(m.build())
        return m

    def test_build_populates_mappings(self, mapper):
        stats = mapper.stats()
        assert stats["built"] is True
        assert stats["cwe_with_capec_mappings"] > 0

    def test_attacks_for_cwe_89(self, mapper):
        patterns = mapper.attacks_for_cwe("CWE-89")
        assert len(patterns) > 0

    def test_attacks_for_unknown_cwe_empty(self, mapper):
        patterns = mapper.attacks_for_cwe("CWE-99999")
        assert patterns == []

    def test_weaknesses_for_capec_66(self, mapper):
        weaknesses = mapper.weaknesses_for_capec("CAPEC-66")
        assert len(weaknesses) > 0

    def test_attack_pattern_enrichment_on_finding(self, mapper):
        finding = Finding(id="f1", name="SQL Injection", cwe_ids=["CWE-89"])
        mapper.enrich_with_attack_patterns(finding)
        assert "attack_patterns" in finding.extra
        assert len(finding.extra["attack_patterns"]) > 0

    def test_enrichment_no_patterns_for_no_cwe(self, mapper):
        finding = Finding(id="f1", name="Test")
        mapper.enrich_with_attack_patterns(finding)
        # Should not crash; patterns should be empty
        assert finding.extra.get("attack_patterns", []) == []

    def test_stats_has_all_keys(self, mapper):
        stats = mapper.stats()
        for key in ("built", "cwe_with_capec_mappings", "capec_with_cwe_mappings",
                    "total_cwe_to_capec_edges", "total_capec_to_cwe_edges"):
            assert key in stats


# ===========================================================================
# ===========================================================================

class TestVulnCWEMapper:
    def test_extract_explicit_cwe_from_text(self):
        text = "This vulnerability is related to CWE-79 and CWE-89."
        cwes = extract_cwe_from_text(text)
        assert "CWE-79" in cwes
        assert "CWE-89" in cwes

    def test_extract_xss_keyword(self):
        cwes = extract_cwe_from_text("A reflected XSS vulnerability was found")
        assert "CWE-79" in cwes

    def test_extract_sqli_keyword(self):
        cwes = extract_cwe_from_text("SQL injection in the login form")
        assert "CWE-89" in cwes

    def test_extract_ssrf_keyword(self):
        cwes = extract_cwe_from_text("Server-side request forgery in webhook handler")
        assert "CWE-918" in cwes

    def test_extract_rce_maps_code_injection(self):
        cwes = extract_cwe_from_text("Remote code execution via template injection")
        assert "CWE-94" in cwes

    def test_empty_text_returns_empty(self):
        assert extract_cwe_from_text("") == []

    def test_apply_cwe_to_finding_from_text(self):
        f = Finding(id="f1", name="Cross-site Scripting via XSS in search bar")
        apply_cwe_to_finding(f)
        assert "CWE-79" in f.cwe_ids

    def test_apply_cwe_explicit_list(self):
        f = Finding(id="f1", name="Test")
        apply_cwe_to_finding(f, cwe_ids=["CWE-20", "CWE-79"])
        assert "CWE-20" in f.cwe_ids
        assert "CWE-79" in f.cwe_ids

    def test_apply_cwe_no_duplicates(self):
        f = Finding(id="f1", name="Test", cwe_ids=["CWE-79"])
        apply_cwe_to_finding(f, cwe_ids=["CWE-79"])
        assert f.cwe_ids.count("CWE-79") == 1

    def test_categorise_by_cwe_89(self):
        assert categorise_finding_by_cwe(["CWE-89"]) == "Injection"

    def test_categorise_by_cwe_79(self):
        assert categorise_finding_by_cwe(["CWE-79"]) == "XSS"

    def test_categorise_unknown_cwe(self):
        assert categorise_finding_by_cwe(["CWE-99999"]) is None


# ===========================================================================
# ===========================================================================

class TestRiskScorer:
    def test_critical_score_high_result(self):
        score = compute_risk_score(9.8, "critical")
        assert score >= 9.0

    def test_no_cvss_uses_severity_fallback(self):
        score = compute_risk_score(None, "high")
        assert score > 0.0

    def test_exploit_multiplier_increases_score(self):
        base = compute_risk_score(7.0, "high")
        with_exploit = compute_risk_score(7.0, "high", exploit_maturity="weaponised")
        assert with_exploit > base

    def test_internet_exposure_increases_score(self):
        internal = compute_risk_score(7.0, "high", exposure="internal")
        external = compute_risk_score(7.0, "high", exposure="internet")
        assert external > internal

    def test_score_capped_at_10(self):
        score = compute_risk_score(10.0, "critical", exploit_maturity="weaponised", exposure="cloud")
        assert score <= 10.0

    def test_severity_normalisation_critical(self):
        assert normalise_severity("critical") == Severity.CRITICAL
        assert normalise_severity("CRITICAL") == Severity.CRITICAL

    def test_severity_normalisation_high(self):
        assert normalise_severity("high") == Severity.HIGH

    def test_severity_normalisation_alias(self):
        assert normalise_severity("moderate") == Severity.MEDIUM
        assert normalise_severity("informational") == Severity.INFO

    def test_severity_normalisation_unknown(self):
        assert normalise_severity("whatisthis") == Severity.UNKNOWN

    def test_prioritise_sorts_by_score_descending(self):
        findings = [
            Finding(id="f1", name="Low", severity=Severity.LOW),
            Finding(id="f2", name="Critical", severity=Severity.CRITICAL),
            Finding(id="f3", name="High", severity=Severity.HIGH),
        ]
        prioritised = prioritise_findings(findings)
        assert prioritised[0].extra["priority_rank"] == 1
        assert prioritised[0].name == "Critical"
        assert prioritised[-1].name == "Low"

    def test_prioritise_annotates_risk_score(self):
        findings = [Finding(id="f1", name="Test", severity=Severity.HIGH)]
        prioritised = prioritise_findings(findings)
        assert "risk_score" in prioritised[0].extra
        assert "priority_rank" in prioritised[0].extra

    def test_score_finding_reads_severity(self):
        f = Finding(id="f1", name="Test", severity=Severity.HIGH, cvss_score=7.5)
        score = score_finding(f)
        assert score > 0.0


# ===========================================================================
# ===========================================================================

class TestUpdateScheduler:
    def test_list_jobs_returns_all_jobs(self):
        sched = UpdateScheduler()
        jobs = sched.list_jobs()
        names = [j["name"] for j in jobs]
        assert "cve_cache_purge" in names
        assert "cwe_reload" in names
        assert "capec_reload" in names
        assert "nuclei_templates" in names

    @pytest.mark.asyncio
    async def test_run_now_unknown_job(self):
        sched = UpdateScheduler()
        result = await sched.run_now("nonexistent_job")
        assert result is False

    @pytest.mark.asyncio
    async def test_run_now_cve_cache_purge_without_cache(self):
        sched = UpdateScheduler()
        result = await sched.run_now("cve_cache_purge")
        assert result is True   # no-op without cache, but should succeed

    @pytest.mark.asyncio
    async def test_run_now_cwe_reload(self):
        cwe_svc = CWEService()
        sched = UpdateScheduler(cwe_service=cwe_svc)
        result = await sched.run_now("cwe_reload")
        assert result is True
        assert cwe_svc.is_loaded()

    @pytest.mark.asyncio
    async def test_run_now_capec_reload(self):
        capec_svc = CAPECService()
        sched = UpdateScheduler(capec_service=capec_svc)
        result = await sched.run_now("capec_reload")
        assert result is True
        assert capec_svc.is_loaded()

    @pytest.mark.asyncio
    async def test_audit_log_written_on_success(self, tmp_path):
        audit_path = str(tmp_path / "audit.jsonl")
        with patch("app.services.cwe_capec.update_scheduler._AUDIT_LOG_PATH", audit_path):
            sched = UpdateScheduler()
            await sched.run_now("cve_cache_purge")
        assert os.path.exists(audit_path)
        entries = [json.loads(l) for l in open(audit_path).readlines() if l.strip()]
        assert len(entries) >= 1
        assert entries[0]["job"] == "cve_cache_purge"
        assert entries[0]["status"] == "success"

    def test_read_audit_log_empty_on_missing_file(self, tmp_path):
        with patch("app.services.cwe_capec.update_scheduler._AUDIT_LOG_PATH", str(tmp_path / "no.jsonl")):
            entries = read_audit_log()
        assert entries == []


# ===========================================================================
# ===========================================================================

class TestEnrichmentAPIContracts:
    def test_router_prefix(self):
        from app.api.enrichment_api import router
        assert router.prefix == "/api/enrichment"

    def test_router_has_get_routes(self):
        from app.api.enrichment_api import router
        all_methods = {m for r in router.routes for m in (r.methods or set())}
        assert "GET" in all_methods

    def test_router_has_post_routes(self):
        from app.api.enrichment_api import router
        all_methods = {m for r in router.routes for m in (r.methods or set())}
        assert "POST" in all_methods

    def test_search_endpoint_exists(self):
        from app.api.enrichment_api import router
        paths = [r.path for r in router.routes]
        assert any("search" in p for p in paths)

    def test_audit_log_endpoint_exists(self):
        from app.api.enrichment_api import router
        paths = [r.path for r in router.routes]
        assert any("audit" in p for p in paths)

    def test_cwe_endpoint_exists(self):
        from app.api.enrichment_api import router
        paths = [r.path for r in router.routes]
        assert any("cwe" in p for p in paths)

    def test_capec_endpoint_exists(self):
        from app.api.enrichment_api import router
        paths = [r.path for r in router.routes]
        assert any("capec" in p for p in paths)

    def test_score_endpoint_exists(self):
        from app.api.enrichment_api import router
        paths = [r.path for r in router.routes]
        assert any("score" in p for p in paths)

    def test_prioritise_endpoint_exists(self):
        from app.api.enrichment_api import router
        paths = [r.path for r in router.routes]
        assert any("prioritise" in p for p in paths)

    def test_finding_score_request_defaults(self):
        from app.api.enrichment_api import FindingScoreRequest
        req = FindingScoreRequest(id="f1", name="Test")
        assert req.severity == "unknown"
        assert req.cve_ids == []
        assert req.cwe_ids == []


# ===========================================================================
# ===========================================================================

class TestWeek10PackageExports:
    def test_cwe_capec_package_exports(self):
        from app.services.cwe_capec import (
            CWEService, CWEEntry, CAPECService, CAPECEntry,
            CWECAPECMapper, compute_risk_score, normalise_severity,
            prioritise_findings, score_finding, UpdateScheduler, read_audit_log,
        )

    def test_cwe_service_directly_importable(self):
        from app.services.cwe_capec.cwe_service import CWEService, CWEEntry
        assert CWEService is not None

    def test_capec_service_directly_importable(self):
        from app.services.cwe_capec.capec_service import CAPECService, CAPECEntry
        assert CAPECService is not None

    def test_risk_scorer_exports(self):
        from app.services.cwe_capec.risk_scorer import (
            compute_risk_score, normalise_severity, prioritise_findings, score_finding
        )
