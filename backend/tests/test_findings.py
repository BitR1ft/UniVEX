"""

Coverage:
  TestFindingModel           (10 tests)
  TestFindingManager         (20 tests)
  TestDeduplicator           (15 tests)
  TestSeverityCalculator     (15 tests)
  TestFindingsAPI            (25 tests)

Total: 85 tests
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import List
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.findings.finding_manager import (
    Evidence,
    EvidenceType,
    Finding,
    FindingManager,
    FindingSeverity,
    FindingSource,
    FindingStatus,
    TriageAction,
)
from app.findings.deduplicator import Deduplicator, DeduplicationResult, DuplicateGroup
from app.findings.severity_calculator import (
    A,
    AC,
    AR,
    AV,
    C,
    CR,
    CVSSScore,
    CVSSVector,
    E,
    I,
    IR,
    PR,
    RC,
    RL,
    S,
    SeverityCalculator,
    SeverityRating,
    UI,
)


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------


def _finding(
    title: str = "SQL Injection",
    severity: FindingSeverity = FindingSeverity.HIGH,
    component: str = "/login",
    cwe: str = "CWE-89",
    cve: str | None = None,
    status: FindingStatus = FindingStatus.OPEN,
    campaign_id: str | None = None,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        description=f"Description of {title}",
        source=FindingSource.NUCLEI,
        affected_component=component,
        cwe_id=cwe,
        cve_id=cve,
        status=status,
        campaign_id=campaign_id,
        owasp_category="A03:2021",
    )


def _manager_with_findings(n: int = 5) -> tuple[FindingManager, list[Finding]]:
    mgr = FindingManager()
    findings = []
    severities = list(FindingSeverity)
    for i in range(n):
        f = mgr.create(
            title=f"Finding {i}",
            severity=severities[i % len(severities)],
            affected_component=f"/endpoint/{i}",
            campaign_id="camp-1",
        )
        findings.append(f)
    return mgr, findings


# ---------------------------------------------------------------------------
# TestFindingModel
# ---------------------------------------------------------------------------


class TestFindingModel:
    def test_auto_fingerprint(self):
        f = _finding()
        assert len(f.fingerprint) == 16

    def test_fingerprint_stable(self):
        f1 = _finding()
        f2 = _finding()
        assert f1.fingerprint == f2.fingerprint

    def test_fingerprint_differs_on_title(self):
        f1 = _finding(title="XSS")
        f2 = _finding(title="SQLi")
        assert f1.fingerprint != f2.fingerprint

    def test_effective_severity_no_override(self):
        f = _finding(severity=FindingSeverity.HIGH)
        assert f.effective_severity == FindingSeverity.HIGH

    def test_effective_severity_with_override(self):
        f = _finding(severity=FindingSeverity.HIGH)
        f.severity_override = FindingSeverity.CRITICAL
        assert f.effective_severity == FindingSeverity.CRITICAL

    def test_risk_score_range(self):
        f = _finding(severity=FindingSeverity.CRITICAL)
        assert 0.0 <= f.risk_score <= 10.0

    def test_risk_score_confirmed_bumped(self):
        f = _finding()
        f.status = FindingStatus.OPEN
        open_risk = f.risk_score
        f.status = FindingStatus.CONFIRMED
        assert f.risk_score >= open_risk

    def test_to_dict_keys(self):
        f = _finding()
        d = f.to_dict()
        for key in ["id", "title", "severity", "status", "fingerprint", "evidence", "triage_history"]:
            assert key in d

    def test_severity_numeric(self):
        assert FindingSeverity.CRITICAL.numeric > FindingSeverity.HIGH.numeric
        assert FindingSeverity.HIGH.numeric > FindingSeverity.MEDIUM.numeric

    def test_evidence_to_dict(self):
        ev = Evidence(type=EvidenceType.TOOL_OUTPUT, title="Nmap output", content="PORT 22 open")
        d = ev.to_dict()
        assert d["type"] == "tool_output"
        assert d["content"] == "Nmap output\nPORT 22 open" or d["content"] == "PORT 22 open"


# ---------------------------------------------------------------------------
# TestFindingManager
# ---------------------------------------------------------------------------


class TestFindingManager:
    def test_create_finding(self):
        mgr = FindingManager()
        f = mgr.create("Test", FindingSeverity.HIGH)
        assert f.id in mgr._findings
        assert f.title == "Test"

    def test_get_existing(self):
        mgr, findings = _manager_with_findings(1)
        result = mgr.get(findings[0].id)
        assert result is not None
        assert result.id == findings[0].id

    def test_get_missing_returns_none(self):
        mgr = FindingManager()
        assert mgr.get("nonexistent") is None

    def test_get_or_raise(self):
        mgr = FindingManager()
        with pytest.raises(KeyError):
            mgr.get_or_raise("nonexistent")

    def test_list_all(self):
        mgr, findings = _manager_with_findings(5)
        results = mgr.list(limit=100)
        assert len(results) == 5

    def test_list_filter_status(self):
        mgr, findings = _manager_with_findings(3)
        mgr.change_status(findings[0].id, FindingStatus.RESOLVED)
        resolved = mgr.list(status=FindingStatus.RESOLVED)
        assert len(resolved) == 1

    def test_list_filter_severity(self):
        mgr = FindingManager()
        mgr.create("Crit", FindingSeverity.CRITICAL)
        mgr.create("Low", FindingSeverity.LOW)
        crits = mgr.list(severity=FindingSeverity.CRITICAL)
        assert all(f.effective_severity == FindingSeverity.CRITICAL for f in crits)

    def test_list_filter_campaign(self):
        mgr = FindingManager()
        mgr.create("A", FindingSeverity.INFO, campaign_id="camp-1")
        mgr.create("B", FindingSeverity.INFO, campaign_id="camp-2")
        results = mgr.list(campaign_id="camp-1")
        assert len(results) == 1

    def test_list_search(self):
        mgr = FindingManager()
        mgr.create("SQL Injection", FindingSeverity.HIGH, description="sql in login")
        mgr.create("XSS reflected", FindingSeverity.MEDIUM)
        results = mgr.list(search="sql")
        assert len(results) == 1

    def test_update_finding(self):
        mgr, findings = _manager_with_findings(1)
        mgr.update(findings[0].id, title="Updated Title")
        assert mgr.get(findings[0].id).title == "Updated Title"

    def test_delete_finding(self):
        mgr, findings = _manager_with_findings(1)
        assert mgr.delete(findings[0].id) is True
        assert mgr.get(findings[0].id) is None

    def test_delete_nonexistent(self):
        mgr = FindingManager()
        assert mgr.delete("nonexistent") is False

    def test_change_status(self):
        mgr, findings = _manager_with_findings(1)
        f = mgr.change_status(findings[0].id, FindingStatus.CONFIRMED, actor="analyst")
        assert f.status == FindingStatus.CONFIRMED
        assert len(f.triage_history) == 1
        assert f.triage_history[0].action == "status_change"

    def test_resolved_sets_timestamp(self):
        mgr, findings = _manager_with_findings(1)
        f = mgr.change_status(findings[0].id, FindingStatus.RESOLVED)
        assert f.resolved_at is not None

    def test_override_severity(self):
        mgr, findings = _manager_with_findings(1)
        f = mgr.override_severity(findings[0].id, FindingSeverity.CRITICAL)
        assert f.effective_severity == FindingSeverity.CRITICAL
        assert f.triage_history[0].action == "severity_override"

    def test_assign(self):
        mgr, findings = _manager_with_findings(1)
        f = mgr.assign(findings[0].id, "alice")
        assert f.assigned_to == "alice"

    def test_annotate(self):
        mgr, findings = _manager_with_findings(1)
        f = mgr.annotate(findings[0].id, "Confirmed by manual test")
        assert "Confirmed" in f.triage_notes

    def test_mark_false_positive(self):
        mgr, findings = _manager_with_findings(1)
        f = mgr.mark_false_positive(findings[0].id, reason="Tool mis-fire")
        assert f.status == FindingStatus.FALSE_POSITIVE
        assert f.false_positive_reason == "Tool mis-fire"

    def test_mark_duplicate(self):
        mgr = FindingManager()
        f1 = mgr.create("SQLi", FindingSeverity.HIGH)
        f2 = mgr.create("SQLi", FindingSeverity.HIGH)
        mgr.mark_duplicate(f2.id, f1.id)
        assert mgr.get(f2.id).status == FindingStatus.DUPLICATE
        assert mgr.get(f2.id).duplicate_of == f1.id

    def test_attach_evidence(self):
        mgr, findings = _manager_with_findings(1)
        ev = mgr.attach_evidence(
            findings[0].id, EvidenceType.TOOL_OUTPUT, "Nuclei Output", "result here"
        )
        assert ev.id in [e.id for e in mgr.get(findings[0].id).evidence]

    def test_remove_evidence(self):
        mgr, findings = _manager_with_findings(1)
        ev = mgr.attach_evidence(findings[0].id, EvidenceType.DESCRIPTION, "T", "C")
        assert mgr.remove_evidence(findings[0].id, ev.id) is True

    def test_bulk_import(self):
        mgr = FindingManager()
        data = [
            {"title": "XSS", "severity": "high", "source": "nuclei"},
            {"title": "SQLi", "severity": "critical"},
        ]
        created = mgr.bulk_import(data)
        assert len(created) == 2

    def test_bulk_import_invalid_skipped(self):
        mgr = FindingManager()
        data = [{"title": "OK", "severity": "medium"}, {"title": "Bad", "severity": "unknown_sev"}]
        created = mgr.bulk_import(data)
        # Second one is skipped
        assert len(created) == 1

    def test_stats_returns_dict(self):
        mgr, _ = _manager_with_findings(5)
        stats = mgr.stats()
        assert "total" in stats
        assert "by_severity" in stats
        assert stats["total"] == 5


# ---------------------------------------------------------------------------
# TestDeduplicator
# ---------------------------------------------------------------------------


class TestDeduplicator:
    def test_empty_returns_empty(self):
        dedup = Deduplicator()
        result = dedup.run([])
        assert result.total_input == 0
        assert result.duplicate_count == 0

    def test_single_no_duplicates(self):
        dedup = Deduplicator()
        result = dedup.run([_finding()])
        assert result.unique_count == 1
        assert result.duplicate_count == 0

    def test_exact_fingerprint_match(self):
        f1 = _finding(title="SQL Injection", component="/login", cwe="CWE-89")
        f2 = _finding(title="SQL Injection", component="/login", cwe="CWE-89")
        # Force different IDs
        import uuid
        f2.id = str(uuid.uuid4())
        dedup = Deduplicator()
        result = dedup.run([f1, f2])
        assert result.duplicate_count >= 1

    def test_cve_match(self):
        f1 = _finding(title="Apache Log4Shell", cve="CVE-2021-44228")
        f2 = _finding(title="Log4j RCE", cve="CVE-2021-44228")
        import uuid
        f1.id = str(uuid.uuid4())
        f2.id = str(uuid.uuid4())
        f1.fingerprint = "aaa"
        f2.fingerprint = "bbb"
        dedup = Deduplicator()
        result = dedup.run([f1, f2])
        assert any(g.match_reason == "cve" for g in result.groups)

    def test_fuzzy_title_match(self):
        f1 = _finding(title="Reflected Cross Site Scripting", component="/search")
        f2 = _finding(title="Reflected Cross-Site Scripting in search", component="/search")
        import uuid
        f1.id = str(uuid.uuid4())
        f2.id = str(uuid.uuid4())
        f1.fingerprint = "xxx1"
        f2.fingerprint = "xxx2"
        dedup = Deduplicator(fuzzy_threshold=0.5)
        result = dedup.run([f1, f2])
        assert result.duplicate_count >= 1

    def test_no_fuzzy_when_disabled(self):
        f1 = _finding(title="XSS Reflected attack", component="/page")
        f2 = _finding(title="XSS Reflected vulnerability", component="/page")
        import uuid
        f1.id = str(uuid.uuid4())
        f2.id = str(uuid.uuid4())
        f1.fingerprint = "p1"
        f2.fingerprint = "p2"
        dedup = Deduplicator(fuzzy_threshold=0.5, enable_fuzzy=False)
        result = dedup.run([f1, f2])
        # With fuzzy disabled, CVE also won't match (no CVE set)
        assert len(result.groups) == 0

    def test_compute_similarity_identical(self):
        dedup = Deduplicator()
        assert dedup.compute_similarity("sql injection login", "sql injection login") == 1.0

    def test_compute_similarity_empty(self):
        dedup = Deduplicator()
        assert dedup.compute_similarity("", "") == 0.0

    def test_compute_similarity_partial(self):
        dedup = Deduplicator()
        sim = dedup.compute_similarity("sql injection", "sql xss")
        assert 0.0 < sim < 1.0

    def test_dedup_ratio(self):
        findings = [_finding() for _ in range(4)]
        import uuid
        for f in findings:
            f.id = str(uuid.uuid4())
        # Make 3 of 4 identical fingerprint
        for f in findings[1:]:
            f.fingerprint = findings[0].fingerprint
        dedup = Deduplicator()
        result = dedup.run(findings)
        assert result.dedup_ratio > 0.0

    def test_to_dict_format(self):
        dedup = Deduplicator()
        result = dedup.run([_finding()])
        d = result.to_dict()
        assert "total_input" in d
        assert "duplicate_count" in d
        assert "dedup_ratio" in d

    def test_group_all_ids(self):
        group = DuplicateGroup(
            canonical_id="a", duplicate_ids=["b", "c"], match_reason="fingerprint", similarity_score=1.0
        )
        assert set(group.all_ids) == {"a", "b", "c"}

    def test_group_to_dict(self):
        group = DuplicateGroup(
            canonical_id="a", duplicate_ids=["b"], match_reason="cve", similarity_score=0.95
        )
        d = group.to_dict()
        assert d["match_reason"] == "cve"
        assert d["total_count"] == 2

    def test_normalise_component_strips_scheme(self):
        dedup = Deduplicator()
        normed = dedup._normalise_component("https://example.com:8080/api/")
        assert "https" not in normed
        assert "8080" not in normed

    def test_tokenise(self):
        tokens = Deduplicator._tokenise("SQL Injection via POST")
        assert "sql" in tokens
        assert "injection" in tokens

    def test_large_finding_set(self):
        findings = [_finding(title=f"Finding {i}", component=f"/ep/{i}") for i in range(20)]
        import uuid
        for f in findings:
            f.id = str(uuid.uuid4())
            f.fingerprint = f.id[:8]
        dedup = Deduplicator()
        result = dedup.run(findings)
        assert result.total_input == 20


# ---------------------------------------------------------------------------
# TestSeverityCalculator
# ---------------------------------------------------------------------------


class TestSeverityCalculator:
    def setup_method(self):
        self.calc = SeverityCalculator()

    def _vector(self, **kwargs) -> CVSSVector:
        defaults = dict(
            attack_vector=AV.NETWORK,
            attack_complexity=AC.LOW,
            privileges_required=PR.NONE,
            user_interaction=UI.NONE,
            scope=S.UNCHANGED,
            confidentiality=C.NONE,
            integrity=I.NONE,
            availability=A.NONE,
        )
        defaults.update(kwargs)
        return CVSSVector(**defaults)

    def test_zero_impact_returns_zero(self):
        score = self.calc.calculate(self._vector())
        assert score.base_score == 0.0
        assert score.severity_rating == SeverityRating.NONE

    def test_critical_score(self):
        vector = self._vector(
            confidentiality=C.HIGH, integrity=I.HIGH, availability=A.HIGH
        )
        score = self.calc.calculate(vector)
        assert score.base_score >= 9.0
        assert score.severity_rating == SeverityRating.CRITICAL

    def test_high_score(self):
        vector = self._vector(
            confidentiality=C.HIGH, integrity=I.HIGH, availability=A.NONE,
            privileges_required=PR.LOW
        )
        score = self.calc.calculate(vector)
        assert score.base_score >= 7.0

    def test_medium_score(self):
        vector = self._vector(
            attack_vector=AV.NETWORK, attack_complexity=AC.HIGH,
            confidentiality=C.LOW, integrity=I.LOW, availability=A.NONE,
            user_interaction=UI.REQUIRED
        )
        score = self.calc.calculate(vector)
        assert 4.0 <= score.base_score < 9.0

    def test_quick_score(self):
        score = self.calc.quick_score(c="H", i="H", a="H")
        assert score.base_score >= 9.0

    def test_temporal_score_lower_than_base(self):
        vector = self._vector(
            confidentiality=C.HIGH,
            exploit_code_maturity=E.UNPROVEN,
            remediation_level=RL.OFFICIAL_FIX,
            report_confidence=RC.UNKNOWN,
        )
        score = self.calc.calculate(vector)
        # Temporal modifiers reduce score slightly
        assert score.temporal_score <= score.base_score

    def test_environmental_score_computed(self):
        vector = self._vector(
            confidentiality=C.HIGH,
            confidentiality_requirement=CR.HIGH,
        )
        score = self.calc.calculate(vector)
        assert score.environmental_score > 0

    def test_vector_string_roundtrip(self):
        vector = self._vector(confidentiality=C.HIGH, integrity=I.HIGH, availability=A.HIGH)
        score = self.calc.calculate(vector)
        vector2 = CVSSVector.from_string(score.vector_string)
        score2 = self.calc.calculate(vector2)
        assert score.base_score == score2.base_score

    def test_calculate_from_string(self):
        vector_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score = self.calc.calculate_from_string(vector_str)
        assert score.base_score == 9.8

    def test_scope_changed_higher_score(self):
        unchanged = self._vector(confidentiality=C.HIGH, scope=S.UNCHANGED)
        changed = self._vector(confidentiality=C.HIGH, scope=S.CHANGED)
        s1 = self.calc.calculate(unchanged)
        s2 = self.calc.calculate(changed)
        assert s2.base_score >= s1.base_score

    def test_physical_av_lower_score(self):
        net = self._vector(confidentiality=C.HIGH, attack_vector=AV.NETWORK)
        phys = self._vector(confidentiality=C.HIGH, attack_vector=AV.PHYSICAL)
        assert self.calc.calculate(net).base_score > self.calc.calculate(phys).base_score

    def test_to_dict_format(self):
        score = self.calc.quick_score(c="H", i="H", a="H")
        d = score.to_dict()
        assert "base_score" in d
        assert "severity_rating" in d
        assert "vector_string" in d

    def test_roundup_0_1_increments(self):
        score = self.calc.quick_score(c="L")
        # All scores should be multiples of 0.1
        assert round(score.base_score * 10) == int(score.base_score * 10)

    def test_vector_from_string_no_prefix(self):
        s = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        v = CVSSVector.from_string(s)
        assert v.attack_vector == AV.NETWORK

    def test_severity_rating_boundaries(self):
        assert SeverityCalculator._rating(0.0) == SeverityRating.NONE
        assert SeverityCalculator._rating(3.9) == SeverityRating.LOW
        assert SeverityCalculator._rating(6.9) == SeverityRating.MEDIUM
        assert SeverityCalculator._rating(8.9) == SeverityRating.HIGH
        assert SeverityCalculator._rating(9.0) == SeverityRating.CRITICAL


# ---------------------------------------------------------------------------
# TestFindingsAPI
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    from app.main import app
    # Reset manager state between tests
    from app.api import findings as findings_module
    findings_module._manager = FindingManager()
    return TestClient(app)


class TestFindingsAPI:
    def test_create_finding_success(self, client):
        resp = client.post("/api/findings", json={
            "title": "SQL Injection in login",
            "severity": "high",
            "description": "Classic SQLi",
            "affected_component": "/api/login",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["title"] == "SQL Injection in login"
        assert data["severity"] == "high"

    def test_create_finding_invalid_severity(self, client):
        resp = client.post("/api/findings", json={"title": "X", "severity": "catastrophic"})
        assert resp.status_code == 422

    def test_list_findings_empty(self, client):
        resp = client.get("/api/findings")
        assert resp.status_code == 200
        assert resp.json()["findings"] == []

    def test_list_findings_with_data(self, client):
        client.post("/api/findings", json={"title": "F1", "severity": "high"})
        client.post("/api/findings", json={"title": "F2", "severity": "low"})
        resp = client.get("/api/findings")
        assert resp.status_code == 200
        assert resp.json()["count"] == 2

    def test_list_filter_severity(self, client):
        client.post("/api/findings", json={"title": "C", "severity": "critical"})
        client.post("/api/findings", json={"title": "L", "severity": "low"})
        resp = client.get("/api/findings?severity=critical")
        assert resp.json()["count"] == 1

    def test_get_finding(self, client):
        r = client.post("/api/findings", json={"title": "Test", "severity": "medium"})
        fid = r.json()["id"]
        resp = client.get(f"/api/findings/{fid}")
        assert resp.status_code == 200
        assert resp.json()["id"] == fid

    def test_get_finding_not_found(self, client):
        resp = client.get("/api/findings/nonexistent")
        assert resp.status_code == 404

    def test_update_finding(self, client):
        r = client.post("/api/findings", json={"title": "Old", "severity": "low"})
        fid = r.json()["id"]
        resp = client.patch(f"/api/findings/{fid}", json={"title": "New"})
        assert resp.status_code == 200
        assert resp.json()["title"] == "New"

    def test_delete_finding(self, client):
        r = client.post("/api/findings", json={"title": "Delete me", "severity": "info"})
        fid = r.json()["id"]
        resp = client.delete(f"/api/findings/{fid}")
        assert resp.status_code == 204
        assert client.get(f"/api/findings/{fid}").status_code == 404

    def test_delete_finding_not_found(self, client):
        resp = client.delete("/api/findings/nonexistent")
        assert resp.status_code == 404

    def test_triage_status_change(self, client):
        r = client.post("/api/findings", json={"title": "F", "severity": "high"})
        fid = r.json()["id"]
        resp = client.patch(f"/api/findings/{fid}/triage", json={
            "action": "status_change", "value": "confirmed", "actor": "alice"
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "confirmed"

    def test_triage_severity_override(self, client):
        r = client.post("/api/findings", json={"title": "F", "severity": "low"})
        fid = r.json()["id"]
        resp = client.patch(f"/api/findings/{fid}/triage", json={
            "action": "severity_override", "value": "critical"
        })
        assert resp.json()["effective_severity"] == "critical"

    def test_triage_assign(self, client):
        r = client.post("/api/findings", json={"title": "F", "severity": "medium"})
        fid = r.json()["id"]
        resp = client.patch(f"/api/findings/{fid}/triage", json={"action": "assign", "value": "bob"})
        assert resp.json()["assigned_to"] == "bob"

    def test_triage_false_positive(self, client):
        r = client.post("/api/findings", json={"title": "F", "severity": "info"})
        fid = r.json()["id"]
        resp = client.patch(f"/api/findings/{fid}/triage", json={
            "action": "false_positive", "value": "scanner artifact"
        })
        assert resp.json()["status"] == "false_positive"

    def test_triage_invalid_action(self, client):
        r = client.post("/api/findings", json={"title": "F", "severity": "low"})
        fid = r.json()["id"]
        resp = client.patch(f"/api/findings/{fid}/triage", json={"action": "unknown", "value": "x"})
        assert resp.status_code == 422

    def test_attach_evidence(self, client):
        r = client.post("/api/findings", json={"title": "F", "severity": "high"})
        fid = r.json()["id"]
        resp = client.post(f"/api/findings/{fid}/evidence", json={
            "type": "tool_output", "title": "Nuclei scan", "content": "result here"
        })
        assert resp.status_code == 201
        assert resp.json()["type"] == "tool_output"

    def test_remove_evidence(self, client):
        r = client.post("/api/findings", json={"title": "F", "severity": "high"})
        fid = r.json()["id"]
        ev = client.post(f"/api/findings/{fid}/evidence", json={
            "type": "description", "title": "Note", "content": "text"
        }).json()
        resp = client.delete(f"/api/findings/{fid}/evidence/{ev['id']}")
        assert resp.status_code == 204

    def test_bulk_import(self, client):
        resp = client.post("/api/findings/bulk-import", json={
            "findings": [
                {"title": "F1", "severity": "high"},
                {"title": "F2", "severity": "medium"},
                {"title": "F3", "severity": "low"},
            ]
        })
        assert resp.status_code == 201
        assert resp.json()["imported"] == 3

    def test_bulk_import_empty_list_rejected(self, client):
        resp = client.post("/api/findings/bulk-import", json={"findings": []})
        assert resp.status_code == 422

    def test_stats_endpoint(self, client):
        client.post("/api/findings", json={"title": "A", "severity": "critical"})
        client.post("/api/findings", json={"title": "B", "severity": "low"})
        resp = client.get("/api/findings/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert "by_severity" in data

    def test_deduplicate_endpoint(self, client):
        client.post("/api/findings", json={"title": "F", "severity": "high"})
        resp = client.post("/api/findings/deduplicate")
        assert resp.status_code == 200
        assert "total_input" in resp.json()

    def test_cvss_endpoint(self, client):
        r = client.post("/api/findings", json={"title": "RCE", "severity": "critical"})
        fid = r.json()["id"]
        resp = client.post(f"/api/findings/{fid}/cvss", json={
            "attack_vector": "N", "attack_complexity": "L",
            "privileges_required": "N", "user_interaction": "N",
            "scope": "U", "confidentiality": "H",
            "integrity": "H", "availability": "H",
        })
        assert resp.status_code == 200
        assert resp.json()["base_score"] == 9.8

    def test_list_pagination(self, client):
        for i in range(10):
            client.post("/api/findings", json={"title": f"F{i}", "severity": "info"})
        resp = client.get("/api/findings?limit=3&offset=0")
        assert resp.json()["count"] == 3
        resp2 = client.get("/api/findings?limit=3&offset=3")
        assert resp2.json()["count"] == 3

    def test_list_search(self, client):
        client.post("/api/findings", json={"title": "SQL Injection", "severity": "high"})
        client.post("/api/findings", json={"title": "SSRF vuln", "severity": "medium"})
        resp = client.get("/api/findings?search=sql")
        assert resp.json()["count"] == 1
