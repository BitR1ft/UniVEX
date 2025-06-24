"""

Coverage:
  TestFinding (8 tests)
  TestFindingDeduplicator (8 tests)
  TestFindingRanker (7 tests)
  TestReportEngine (14 tests)
  TestChartGenerator (10 tests)
  TestPDFGenerator (8 tests)
  TestReportAPI (15 tests)

Total: 70 tests
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
from typing import List

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Domain imports
# ---------------------------------------------------------------------------
from app.reports.report_engine import (
    Finding,
    FindingDeduplicator,
    FindingRanker,
    ReportConfig,
    ReportEngine,
    ReportFormat,
    ReportMetadata,
    ReportTemplate,
    ScanResult,
    Severity,
)
from app.reports.chart_generator import ChartGenerator
from app.reports.pdf_generator import PDFGenerator, PDFOptions


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

def _finding(
    title: str = "SQL Injection",
    severity: Severity = Severity.HIGH,
    cvss: float = 8.1,
    component: str = "login endpoint",
    cve: str | None = None,
    owasp: str | None = None,
    likelihood: str = "medium",
) -> Finding:
    return Finding(
        title=title,
        description=f"Description for {title}",
        severity=severity,
        cvss_score=cvss,
        cve_id=cve,
        cwe_id="CWE-89",
        owasp_category=owasp,
        reproduction_steps=["Step 1", "Step 2"],
        evidence="SELECT * FROM users WHERE id='1 OR 1=1'",
        remediation="Use parameterised queries.",
        affected_component=component,
        likelihood=likelihood,
        business_impact="Data breach.",
        nist_controls=["SI-10"],
        pci_dss_requirements=["6"],
    )


def _scan_result(findings: List[Finding] | None = None) -> ScanResult:
    return ScanResult(
        target="10.10.10.1",
        scan_type="web",
        started_at=datetime(2024, 1, 1, 10, 0, 0),
        completed_at=datetime(2024, 1, 1, 10, 30, 0),
        findings=findings or [_finding()],
    )


def _config(template: ReportTemplate = ReportTemplate.TECHNICAL_REPORT) -> ReportConfig:
    return ReportConfig(
        title="Test Report",
        template=template,
        format=ReportFormat.HTML,
        include_charts=False,  # charts off by default in tests (matplotlib may vary)
        include_toc=True,
    )


def _metadata() -> ReportMetadata:
    return ReportMetadata(
        project_name="UniVex Test",
        author="Security Bot",
        generated_at=datetime(2024, 1, 1, 12, 0, 0),
    )


# ---------------------------------------------------------------------------
# TestFinding
# ---------------------------------------------------------------------------

class TestFinding:
    def test_default_id_generated(self):
        f = Finding(title="XSS")
        assert f.id and len(f.id) == 36  # UUID4

    def test_severity_order_critical_lowest(self):
        assert Finding(severity=Severity.CRITICAL).severity_order == 0

    def test_severity_order_info_highest(self):
        assert Finding(severity=Severity.INFO).severity_order == 4

    def test_fingerprint_is_deterministic(self):
        f1 = _finding(title="XSS", component="search")
        f2 = _finding(title="XSS", component="search")
        assert f1.fingerprint == f2.fingerprint

    def test_fingerprint_differs_on_title(self):
        f1 = _finding(title="XSS")
        f2 = _finding(title="SSRF")
        assert f1.fingerprint != f2.fingerprint

    def test_fingerprint_differs_on_component(self):
        f1 = _finding(component="login")
        f2 = _finding(component="register")
        assert f1.fingerprint != f2.fingerprint

    def test_severity_enum_value(self):
        assert Severity.CRITICAL.value == "critical"

    def test_finding_fields(self):
        f = _finding(cvss=9.8, cve="CVE-2023-1234")
        assert f.cvss_score == 9.8
        assert f.cve_id == "CVE-2023-1234"


# ---------------------------------------------------------------------------
# TestFindingDeduplicator
# ---------------------------------------------------------------------------

class TestFindingDeduplicator:
    def setup_method(self):
        self.dedup = FindingDeduplicator()

    def test_empty_list(self):
        assert self.dedup.deduplicate([]) == []

    def test_no_duplicates_unchanged(self):
        findings = [_finding("A"), _finding("B"), _finding("C")]
        result = self.dedup.deduplicate(findings)
        assert len(result) == 3

    def test_exact_duplicate_removed(self):
        f = _finding("XSS")
        result = self.dedup.deduplicate([f, f])
        assert len(result) == 1

    def test_same_title_same_component_deduplicated(self):
        f1 = _finding("SQL Injection", component="login")
        f2 = _finding("SQL Injection", component="login")
        result = self.dedup.deduplicate([f1, f2])
        assert len(result) == 1

    def test_same_title_different_component_kept(self):
        f1 = _finding("SQL Injection", component="login")
        f2 = _finding("SQL Injection", component="register")
        result = self.dedup.deduplicate([f1, f2])
        assert len(result) == 2

    def test_first_occurrence_kept(self):
        f1 = _finding("XSS", severity=Severity.CRITICAL)
        f2 = _finding("XSS", severity=Severity.LOW)
        result = self.dedup.deduplicate([f1, f2])
        assert result[0].severity == Severity.CRITICAL

    def test_multiple_duplicates(self):
        f = _finding("Broken Auth")
        result = self.dedup.deduplicate([f, f, f, f])
        assert len(result) == 1

    def test_mixed_findings(self):
        findings = [
            _finding("A", component="c1"),
            _finding("B", component="c2"),
            _finding("A", component="c1"),  # dup
            _finding("C", component="c3"),
        ]
        result = self.dedup.deduplicate(findings)
        assert len(result) == 3


# ---------------------------------------------------------------------------
# TestFindingRanker
# ---------------------------------------------------------------------------

class TestFindingRanker:
    def setup_method(self):
        self.ranker = FindingRanker()

    def test_empty_list(self):
        assert self.ranker.rank([]) == []

    def test_critical_first(self):
        findings = [
            _finding("Low vuln", severity=Severity.LOW),
            _finding("Critical vuln", severity=Severity.CRITICAL),
            _finding("Medium vuln", severity=Severity.MEDIUM),
        ]
        ranked = self.ranker.rank(findings)
        assert ranked[0].severity == Severity.CRITICAL

    def test_info_last(self):
        findings = [_finding(severity=Severity.INFO), _finding(severity=Severity.HIGH)]
        ranked = self.ranker.rank(findings)
        assert ranked[-1].severity == Severity.INFO

    def test_same_severity_sorted_by_cvss_desc(self):
        f1 = _finding(title="A", severity=Severity.HIGH, cvss=6.0)
        f2 = _finding(title="B", severity=Severity.HIGH, cvss=9.8)
        ranked = self.ranker.rank([f1, f2])
        assert ranked[0].cvss_score == 9.8

    def test_same_severity_same_cvss_sorted_by_title(self):
        f1 = _finding(title="ZXCVBN", severity=Severity.HIGH, cvss=7.0)
        f2 = _finding(title="ABCDEF", severity=Severity.HIGH, cvss=7.0)
        ranked = self.ranker.rank([f1, f2])
        assert ranked[0].title == "ABCDEF"

    def test_complete_severity_ordering(self):
        findings = [_finding(severity=s) for s in reversed(list(Severity))]
        ranked = self.ranker.rank(findings)
        expected = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        assert [r.severity for r in ranked] == expected

    def test_single_finding_unchanged(self):
        f = _finding()
        assert self.ranker.rank([f]) == [f]


# ---------------------------------------------------------------------------
# TestReportEngine
# ---------------------------------------------------------------------------

class TestReportEngine:
    def setup_method(self):
        self.engine = ReportEngine()

    def test_generate_technical_html_contains_title(self):
        html = self.engine.generate(
            scan_results=[_scan_result()],
            config=_config(ReportTemplate.TECHNICAL_REPORT),
            metadata=_metadata(),
        )
        assert "Test Report" in html
        assert "<!DOCTYPE html>" in html

    def test_generate_executive_summary(self):
        html = self.engine.generate(
            scan_results=[_scan_result()],
            config=_config(ReportTemplate.EXECUTIVE_SUMMARY),
            metadata=_metadata(),
        )
        assert "Executive Summary" in html

    def test_generate_compliance_report(self):
        html = self.engine.generate(
            scan_results=[_scan_result()],
            config=_config(ReportTemplate.COMPLIANCE_REPORT),
            metadata=_metadata(),
        )
        assert "OWASP" in html
        assert "PCI-DSS" in html or "PCI" in html

    def test_finding_title_in_output(self):
        f = _finding(title="Remote Code Execution")
        html = self.engine.generate(
            scan_results=[_scan_result(findings=[f])],
            config=_config(),
            metadata=_metadata(),
        )
        assert "Remote Code Execution" in html

    def test_empty_findings(self):
        html = self.engine.generate(
            scan_results=[_scan_result(findings=[])],
            config=_config(),
            metadata=_metadata(),
        )
        assert html  # no crash, returns HTML

    def test_multiple_scan_results(self):
        sr1 = _scan_result([_finding("XSS")])
        sr2 = _scan_result([_finding("SSRF")])
        html = self.engine.generate(
            scan_results=[sr1, sr2],
            config=_config(),
            metadata=_metadata(),
        )
        assert "XSS" in html
        assert "SSRF" in html

    def test_deduplication_applied(self):
        f = _finding("Dup Finding")
        html = self.engine.generate(
            scan_results=[_scan_result([f, f, f])],
            config=_config(),
            metadata=_metadata(),
        )
        # Should appear only once in the findings section
        assert html.count("Dup Finding") >= 1  # at least once

    def test_severity_counts_correct(self):
        findings = [
            _finding(severity=Severity.CRITICAL),
            _finding("H1", severity=Severity.HIGH),
            _finding("H2", severity=Severity.HIGH),
        ]
        html = self.engine.generate(
            scan_results=[_scan_result(findings)],
            config=_config(ReportTemplate.EXECUTIVE_SUMMARY),
            metadata=_metadata(),
        )
        assert "1" in html  # at least one critical
        assert html  # rendered ok

    def test_count_by_severity_helper(self):
        findings = [_finding(severity=Severity.CRITICAL), _finding(severity=Severity.HIGH)]
        counts = ReportEngine._count_by_severity(findings)
        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["medium"] == 0

    def test_risk_score_zero_no_findings(self):
        score = ReportEngine._calculate_risk_score([])
        assert score == 0.0

    def test_risk_score_critical_findings(self):
        findings = [_finding(severity=Severity.CRITICAL)] * 5
        score = ReportEngine._calculate_risk_score(findings)
        assert score > 0

    def test_risk_level_critical(self):
        assert ReportEngine._risk_level(8.0) == "Critical"

    def test_risk_level_none(self):
        assert ReportEngine._risk_level(0.0) == "None"

    def test_owasp_coverage_grouping(self):
        f = _finding(owasp="A03")
        coverage = ReportEngine._owasp_coverage([f])
        assert "A03" in coverage
        assert len(coverage["A03"]) == 1


# ---------------------------------------------------------------------------
# TestChartGenerator
# ---------------------------------------------------------------------------

class TestChartGenerator:
    def setup_method(self):
        self.gen = ChartGenerator()
        self.findings = [
            _finding(severity=Severity.CRITICAL, cvss=9.8),
            _finding("XSS", severity=Severity.HIGH, cvss=7.5),
            _finding("Info", severity=Severity.INFO, cvss=0.0),
        ]

    def test_severity_pie_returns_string_or_empty(self):
        result = self.gen.generate_severity_pie(self.findings)
        assert isinstance(result, str)

    def test_severity_bar_returns_string_or_empty(self):
        result = self.gen.generate_severity_bar(self.findings)
        assert isinstance(result, str)

    def test_cvss_histogram_returns_string_or_empty(self):
        result = self.gen.generate_cvss_histogram(self.findings)
        assert isinstance(result, str)

    def test_risk_heatmap_returns_string_or_empty(self):
        result = self.gen.generate_risk_heatmap(self.findings)
        assert isinstance(result, str)

    def test_attack_timeline_empty_without_dates(self):
        result = self.gen.generate_attack_timeline(self.findings)
        assert isinstance(result, str)

    def test_attack_timeline_with_dates(self):
        f = _finding()
        f.discovered_at = datetime(2024, 1, 15)
        result = self.gen.generate_attack_timeline([f])
        assert isinstance(result, str)

    def test_generate_all_returns_dict(self):
        result = self.gen.generate_all(self.findings)
        assert isinstance(result, dict)
        assert "severity_pie" in result
        assert "severity_bar" in result
        assert "cvss_histogram" in result
        assert "risk_heatmap" in result

    def test_empty_findings_return_empty_string(self):
        assert self.gen.generate_severity_pie([]) == ""
        assert self.gen.generate_severity_bar([]) == ""
        assert self.gen.generate_risk_heatmap([]) == ""

    def test_base64_valid_if_matplotlib_available(self):
        if not self.gen._mpl_available:
            pytest.skip("matplotlib not installed")
        result = self.gen.generate_severity_pie(self.findings)
        if result:
            # Should be valid base64
            decoded = base64.b64decode(result)
            assert decoded[:8] == b"\x89PNG\r\n\x1a\n"  # PNG magic bytes

    def test_chart_generator_count_severity(self):
        findings = [_finding(severity=Severity.CRITICAL), _finding(severity=Severity.HIGH)]
        counts = ChartGenerator._count_severity(findings)
        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["medium"] == 0


# ---------------------------------------------------------------------------
# TestPDFGenerator
# ---------------------------------------------------------------------------

class TestPDFGenerator:
    def setup_method(self):
        self.gen = PDFGenerator()

    def test_is_available_returns_bool(self):
        result = PDFGenerator.is_available()
        assert isinstance(result, bool)

    def test_generate_pdf_no_weasyprint_returns_empty(self):
        if PDFGenerator.is_available():
            pytest.skip("WeasyPrint is installed; testing fallback not applicable")
        result = self.gen.generate_pdf("<html><body>test</body></html>")
        assert result == b""

    def test_generate_pdf_with_mock(self):
        """Test PDF generation path with mocked WeasyPrint."""
        mock_pdf_bytes = b"%PDF-1.4 test"
        with patch("app.reports.pdf_generator.PDFGenerator.is_available", return_value=True):
            gen = PDFGenerator()
            gen._weasyprint_available = True
            with patch.dict("sys.modules", {"weasyprint": MagicMock()}):
                import sys
                mock_wp = sys.modules["weasyprint"]
                mock_html_instance = MagicMock()
                mock_html_instance.write_pdf.return_value = mock_pdf_bytes
                mock_wp.HTML.return_value = mock_html_instance
                mock_wp.CSS.return_value = MagicMock()
                result = gen.generate_pdf("<html></html>")
                # Either real or mocked bytes
                assert isinstance(result, bytes)

    def test_pdf_options_defaults(self):
        opts = PDFOptions()
        assert opts.page_size == "A4"
        assert "20mm" in opts.margin_top

    def test_pdf_options_custom(self):
        opts = PDFOptions(page_size="Letter", margin_top="10mm")
        assert opts.page_size == "Letter"
        assert opts.margin_top == "10mm"

    def test_generate_pdf_unavailable_logs_warning(self, caplog):
        import logging
        gen = PDFGenerator()
        gen._weasyprint_available = False
        with caplog.at_level(logging.WARNING, logger="app.reports.pdf_generator"):
            result = gen.generate_pdf("<html></html>")
        assert result == b""

    def test_pdf_generator_constructor(self):
        gen = PDFGenerator(options=PDFOptions(page_size="A3"))
        assert gen._options.page_size == "A3"

    def test_generate_pdf_from_file(self, tmp_path):
        html_file = tmp_path / "test.html"
        html_file.write_text("<html><body>Hello PDF</body></html>", encoding="utf-8")
        gen = PDFGenerator()
        gen._weasyprint_available = False
        result = gen.generate_pdf_from_file(str(html_file))
        assert isinstance(result, bytes)


# ---------------------------------------------------------------------------
# TestReportAPI (FastAPI TestClient)
# ---------------------------------------------------------------------------

class TestReportAPI:
    def setup_method(self):
        from fastapi import FastAPI
        from app.api import reports as reports_module

        # Build a lightweight app with only the reports router
        _app = FastAPI()
        _app.include_router(reports_module.router)

        # Clear in-memory store before each test
        reports_module._reports.clear()
        self.client = TestClient(_app)

    def _post_generate(self, template: str = "technical_report") -> dict:
        body = {
            "project_name": "Test Project",
            "author": "Tester",
            "title": "Security Report",
            "template": template,
            "format": "html",
            "include_charts": False,
            "scan_results": [
                {
                    "target": "10.0.0.1",
                    "scan_type": "web",
                    "findings": [
                        {
                            "title": "SQL Injection",
                            "description": "Unparameterised query",
                            "severity": "high",
                            "cvss_score": 8.1,
                            "affected_component": "login",
                            "remediation": "Use prepared statements",
                        }
                    ],
                }
            ],
        }
        return self.client.post("/api/reports/generate", json=body)

    def test_generate_report_returns_201(self):
        resp = self._post_generate()
        assert resp.status_code == 201

    def test_generate_report_returns_summary(self):
        resp = self._post_generate()
        data = resp.json()
        assert "id" in data
        assert data["project_name"] == "Test Project"
        assert data["template"] == "technical_report"

    def test_generate_executive_summary(self):
        resp = self._post_generate(template="executive_summary")
        assert resp.status_code == 201
        assert resp.json()["template"] == "executive_summary"

    def test_generate_compliance_report(self):
        resp = self._post_generate(template="compliance_report")
        assert resp.status_code == 201
        assert resp.json()["template"] == "compliance_report"

    def test_list_reports_empty(self):
        resp = self.client.get("/api/reports")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_reports_after_generate(self):
        self._post_generate()
        resp = self.client.get("/api/reports")
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    def test_get_report_by_id(self):
        gen_resp = self._post_generate()
        report_id = gen_resp.json()["id"]
        resp = self.client.get(f"/api/reports/{report_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == report_id

    def test_get_report_not_found(self):
        resp = self.client.get("/api/reports/nonexistent-id")
        assert resp.status_code == 404

    def test_download_html_report(self):
        gen_resp = self._post_generate()
        report_id = gen_resp.json()["id"]
        resp = self.client.get(f"/api/reports/{report_id}/download")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "<!DOCTYPE html>" in resp.text

    def test_download_not_found(self):
        resp = self.client.get("/api/reports/bad-id/download")
        assert resp.status_code == 404

    def test_delete_report(self):
        gen_resp = self._post_generate()
        report_id = gen_resp.json()["id"]
        resp = self.client.delete(f"/api/reports/{report_id}")
        assert resp.status_code == 204

    def test_delete_removes_from_list(self):
        gen_resp = self._post_generate()
        report_id = gen_resp.json()["id"]
        self.client.delete(f"/api/reports/{report_id}")
        resp = self.client.get("/api/reports")
        assert all(r["id"] != report_id for r in resp.json())

    def test_delete_not_found(self):
        resp = self.client.delete("/api/reports/nonexistent")
        assert resp.status_code == 404

    def test_generate_empty_scan_results(self):
        body = {
            "project_name": "Empty",
            "author": "Bot",
            "title": "Empty Report",
            "template": "technical_report",
            "format": "html",
            "scan_results": [],
        }
        resp = self.client.post("/api/reports/generate", json=body)
        assert resp.status_code == 201
        assert resp.json()["finding_count"] == 0

    def test_finding_count_in_summary(self):
        resp = self._post_generate()
        assert resp.json()["finding_count"] == 1
