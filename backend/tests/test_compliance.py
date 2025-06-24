"""

Coverage:
  TestOWASPMapping (13 tests)
  TestPCIDSSMapping (12 tests)
  TestNISTMapping (11 tests)
  TestCISMapping (8 tests)
  TestComplianceMapper (10 tests)
  TestComplianceAPI (10 tests + 1 fixture)

Total: 65 tests
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI

# ---------------------------------------------------------------------------
# Framework imports
# ---------------------------------------------------------------------------
from app.compliance.frameworks.owasp_top10 import (
    OWASP_TOP10_CONTROLS,
    OwaspControl,
    map_finding_to_owasp,
)
from app.compliance.frameworks.pci_dss import (
    PCI_DSS_CONTROLS,
    PCIDSSRequirement,
    map_finding_to_pci_dss,
)
from app.compliance.frameworks.nist_800_53 import (
    NIST_CONTROLS,
    NISTFamily,
    map_finding_to_nist,
)
from app.compliance.frameworks.cis_benchmarks import (
    CIS_BENCHMARKS,
    CISBenchmark,
    map_finding_to_cis,
)
from app.compliance.mapper import (
    ComplianceMapper,
    ComplianceReport,
    ControlMapping,
    Finding,
    GapAnalysis,
    SUPPORTED_FRAMEWORKS,
)
from app.api.compliance import router as compliance_router


# ---------------------------------------------------------------------------
# Test app and client
# ---------------------------------------------------------------------------

def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(compliance_router)
    return app


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(_make_app())


# ---------------------------------------------------------------------------
# Finding factories
# ---------------------------------------------------------------------------

def _finding(
    id: str = "F001",
    title: str = "SQL Injection",
    description: str = "Unsanitised input allows SQL injection",
    severity: str = "high",
    category: str = "injection",
    source: str = "manual",
) -> Finding:
    return Finding(
        id=id,
        title=title,
        description=description,
        severity=severity,
        category=category,
        source=source,
        tested=True,
    )


# ===========================================================================
# TestOWASPMapping
# ===========================================================================

class TestOWASPMapping:
    def test_all_ten_controls_defined(self):
        assert len(OWASP_TOP10_CONTROLS) == 10

    def test_control_ids_correct(self):
        expected = {f"A{str(i).zfill(2)}" for i in range(1, 11)}
        assert set(OWASP_TOP10_CONTROLS.keys()) == expected

    def test_a01_broken_access_control_mapped(self):
        result = map_finding_to_owasp("IDOR Vulnerability", "insecure direct object reference allows unauthorized access")
        assert "A01" in result

    def test_a02_cryptographic_failures_mapped(self):
        result = map_finding_to_owasp("Weak Cipher Suite", "Server supports RC4 and MD5 weak cipher")
        assert "A02" in result

    def test_a03_injection_mapped(self):
        result = map_finding_to_owasp("SQL Injection", "Error-based SQL injection found in login endpoint")
        assert "A03" in result

    def test_a04_insecure_design_mapped(self):
        result = map_finding_to_owasp("Missing Rate Limiting", "No rate limit applied to authentication endpoint")
        assert "A04" in result

    def test_a05_security_misconfiguration_mapped(self):
        result = map_finding_to_owasp("Default Credentials", "Admin panel accessible with default password admin/admin")
        assert "A05" in result

    def test_a06_vulnerable_components_mapped(self):
        result = map_finding_to_owasp("Outdated Library", "Application uses unpatched outdated library with known CVE")
        assert "A06" in result

    def test_a07_authentication_failure_mapped(self):
        result = map_finding_to_owasp("Broken Authentication", "No account lockout after repeated brute force attempts")
        assert "A07" in result

    def test_a08_integrity_failure_mapped(self):
        result = map_finding_to_owasp("Insecure Deserialization", "Java object deserialization vulnerability allows RCE")
        assert "A08" in result

    def test_a09_logging_failure_mapped(self):
        result = map_finding_to_owasp("Insufficient Logging", "Failed login attempts not logged in audit trail")
        assert "A09" in result

    def test_a10_ssrf_mapped(self):
        result = map_finding_to_owasp("SSRF Vulnerability", "Server-side request forgery allows access to internal services")
        assert "A10" in result

    def test_unknown_finding_returns_empty(self):
        result = map_finding_to_owasp("Typo in UI Label", "A cosmetic spelling error on the dashboard page")
        assert result == []


# ===========================================================================
# TestPCIDSSMapping
# ===========================================================================

class TestPCIDSSMapping:
    def test_all_twelve_requirements_defined(self):
        assert len(PCI_DSS_CONTROLS) == 12

    def test_requirement_ids_correct(self):
        expected = {str(i) for i in range(1, 13)}
        assert set(PCI_DSS_CONTROLS.keys()) == expected

    def test_req1_firewall_mapped(self):
        result = map_finding_to_pci_dss("Open Firewall Port", "Unnecessary port 8080 exposed through firewall rule")
        assert "1" in result

    def test_req2_default_creds_mapped(self):
        result = map_finding_to_pci_dss("Default Credentials", "Device uses default credentials set by vendor")
        assert "2" in result

    def test_req3_stored_data_mapped(self):
        result = map_finding_to_pci_dss("Unencrypted PAN", "Primary account number stored as clear text in database")
        assert "3" in result

    def test_req4_transmission_mapped(self):
        result = map_finding_to_pci_dss("Plaintext Transmission", "Cardholder data transmitted without TLS encryption")
        assert "4" in result

    def test_req6_injection_mapped(self):
        result = map_finding_to_pci_dss("Cross-Site Scripting", "Reflected XSS in search parameter of payment page")
        assert "6" in result

    def test_req8_authentication_mapped(self):
        result = map_finding_to_pci_dss("Missing MFA", "Multi-factor authentication not enforced for admin access")
        assert "8" in result

    def test_req10_logging_mapped(self):
        result = map_finding_to_pci_dss("Audit Log Gap", "Access logging disabled on payment processing system")
        assert "10" in result

    def test_req11_penetration_test_mapped(self):
        result = map_finding_to_pci_dss("No Penetration Test", "Evidence of vulnerability scan missing from security testing")
        assert "11" in result

    def test_req12_policy_mapped(self):
        result = map_finding_to_pci_dss("Missing Security Policy", "No information security policy found for the organisation")
        assert "12" in result

    def test_unknown_finding_returns_empty(self):
        result = map_finding_to_pci_dss("UI Color Contrast", "Low contrast ratio in user interface for accessibility")
        assert result == []


# ===========================================================================
# TestNISTMapping
# ===========================================================================

class TestNISTMapping:
    def test_twenty_families_defined(self):
        assert len(NIST_CONTROLS) == 20

    def test_ac_access_control_mapped(self):
        result = map_finding_to_nist("Broken Access Control", "Unauthorized access to admin functionality via IDOR")
        assert "AC" in result

    def test_au_audit_mapped(self):
        result = map_finding_to_nist("Missing Audit Log", "Authentication events not captured in audit log")
        assert "AU" in result

    def test_ia_identification_mapped(self):
        result = map_finding_to_nist("Weak Authentication", "No account lockout enables brute force of credentials")
        assert "IA" in result

    def test_sc_system_comms_mapped(self):
        result = map_finding_to_nist("Weak Encryption", "TLS 1.0 still enabled; weak cipher suite negotiated")
        assert "SC" in result

    def test_si_system_integrity_mapped(self):
        result = map_finding_to_nist("SQL Injection", "Input validation missing; SQL injection possible")
        assert "SI" in result

    def test_ra_risk_assessment_mapped(self):
        result = map_finding_to_nist("No Vulnerability Scan", "Risk assessment and vulnerability scan not performed")
        assert "RA" in result

    def test_sa_acquisition_mapped(self):
        result = map_finding_to_nist("Supply Chain Risk", "Third-party component from untrusted supply chain source")
        assert "SA" in result

    def test_ir_incident_response_mapped(self):
        result = map_finding_to_nist("No Incident Response Plan", "Organization lacks incident response capability")
        assert "IR" in result

    def test_cm_config_management_mapped(self):
        result = map_finding_to_nist("Security Misconfiguration", "System deployed with insecure default configuration")
        assert "CM" in result

    def test_unknown_finding_returns_empty(self):
        result = map_finding_to_nist("Logo Alignment Issue", "The company logo appears misaligned on mobile devices")
        assert result == []


# ===========================================================================
# TestCISMapping
# ===========================================================================

class TestCISMapping:
    def test_five_platforms_defined(self):
        assert len(CIS_BENCHMARKS) == 5

    def test_docker_privileged_mapped(self):
        result = map_finding_to_cis("Privileged Container", "Container runs with --privileged flag enabling container escape", platform="docker")
        assert any("docker" in r for r in result)

    def test_kubernetes_anonymous_auth_mapped(self):
        result = map_finding_to_cis("Anonymous Authentication Enabled", "Kubernetes API server allows anonymous authentication", platform="kubernetes")
        assert any("kubernetes" in r for r in result)

    def test_aws_iam_mapped(self):
        result = map_finding_to_cis("Overprivileged IAM Role", "AWS IAM role has excessive permissions attached", platform="aws")
        assert any("aws" in r for r in result)

    def test_linux_ssh_root_mapped(self):
        result = map_finding_to_cis("SSH Root Login Enabled", "Direct SSH root login allowed on production server", platform="linux")
        assert any("linux" in r for r in result)

    def test_azure_mfa_mapped(self):
        result = map_finding_to_cis("Azure MFA Not Enforced", "MFA azure not configured for privileged accounts", platform="azure")
        assert any("azure" in r for r in result)

    def test_no_platform_searches_all(self):
        result = map_finding_to_cis("Privileged Container", "Container runs with --privileged flag")
        assert len(result) >= 1

    def test_unknown_finding_returns_empty(self):
        result = map_finding_to_cis("Font Size Issue", "The font size on the login page is too small")
        assert result == []

    def test_platform_filter_limits_results(self):
        docker_result = map_finding_to_cis("Privileged Container", "Container running with --privileged flag", platform="docker")
        all_result = map_finding_to_cis("Privileged Container", "Container running with --privileged flag")
        # Platform-filtered should only contain docker entries
        assert all("docker" in r for r in docker_result)


# ===========================================================================
# TestComplianceMapper
# ===========================================================================

class TestComplianceMapper:
    @pytest.fixture
    def mapper(self) -> ComplianceMapper:
        return ComplianceMapper()

    @pytest.fixture
    def sample_findings(self) -> list[Finding]:
        return [
            _finding("F001", "SQL Injection", "Error-based SQL injection in login form", "critical"),
            _finding("F002", "Broken Access Control", "IDOR allows access to other users' data", "high"),
            _finding("F003", "Weak TLS", "Server supports TLS 1.0 with weak cipher suites", "medium"),
            _finding("F004", "Missing Audit Log", "Authentication failures not captured in audit logging", "low"),
        ]

    def test_map_findings_returns_compliance_report(self, mapper, sample_findings):
        report = mapper.map_findings(sample_findings, "owasp")
        assert isinstance(report, ComplianceReport)
        assert report.framework == "owasp"

    def test_report_has_ten_owasp_mappings(self, mapper, sample_findings):
        report = mapper.map_findings(sample_findings, "owasp")
        assert len(report.mappings) == 10

    def test_report_has_twelve_pci_mappings(self, mapper, sample_findings):
        report = mapper.map_findings(sample_findings, "pci_dss")
        assert len(report.mappings) == 12

    def test_report_has_twenty_nist_mappings(self, mapper, sample_findings):
        report = mapper.map_findings(sample_findings, "nist")
        assert len(report.mappings) == 20

    def test_gap_analysis_returned(self, mapper, sample_findings):
        gap = mapper.get_gap_analysis(sample_findings, "owasp")
        assert isinstance(gap, GapAnalysis)
        assert gap.framework == "owasp"
        assert gap.total_controls == 10

    def test_coverage_percentage_between_0_and_100(self, mapper, sample_findings):
        gap = mapper.get_gap_analysis(sample_findings, "owasp")
        assert 0.0 <= gap.coverage_percentage <= 100.0

    def test_map_all_frameworks_returns_four(self, mapper, sample_findings):
        reports = mapper.map_all_frameworks(sample_findings)
        assert set(reports.keys()) == {"owasp", "pci_dss", "nist", "cis"}

    def test_unsupported_framework_raises_value_error(self, mapper, sample_findings):
        with pytest.raises(ValueError, match="Unsupported framework"):
            mapper.map_findings(sample_findings, "iso27001")

    def test_empty_findings_coverage_zero(self, mapper):
        gap = mapper.get_gap_analysis([], "owasp")
        assert gap.tested_controls == 0
        assert gap.coverage_percentage == 0.0
        assert gap.total_controls == 10

    def test_to_dict_contains_expected_keys(self, mapper, sample_findings):
        report = mapper.map_findings(sample_findings, "owasp")
        d = report.to_dict()
        assert "framework" in d
        assert "generated_at" in d
        assert "findings" in d
        assert "mappings" in d
        assert "gap_analysis" in d
        assert "risk_summary" in d


# ===========================================================================
# TestComplianceAPI
# ===========================================================================

class TestComplianceAPI:
    @pytest.fixture(autouse=True)
    def _client(self, client):
        self.client = client

    def _finding_payload(
        self,
        id: str = "F001",
        title: str = "SQL Injection",
        description: str = "SQL injection via login parameter",
        severity: str = "high",
    ) -> dict:
        return {
            "id": id,
            "title": title,
            "description": description,
            "severity": severity,
            "category": "injection",
            "source": "manual",
            "tested": True,
        }

    def test_list_frameworks_returns_four(self):
        resp = self.client.get("/api/compliance/frameworks")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["frameworks"]) == 4

    def test_list_frameworks_contains_owasp(self):
        resp = self.client.get("/api/compliance/frameworks")
        ids = [f["id"] for f in resp.json()["frameworks"]]
        assert "owasp" in ids

    def test_map_findings_owasp_returns_report(self):
        payload = {
            "findings": [self._finding_payload()],
            "framework": "owasp",
        }
        resp = self.client.post("/api/compliance/map", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == "owasp"
        assert "mappings" in data
        assert "gap_analysis" in data

    def test_map_findings_invalid_framework_returns_400(self):
        payload = {
            "findings": [self._finding_payload()],
            "framework": "iso27001",
        }
        resp = self.client.post("/api/compliance/map", json=payload)
        assert resp.status_code == 400

    def test_gaps_endpoint_returns_gap_analysis(self):
        payload = {
            "findings": [self._finding_payload()],
            "framework": "pci_dss",
        }
        resp = self.client.post("/api/compliance/gaps", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "total_controls" in data
        assert "coverage_percentage" in data

    def test_gaps_invalid_framework_returns_400(self):
        payload = {
            "findings": [self._finding_payload()],
            "framework": "cobit",
        }
        resp = self.client.post("/api/compliance/gaps", json=payload)
        assert resp.status_code == 400

    def test_map_all_returns_all_frameworks(self):
        payload = {
            "findings": [self._finding_payload()],
        }
        resp = self.client.post("/api/compliance/map-all", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert set(data.keys()) == {"owasp", "pci_dss", "nist", "cis"}

    def test_controls_owasp_returns_ten(self):
        resp = self.client.get("/api/compliance/controls/owasp")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 10

    def test_controls_pci_dss_returns_twelve(self):
        resp = self.client.get("/api/compliance/controls/pci_dss")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 12

    def test_controls_invalid_framework_returns_400(self):
        resp = self.client.get("/api/compliance/controls/unknown_fw")
        assert resp.status_code == 400
