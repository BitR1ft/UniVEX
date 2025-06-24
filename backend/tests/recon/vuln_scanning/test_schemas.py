"""
Tests for vulnerability scanning schemas.

Author: BitR1FT (BitR1FT)
Developed by: BitR1FT
Project: UniVex - Month 7
"""

import pytest
from pydantic import ValidationError
from datetime import datetime

from app.recon.vuln_scanning.schemas import (
    VulnScanRequest,
    VulnerabilityInfo,
    CVEInfo,
    CWEInfo,
    CAPECInfo,
    MITREData,
    ScanMode,
    VulnSeverity,
    VulnCategory,
    NucleiConfig,
    CVEEnrichmentConfig,
    MITREConfig,
    VulnScanStats,
    VulnScanResult,
)


class TestVulnScanRequest:
    """Tests for VulnScanRequest schema."""
    
    def test_minimal_request(self, sample_targets):
        """Test creating minimal scan request."""
        request = VulnScanRequest(targets=sample_targets)
        
        assert request.targets == sample_targets
        assert request.mode == ScanMode.FULL
        assert isinstance(request.nuclei_config, NucleiConfig)
        assert isinstance(request.cve_enrichment, CVEEnrichmentConfig)
        assert isinstance(request.mitre_mapping, MITREConfig)
    
    def test_empty_targets_validation(self):
        """Test that empty targets list raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            VulnScanRequest(targets=[])
        
        assert "Targets list cannot be empty" in str(exc_info.value)
    
    def test_all_scan_modes(self, sample_targets):
        """Test all scan modes."""
        for mode in ScanMode:
            request = VulnScanRequest(
                targets=sample_targets,
                mode=mode
            )
            assert request.mode == mode
    
    def test_custom_configuration(self, sample_targets, basic_nuclei_config):
        """Test request with custom configurations."""
        request = VulnScanRequest(
            targets=sample_targets,
            mode=ScanMode.ACTIVE,
            nuclei_config=basic_nuclei_config,
            parallel_execution=False,
            max_workers=5
        )
        
        assert request.nuclei_config.rate_limit == 50
        assert request.parallel_execution is False
        assert request.max_workers == 5
    
    def test_detected_technologies(self, sample_targets):
        """Test with detected technologies."""
        technologies = [
            {"name": "nginx", "version": "1.20.0"},
            {"name": "php", "version": "7.4.0"}
        ]
        
        request = VulnScanRequest(
            targets=sample_targets,
            detected_technologies=technologies
        )
        
        assert len(request.detected_technologies) == 2
        assert request.detected_technologies[0]["name"] == "nginx"


class TestNucleiConfig:
    """Tests for NucleiConfig schema."""
    
    def test_default_config(self):
        """Test default Nuclei configuration."""
        config = NucleiConfig()
        
        assert config.severity_filter == [VulnSeverity.CRITICAL, VulnSeverity.HIGH]
        assert config.exclude_tags == ["dos", "fuzz"]
        assert config.rate_limit == 100
        assert config.concurrency == 25
        assert config.auto_update_templates is True
    
    def test_dast_configuration(self):
        """Test DAST-enabled configuration."""
        config = NucleiConfig(
            dast_enabled=True,
            interactsh_enabled=True,
            interactsh_server="https://custom.interactsh.com"
        )
        
        assert config.dast_enabled is True
        assert config.interactsh_enabled is True
        assert config.interactsh_server == "https://custom.interactsh.com"
    
    def test_severity_filtering(self):
        """Test severity filter configuration."""
        config = NucleiConfig(
            severity_filter=[VulnSeverity.CRITICAL]
        )
        
        assert len(config.severity_filter) == 1
        assert config.severity_filter[0] == VulnSeverity.CRITICAL
    
    def test_tag_filtering(self):
        """Test tag filtering."""
        config = NucleiConfig(
            include_tags=["cve", "xss", "sqli"],
            exclude_tags=["dos", "fuzz", "slow"]
        )
        
        assert "cve" in config.include_tags
        assert "dos" in config.exclude_tags


class TestCVEInfo:
    """Tests for CVEInfo schema."""
    
    def test_cve_creation(self):
        """Test creating CVE information."""
        cve = CVEInfo(
            cve_id="CVE-2024-1234",
            cvss_score=8.5,
            severity=VulnSeverity.HIGH,
            description="Test vulnerability"
        )
        
        assert cve.cve_id == "CVE-2024-1234"
        assert cve.cvss_score == 8.5
        assert cve.severity == VulnSeverity.HIGH
    
    def test_cvss_score_validation(self):
        """Test CVSS score validation."""
        # Valid scores
        for score in [0.0, 5.5, 10.0]:
            cve = CVEInfo(
                cve_id="CVE-2024-0001",
                cvss_score=score,
                severity=VulnSeverity.INFO,
                description="Test"
            )
            assert cve.cvss_score == score
        
        # Invalid scores
        with pytest.raises(ValidationError):
            CVEInfo(
                cve_id="CVE-2024-0001",
                cvss_score=11.0,  # > 10.0
                severity=VulnSeverity.INFO,
                description="Test"
            )
    
    def test_cve_with_mitre(self):
        """Test CVE with MITRE data."""
        cwe = CWEInfo(
            cwe_id="CWE-79",
            cwe_name="Cross-site Scripting"
        )
        
        mitre = MITREData(cwe=cwe, capec=[])
        
        cve = CVEInfo(
            cve_id="CVE-2024-1234",
            severity=VulnSeverity.MEDIUM,
            description="XSS vulnerability",
            mitre=mitre
        )
        
        assert cve.mitre is not None
        assert cve.mitre.cwe.cwe_id == "CWE-79"


class TestVulnerabilityInfo:
    """Tests for VulnerabilityInfo schema."""
    
    def test_vulnerability_creation(self, sample_vulnerability):
        """Test creating vulnerability."""
        assert sample_vulnerability.id == "nuclei-CVE-2024-1234"
        assert sample_vulnerability.severity == VulnSeverity.HIGH
        assert sample_vulnerability.category == VulnCategory.SQLI
        assert sample_vulnerability.source == "nuclei"
    
    def test_vulnerability_with_cve(self):
        """Test vulnerability with CVE information."""
        cve = CVEInfo(
            cve_id="CVE-2024-5678",
            cvss_score=9.8,
            severity=VulnSeverity.CRITICAL,
            description="Critical RCE"
        )
        
        vuln = VulnerabilityInfo(
            id="test-001",
            title="Remote Code Execution",
            description="RCE vulnerability",
            severity=VulnSeverity.CRITICAL,
            category=VulnCategory.RCE,
            source="nuclei",
            cve=cve
        )
        
        assert vuln.cve is not None
        assert vuln.cve.cve_id == "CVE-2024-5678"
        assert vuln.cve.cvss_score == 9.8
    
    def test_vulnerability_defaults(self):
        """Test default values."""
        vuln = VulnerabilityInfo(
            id="test-002",
            title="Test Vulnerability",
            description="Test description",
            severity=VulnSeverity.LOW,
            source="test"
        )
        
        assert vuln.category == VulnCategory.UNKNOWN
        assert vuln.tags == []
        assert vuln.references == []
        assert isinstance(vuln.discovered_at, datetime)


class TestVulnScanStats:
    """Tests for VulnScanStats schema."""
    
    def test_stats_creation(self):
        """Test creating scan statistics."""
        stats = VulnScanStats(
            total_vulnerabilities=42,
            by_severity={"critical": 5, "high": 15, "medium": 20, "low": 2},
            by_category={"sqli": 8, "xss": 12},
            by_source={"nuclei": 42},
            execution_time=125.5
        )
        
        assert stats.total_vulnerabilities == 42
        assert stats.by_severity["critical"] == 5
        assert stats.execution_time == 125.5
    
    def test_stats_defaults(self):
        """Test default statistics values."""
        stats = VulnScanStats()
        
        assert stats.total_vulnerabilities == 0
        assert stats.by_severity == {}
        assert stats.execution_time == 0.0


class TestVulnScanResult:
    """Tests for VulnScanResult schema."""
    
    def test_result_creation(self, sample_targets, sample_vulnerability):
        """Test creating scan result."""
        request = VulnScanRequest(targets=sample_targets)
        
        stats = VulnScanStats(
            total_vulnerabilities=1,
            execution_time=10.5
        )
        
        result = VulnScanResult(
            request=request,
            vulnerabilities=[sample_vulnerability],
            stats=stats,
            success=True
        )
        
        assert result.success is True
        assert len(result.vulnerabilities) == 1
        assert result.stats.total_vulnerabilities == 1
        assert isinstance(result.scan_completed_at, datetime)
    
    def test_result_with_errors(self, sample_targets):
        """Test result with errors."""
        request = VulnScanRequest(targets=sample_targets)
        stats = VulnScanStats()
        
        result = VulnScanResult(
            request=request,
            vulnerabilities=[],
            stats=stats,
            errors=["Error 1", "Error 2"],
            warnings=["Warning 1"],
            success=False
        )
        
        assert result.success is False
        assert len(result.errors) == 2
        assert len(result.warnings) == 1


class TestMITRESchemas:
    """Tests for MITRE-related schemas."""
    
    def test_cwe_info(self):
        """Test CWE information schema."""
        cwe = CWEInfo(
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
            description="SQL command injection",
            parent_cwe="CWE-943",
            abstraction_level="Base"
        )
        
        assert cwe.cwe_id == "CWE-89"
        assert cwe.cwe_name == "SQL Injection"
        assert cwe.parent_cwe == "CWE-943"
    
    def test_capec_info(self):
        """Test CAPEC information schema."""
        capec = CAPECInfo(
            capec_id="CAPEC-66",
            capec_name="SQL Injection",
            description="Attack via SQL injection",
            likelihood="High",
            severity="Very High",
            prerequisites=["SQL database", "Unsanitized input"],
            mitigations=["Parameterized queries"],
            examples=["UNION SQLi"]
        )
        
        assert capec.capec_id == "CAPEC-66"
        assert capec.likelihood == "High"
        assert len(capec.prerequisites) == 2
        assert len(capec.mitigations) == 1
    
    def test_mitre_data(self):
        """Test MITRE data schema."""
        cwe = CWEInfo(cwe_id="CWE-79", cwe_name="XSS")
        capec = CAPECInfo(capec_id="CAPEC-18", capec_name="XSS Attack")
        
        mitre = MITREData(cwe=cwe, capec=[capec])
        
        assert mitre.cwe.cwe_id == "CWE-79"
        assert len(mitre.capec) == 1
        assert mitre.capec[0].capec_id == "CAPEC-18"
