"""
Integration tests for vulnerability scanning module.

Author: BitR1FT (BitR1FT)
Developed by: BitR1FT
Project: UniVex - Month 7
"""

import pytest

from app.recon.vuln_scanning.schemas import (
    VulnScanRequest,
    ScanMode,
    NucleiConfig,
    CVEEnrichmentConfig,
    MITREConfig,
    VulnSeverity,
)


class TestIntegration:
    """Integration tests for vulnerability scanning."""
    
    def test_scan_request_serialization(self, sample_targets):
        """Test that scan request can be serialized to JSON."""
        request = VulnScanRequest(
            targets=sample_targets,
            mode=ScanMode.FULL
        )
        
        # Serialize to dict
        data = request.model_dump(mode='json')
        
        assert data["targets"] == sample_targets
        assert data["mode"] == "full"
        assert "nuclei_config" in data
        assert "cve_enrichment" in data
        assert "mitre_mapping" in data
    
    def test_scan_request_deserialization(self, sample_targets):
        """Test that scan request can be deserialized from JSON."""
        data = {
            "targets": sample_targets,
            "mode": "active",
            "nuclei_config": {
                "severity_filter": ["critical", "high"],
                "dast_enabled": True,
                "rate_limit": 50
            }
        }
        
        request = VulnScanRequest(**data)
        
        assert request.mode == ScanMode.ACTIVE
        assert request.nuclei_config.dast_enabled is True
        assert request.nuclei_config.rate_limit == 50
    
    def test_vulnerability_with_full_enrichment(self):
        """Test vulnerability with CVE and MITRE data."""
        from app.recon.vuln_scanning.schemas import (
            VulnerabilityInfo,
            CVEInfo,
            MITREData,
            CWEInfo,
            CAPECInfo,
            VulnCategory,
        )
        
        # Create MITRE data
        cwe = CWEInfo(
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
            description="SQL injection vulnerability"
        )
        
        capec = CAPECInfo(
            capec_id="CAPEC-66",
            capec_name="SQL Injection",
            description="SQL injection attack pattern",
            likelihood="High",
            severity="Very High"
        )
        
        mitre = MITREData(cwe=cwe, capec=[capec])
        
        # Create CVE with MITRE
        cve = CVEInfo(
            cve_id="CVE-2024-1234",
            cvss_score=8.5,
            severity=VulnSeverity.HIGH,
            description="SQL injection in login",
            mitre=mitre
        )
        
        # Create vulnerability with CVE
        vuln = VulnerabilityInfo(
            id="test-001",
            title="SQL Injection",
            description="SQL injection vulnerability",
            severity=VulnSeverity.HIGH,
            category=VulnCategory.SQLI,
            source="nuclei",
            cve=cve
        )
        
        # Verify full chain
        assert vuln.cve is not None
        assert vuln.cve.mitre is not None
        assert vuln.cve.mitre.cwe.cwe_id == "CWE-89"
        assert len(vuln.cve.mitre.capec) == 1
        assert vuln.cve.mitre.capec[0].capec_id == "CAPEC-66"
        
        # Verify serialization
        data = vuln.model_dump(mode='json')
        assert data["cve"]["mitre"]["cwe"]["cwe_id"] == "CWE-89"
    
    def test_scan_result_serialization(self, sample_targets, sample_vulnerability):
        """Test that full scan result can be serialized."""
        from app.recon.vuln_scanning.schemas import VulnScanResult, VulnScanStats
        
        request = VulnScanRequest(targets=sample_targets)
        
        stats = VulnScanStats(
            total_vulnerabilities=1,
            by_severity={"high": 1},
            by_category={"sqli": 1},
            execution_time=10.5
        )
        
        result = VulnScanResult(
            request=request,
            vulnerabilities=[sample_vulnerability],
            stats=stats,
            success=True
        )
        
        # Serialize
        data = result.model_dump(mode='json')
        
        assert data["success"] is True
        assert data["stats"]["total_vulnerabilities"] == 1
        assert len(data["vulnerabilities"]) == 1
    
    def test_all_scan_modes_are_valid(self, sample_targets):
        """Test that all scan modes can be used in requests."""
        for mode in ScanMode:
            request = VulnScanRequest(
                targets=sample_targets,
                mode=mode
            )
            assert request.mode == mode
            
            # Verify serialization
            data = request.model_dump(mode='json')
            assert data["mode"] == mode.value
    
    def test_all_severities_are_valid(self):
        """Test that all severity levels can be used."""
        from app.recon.vuln_scanning.schemas import VulnerabilityInfo, VulnCategory
        
        for severity in VulnSeverity:
            vuln = VulnerabilityInfo(
                id=f"test-{severity.value}",
                title=f"Test {severity.value}",
                description="Test vulnerability",
                severity=severity,
                category=VulnCategory.UNKNOWN,
                source="test"
            )
            assert vuln.severity == severity
    
    def test_all_categories_are_valid(self):
        """Test that all vulnerability categories can be used."""
        from app.recon.vuln_scanning.schemas import VulnerabilityInfo, VulnCategory
        
        for category in VulnCategory:
            vuln = VulnerabilityInfo(
                id=f"test-{category.value}",
                title=f"Test {category.value}",
                description="Test vulnerability",
                severity=VulnSeverity.MEDIUM,
                category=category,
                source="test"
            )
            assert vuln.category == category
