"""
Tests for MITRE mapper.

Author: BitR1FT (BitR1FT)
Developed by: BitR1FT
Project: UniVex - Month 7
"""

import pytest
from pathlib import Path
import tempfile

from app.recon.vuln_scanning.mitre_mapper import MITREMapper
from app.recon.vuln_scanning.schemas import MITREConfig


class TestMITREMapper:
    """Tests for MITRE mapper."""
    
    @pytest.fixture
    def temp_db_path(self):
        """Create temporary database path for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    @pytest.fixture
    def mitre_config(self, temp_db_path):
        """MITRE configuration for testing."""
        return MITREConfig(
            enabled=True,
            cve_to_cwe=True,
            cwe_to_capec=True,
            auto_update_db=True,
            db_path=temp_db_path
        )
    
    @pytest.fixture
    def mapper(self, mitre_config):
        """Create MITRE mapper instance."""
        return MITREMapper(mitre_config)
    
    def test_mapper_initialization(self, mapper, temp_db_path):
        """Test MITRE mapper initialization."""
        assert mapper.config.enabled is True
        assert mapper.db_path == Path(temp_db_path)
        assert mapper.db_path.exists()
    
    def test_cwe_data_loaded(self, mapper):
        """Test that CWE data is loaded."""
        assert len(mapper.cwe_data) > 0
        assert "CWE-79" in mapper.cwe_data
        assert "CWE-89" in mapper.cwe_data
    
    def test_cwe_to_capec_mapping(self, mapper):
        """Test CWE to CAPEC mapping is loaded."""
        assert len(mapper.cwe_to_capec) > 0
        assert "CWE-79" in mapper.cwe_to_capec
        assert "CWE-89" in mapper.cwe_to_capec
    
    def test_capec_data_loaded(self, mapper):
        """Test that CAPEC data is loaded."""
        assert len(mapper.capec_data) > 0
        assert "CAPEC-18" in mapper.capec_data  # XSS
        assert "CAPEC-66" in mapper.capec_data  # SQLi
    
    def test_get_cwe_info(self, mapper):
        """Test retrieving CWE information."""
        cwe_info = mapper._get_cwe_info("CWE-89")
        
        assert cwe_info is not None
        assert cwe_info.cwe_id == "CWE-89"
        assert cwe_info.cwe_name == "SQL Injection"
        assert cwe_info.parent_cwe == "CWE-943"
    
    def test_get_cwe_info_with_number(self, mapper):
        """Test retrieving CWE by number."""
        cwe_info = mapper._get_cwe_info("79")
        
        assert cwe_info is not None
        assert cwe_info.cwe_id == "CWE-79"
        assert "XSS" in cwe_info.cwe_name or "Cross-site" in cwe_info.cwe_name
    
    def test_get_cwe_info_invalid(self, mapper):
        """Test retrieving non-existent CWE."""
        cwe_info = mapper._get_cwe_info("CWE-99999")
        assert cwe_info is None
    
    def test_get_capec_info(self, mapper):
        """Test retrieving CAPEC information."""
        capec_info = mapper._get_capec_info("CAPEC-66")
        
        assert capec_info is not None
        assert capec_info.capec_id == "CAPEC-66"
        assert capec_info.capec_name == "SQL Injection"
        assert capec_info.likelihood == "High"
        assert capec_info.severity == "Very High"
        assert len(capec_info.prerequisites) > 0
    
    def test_get_capec_info_with_number(self, mapper):
        """Test retrieving CAPEC by number."""
        capec_info = mapper._get_capec_info("18")
        
        assert capec_info is not None
        assert capec_info.capec_id == "CAPEC-18"
    
    def test_get_capec_info_invalid(self, mapper):
        """Test retrieving non-existent CAPEC."""
        capec_info = mapper._get_capec_info("CAPEC-99999")
        assert capec_info is None
    
    def test_map_cve_to_mitre_with_cwe(self, mapper):
        """Test mapping CVE to MITRE with CWE IDs."""
        mitre_data = mapper.map_cve_to_mitre("CVE-2024-1234", ["CWE-89"])
        
        assert mitre_data is not None
        assert mitre_data.cwe is not None
        assert mitre_data.cwe.cwe_id == "CWE-89"
        assert len(mitre_data.capec) > 0
        
        # Check CAPEC mapping
        capec_ids = [c.capec_id for c in mitre_data.capec]
        assert "CAPEC-66" in capec_ids
    
    def test_map_cve_to_mitre_xss(self, mapper):
        """Test mapping XSS vulnerability."""
        mitre_data = mapper.map_cve_to_mitre("CVE-2024-XSS", ["CWE-79"])
        
        assert mitre_data is not None
        assert mitre_data.cwe.cwe_id == "CWE-79"
        
        # Should have XSS-related CAPEC
        capec_ids = [c.capec_id for c in mitre_data.capec]
        assert "CAPEC-18" in capec_ids
    
    def test_map_cve_to_mitre_disabled_capec(self, temp_db_path):
        """Test mapping with CAPEC disabled."""
        config = MITREConfig(
            enabled=True,
            cve_to_cwe=True,
            cwe_to_capec=False,  # Disabled
            db_path=temp_db_path
        )
        mapper = MITREMapper(config)
        
        mitre_data = mapper.map_cve_to_mitre("CVE-2024-1234", ["CWE-89"])
        
        assert mitre_data is not None
        assert mitre_data.cwe is not None
        assert len(mitre_data.capec) == 0  # No CAPEC mapping
    
    def test_get_cwe_by_category(self, mapper):
        """Test getting CWE by vulnerability category."""
        # Test various categories
        test_cases = [
            ("xss", ["CWE-79"]),
            ("sqli", ["CWE-89"]),
            ("sql", ["CWE-89"]),
            ("rce", ["CWE-78", "CWE-94"]),
            ("lfi", ["CWE-22"]),
            ("ssrf", ["CWE-918"]),
        ]
        
        for category, expected_cwes in test_cases:
            cwes = mapper.get_cwe_by_category(category)
            assert cwes == expected_cwes
    
    def test_get_cwe_by_category_unknown(self, mapper):
        """Test getting CWE for unknown category."""
        cwes = mapper.get_cwe_by_category("unknown_category")
        assert cwes == []
    
    def test_map_multiple_cwes(self, mapper):
        """Test mapping with multiple CWEs (uses first one)."""
        mitre_data = mapper.map_cve_to_mitre("CVE-2024-MULTI", ["CWE-89", "CWE-79"])
        
        assert mitre_data is not None
        # Should use first CWE
        assert mitre_data.cwe.cwe_id == "CWE-89"
    
    def test_disabled_mapper(self, temp_db_path):
        """Test disabled MITRE mapper."""
        config = MITREConfig(enabled=False, db_path=temp_db_path)
        mapper = MITREMapper(config)
        
        mitre_data = mapper.map_cve_to_mitre("CVE-2024-1234", ["CWE-89"])
        assert mitre_data is None
    
    def test_database_persistence(self, temp_db_path):
        """Test that database files are created."""
        config = MITREConfig(
            enabled=True,
            auto_update_db=True,
            db_path=temp_db_path
        )
        mapper = MITREMapper(config)
        
        db_path = Path(temp_db_path)
        assert (db_path / "cwe_data.json").exists()
        assert (db_path / "capec_data.json").exists()
        assert (db_path / "cwe_to_capec.json").exists()
