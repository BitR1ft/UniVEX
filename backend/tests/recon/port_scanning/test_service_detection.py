"""
Tests for Service Detection Module
"""
import pytest
from app.recon.port_scanning.service_detection import ServiceDetector
from app.recon.port_scanning.schemas import ServiceInfo, PortInfo


class TestServiceDetector:
    """Test service detection functionality"""
    
    def test_initialization(self):
        """Test service detector initialization"""
        detector = ServiceDetector()
        assert detector is not None
        assert detector.iana_services is not None
    
    def test_iana_service_mapping_http(self):
        """Test IANA service mapping for HTTP"""
        detector = ServiceDetector()
        
        service = detector.get_service_name(80)
        assert service == "http"
    
    def test_iana_service_mapping_https(self):
        """Test IANA service mapping for HTTPS"""
        detector = ServiceDetector()
        
        service = detector.get_service_name(443)
        assert service == "https"
    
    def test_iana_service_mapping_ssh(self):
        """Test IANA service mapping for SSH"""
        detector = ServiceDetector()
        
        service = detector.get_service_name(22)
        assert service == "ssh"
    
    def test_iana_service_mapping_unknown_port(self):
        """Test IANA mapping for unknown port"""
        detector = ServiceDetector()
        
        service = detector.get_service_name(99999)
        assert service is None
    
    def test_iana_service_mapping_mysql(self):
        """Test IANA service mapping for MySQL"""
        detector = ServiceDetector()
        
        service = detector.get_service_name(3306)
        assert service == "mysql"
    
    def test_iana_service_mapping_postgresql(self):
        """Test IANA service mapping for PostgreSQL"""
        detector = ServiceDetector()
        
        service = detector.get_service_name(5432)
        assert service == "postgresql"
    
    def test_fallback_to_iana(self):
        """Test fallback to IANA when Nmap is not available"""
        detector = ServiceDetector()
        
        ports = [80, 443, 22]
        services = detector._fallback_to_iana(ports)
        
        assert len(services) == 3
        assert services[0].port == 80
        assert services[0].service_name == "http"
        assert services[1].port == 443
        assert services[1].service_name == "https"
        assert services[2].port == 22
        assert services[2].service_name == "ssh"
    
    def test_common_ports_mapping(self):
        """Test mapping of common ports"""
        detector = ServiceDetector()
        
        common_ports = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            3306: "mysql",
            5432: "postgresql",
            6379: "redis",
            27017: "mongodb"
        }
        
        for port, expected_service in common_ports.items():
            service = detector.get_service_name(port)
            assert service == expected_service, f"Port {port} should map to {expected_service}"
