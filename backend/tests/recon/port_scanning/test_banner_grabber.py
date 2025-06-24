"""
Tests for Banner Grabber Module
"""
import pytest
from app.recon.port_scanning.banner_grabber import BannerGrabber
from app.recon.port_scanning.schemas import ServiceInfo


class TestBannerGrabber:
    """Test banner grabbing functionality"""
    
    def test_initialization(self):
        """Test banner grabber initialization"""
        grabber = BannerGrabber(timeout=5)
        assert grabber is not None
        assert grabber.timeout == 5
    
    def test_version_extraction_ssh(self):
        """Test version extraction from SSH banner"""
        grabber = BannerGrabber()
        
        banner = "SSH-2.0-OpenSSH_7.4"
        result = grabber.extract_version_from_banner(banner)
        
        assert result is not None
        assert result['version'] == 'OpenSSH_7.4'
    
    def test_version_extraction_http(self):
        """Test version extraction from HTTP Server header"""
        grabber = BannerGrabber()
        
        banner = "Server: nginx/1.18.0"
        result = grabber.extract_version_from_banner(banner)
        
        assert result is not None
        assert result['product'] == 'nginx'
        assert result['version'] == '1.18.0'
    
    def test_version_extraction_mysql(self):
        """Test version extraction from MySQL banner"""
        grabber = BannerGrabber()
        
        banner = "5.7.30-MariaDB"
        result = grabber.extract_version_from_banner(banner)
        
        assert result is not None
        assert result['version'] == '5.7.30'
    
    def test_version_extraction_redis(self):
        """Test version extraction from Redis banner"""
        grabber = BannerGrabber()
        
        banner = "redis_version:6.0.9"
        result = grabber.extract_version_from_banner(banner)
        
        assert result is not None
        assert result['version'] == '6.0.9'
    
    def test_version_extraction_empty_banner(self):
        """Test version extraction with empty banner"""
        grabber = BannerGrabber()
        
        result = grabber.extract_version_from_banner("")
        assert result is None
    
    def test_version_extraction_no_match(self):
        """Test version extraction with no pattern match"""
        grabber = BannerGrabber()
        
        banner = "Unknown service"
        result = grabber.extract_version_from_banner(banner)
        assert result is None
    
    def test_enrich_service_with_banner(self):
        """Test enriching service info with banner"""
        grabber = BannerGrabber()
        
        service = ServiceInfo(
            port=80,
            protocol="tcp",
            service_name="http"
        )
        
        banner = "Server: Apache/2.4.41"
        enriched = grabber.enrich_service_with_banner(service, banner)
        
        assert enriched.banner == banner
        # Version extraction should have worked
        assert enriched.product == "Apache"
        assert enriched.version == "2.4.41"
    
    def test_enrich_service_existing_version(self):
        """Test enriching service that already has version info"""
        grabber = BannerGrabber()
        
        service = ServiceInfo(
            port=22,
            protocol="tcp",
            service_name="ssh",
            product="OpenSSH",
            version="7.4"
        )
        
        banner = "SSH-2.0-OpenSSH_7.4"
        enriched = grabber.enrich_service_with_banner(service, banner)
        
        assert enriched.banner == banner
        # Should keep existing version
        assert enriched.product == "OpenSSH"
        assert enriched.version == "7.4"
    
    def test_protocol_probes(self):
        """Test that protocol-specific probes are defined"""
        grabber = BannerGrabber()
        
        # Check common protocol probes exist
        assert 21 in grabber.PROBES  # FTP
        assert 22 in grabber.PROBES  # SSH
        assert 80 in grabber.PROBES  # HTTP
        assert 443 in grabber.PROBES  # HTTPS
        assert 3306 in grabber.PROBES  # MySQL
