"""
Tests for CDN Detection Module
"""
import pytest
from app.recon.port_scanning.cdn_detector import CDNDetector
from app.recon.port_scanning.schemas import CDNInfo


class TestCDNDetector:
    """Test CDN detection functionality"""
    
    def test_initialization(self):
        """Test CDN detector initialization"""
        detector = CDNDetector()
        assert detector is not None
        assert detector.compiled_ranges is not None
    
    def test_cloudflare_ip_detection(self):
        """Test Cloudflare IP detection"""
        detector = CDNDetector()
        
        # Test known Cloudflare IP
        result = detector.detect_by_ip("104.16.1.1")
        assert result.is_cdn is True
        assert result.provider == "cloudflare"
        assert result.detection_method == "ip_range"
    
    def test_non_cdn_ip(self):
        """Test non-CDN IP"""
        detector = CDNDetector()
        
        # Test private IP
        result = detector.detect_by_ip("192.168.1.1")
        assert result.is_cdn is False
    
    def test_cname_cloudflare_detection(self):
        """Test CNAME-based Cloudflare detection"""
        detector = CDNDetector()
        
        result = detector.detect_by_cname("example.cloudflare.com")
        assert result.is_cdn is True
        assert result.provider == "cloudflare"
        assert result.detection_method == "cname"
    
    def test_cname_akamai_detection(self):
        """Test CNAME-based Akamai detection"""
        detector = CDNDetector()
        
        result = detector.detect_by_cname("example.akamai.net")
        assert result.is_cdn is True
        assert result.provider == "akamai"
    
    def test_cname_no_cdn(self):
        """Test CNAME without CDN"""
        detector = CDNDetector()
        
        result = detector.detect_by_cname("example.com")
        assert result.is_cdn is False
    
    def test_should_exclude_cdn_ip(self):
        """Test CDN IP exclusion logic"""
        detector = CDNDetector()
        
        # Should exclude Cloudflare IP when exclude_cdn is True
        assert detector.should_exclude_ip("104.16.1.1", exclude_cdn=True) is True
        
        # Should not exclude when exclude_cdn is False
        assert detector.should_exclude_ip("104.16.1.1", exclude_cdn=False) is False
        
        # Should not exclude non-CDN IP
        assert detector.should_exclude_ip("192.168.1.1", exclude_cdn=True) is False
    
    def test_invalid_ip(self):
        """Test handling of invalid IP address"""
        detector = CDNDetector()
        
        result = detector.detect_by_ip("invalid-ip")
        assert result.is_cdn is False
    
    def test_akamai_ip_detection(self):
        """Test Akamai IP detection"""
        detector = CDNDetector()
        
        # Test known Akamai IP range
        result = detector.detect_by_ip("23.1.1.1")
        assert result.is_cdn is True
        assert result.provider == "akamai"
    
    def test_fastly_ip_detection(self):
        """Test Fastly IP detection"""
        detector = CDNDetector()
        
        result = detector.detect_by_ip("151.101.1.1")
        assert result.is_cdn is True
        assert result.provider == "fastly"
