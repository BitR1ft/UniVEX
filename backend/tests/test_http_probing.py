"""
Tests for HTTP Probing Module - Month 5
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, patch, AsyncMock
import json

from app.recon.http_probing.schemas import (
    HttpProbeRequest,
    ProbeMode,
    BaseURLInfo,
    TLSCertInfo,
    TLSInfo,
    TechnologyInfo,
    SecurityHeaders,
    FaviconInfo,
    HttpProbeStats,
    ContentInfo
)
from app.recon.http_probing.http_probe import HttpProbe
from app.recon.http_probing.tls_inspector import TLSInspector
from app.recon.http_probing.tech_detector import TechDetector
from app.recon.http_probing.favicon_hasher import FaviconHasher
from app.recon.http_probing.http_orchestrator import HttpProbeOrchestrator


# Schema Tests

def test_probe_mode_enum():
    """Test ProbeMode enum values"""
    assert ProbeMode.BASIC == "basic"
    assert ProbeMode.FULL == "full"
    assert ProbeMode.STEALTH == "stealth"


def test_http_probe_request_defaults():
    """Test HttpProbeRequest with default values"""
    request = HttpProbeRequest(targets=["https://example.com"])
    
    assert request.targets == ["https://example.com"]
    assert request.mode == ProbeMode.FULL
    assert request.follow_redirects == True
    assert request.max_redirects == 10
    assert request.timeout == 10
    assert request.threads == 50
    assert request.tech_detection == True
    assert request.wappalyzer == True


def test_http_probe_request_validation():
    """Test HttpProbeRequest validation"""
    # Valid request
    request = HttpProbeRequest(
        targets=["https://example.com"],
        threads=100,
        timeout=30
    )
    assert request.threads == 100
    
    # Invalid threads (too high)
    with pytest.raises(ValueError):
        HttpProbeRequest(
            targets=["https://example.com"],
            threads=300
        )
    
    # Invalid timeout
    with pytest.raises(ValueError):
        HttpProbeRequest(
            targets=["https://example.com"],
            timeout=100
        )


def test_security_headers_model():
    """Test SecurityHeaders model"""
    headers = SecurityHeaders(
        strict_transport_security="max-age=31536000",
        content_security_policy="default-src 'self'",
        x_frame_options="DENY",
        security_score=80
    )
    
    assert headers.strict_transport_security == "max-age=31536000"
    assert headers.security_score == 80


def test_tls_cert_info_model():
    """Test TLSCertInfo model"""
    cert = TLSCertInfo(
        subject="CN=example.com",
        issuer="CN=Let's Encrypt",
        not_before=datetime.now(timezone.utc),
        not_after=datetime.now(timezone.utc),
        days_until_expiry=45,
        subject_alt_names=["example.com", "www.example.com"],
        is_expired=False,
        is_self_signed=False
    )
    
    assert cert.subject == "CN=example.com"
    assert cert.days_until_expiry == 45
    assert len(cert.subject_alt_names) == 2


def test_technology_info_model():
    """Test TechnologyInfo model"""
    tech = TechnologyInfo(
        name="Nginx",
        version="1.18.0",
        category="Web Server",
        confidence=100,
        source="httpx"
    )
    
    assert tech.name == "Nginx"
    assert tech.version == "1.18.0"
    assert tech.confidence == 100


def test_favicon_info_model():
    """Test FaviconInfo model"""
    favicon = FaviconInfo(
        url="https://example.com/favicon.ico",
        md5="abc123",
        sha256="def456",
        mmh3=-123456,
        size_bytes=1234
    )
    
    assert favicon.md5 == "abc123"
    assert favicon.mmh3 == -123456


def test_base_url_info_model():
    """Test BaseURLInfo model"""
    info = BaseURLInfo(
        url="https://example.com",
        final_url="https://www.example.com",
        scheme="https",
        host="example.com",
        port=443,
        status_code=200,
        response_time_ms=45.2,
        success=True
    )
    
    assert info.url == "https://example.com"
    assert info.status_code == 200
    assert info.success == True


# HttpProbe Tests

class TestHttpProbe:
    """Tests for HttpProbe class"""
    
    def test_initialization(self):
        """Test HttpProbe initialization"""
        probe = HttpProbe(timeout=15, threads=100)
        
        assert probe.timeout == 15
        assert probe.threads == 100
        assert probe.follow_redirects == True
    
    def test_build_httpx_command_bulk(self):
        """Test building httpx command for bulk URLs"""
        probe = HttpProbe()
        urls = ["https://example.com", "https://google.com"]
        
        cmd, input_data = probe._build_httpx_command_bulk(urls)
        
        assert "httpx" in cmd
        assert "-json" in cmd
        assert "https://example.com\nhttps://google.com" == input_data
    
    def test_parse_security_headers(self):
        """Test security header parsing"""
        probe = HttpProbe()
        
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "Content-Type": "text/html"
        }
        
        security = probe._parse_security_headers(headers)
        
        assert security.strict_transport_security == "max-age=31536000"
        assert security.x_frame_options == "DENY"
        assert "Content-Security-Policy" in security.missing_headers
        assert security.security_score > 0
    
    def test_parse_redirect_chain(self):
        """Test redirect chain parsing"""
        probe = HttpProbe()
        
        chain_data = [
            {"url": "http://example.com", "status_code": 301, "location": "https://example.com"},
            {"url": "https://example.com", "status_code": 302, "location": "https://www.example.com"}
        ]
        
        redirects = probe._parse_redirect_chain(chain_data)
        
        assert len(redirects) == 2
        assert redirects[0].status_code == 301
        assert redirects[1].url == "https://example.com"


# TLSInspector Tests

class TestTLSInspector:
    """Tests for TLSInspector class"""
    
    def test_initialization(self):
        """Test TLSInspector initialization"""
        inspector = TLSInspector(timeout=15)
        assert inspector.timeout == 15
    
    def test_analyze_cipher_strength(self):
        """Test cipher strength analysis"""
        inspector = TLSInspector()
        
        # Strong cipher
        assert inspector._analyze_cipher_strength("TLS_AES_256_GCM_SHA384") == "strong"
        assert inspector._analyze_cipher_strength("TLS_CHACHA20_POLY1305_SHA256") == "strong"
        
        # Weak cipher
        assert inspector._analyze_cipher_strength("TLS_RSA_WITH_RC4_128_SHA") == "weak"
        assert inspector._analyze_cipher_strength("TLS_RSA_WITH_3DES_EDE_CBC_SHA") == "weak"
        
        # Medium cipher
        assert inspector._analyze_cipher_strength("TLS_RSA_WITH_AES_128_CBC_SHA") == "medium"


# TechDetector Tests

class TestTechDetector:
    """Tests for TechDetector class"""
    
    def test_initialization(self):
        """Test TechDetector initialization"""
        detector = TechDetector()
        assert detector.confidence_threshold == 50
    
    def test_parse_powered_by(self):
        """Test X-Powered-By header parsing"""
        detector = TechDetector()
        
        # PHP
        tech = detector._parse_powered_by("PHP/7.4.3")
        assert tech.name == "PHP"
        assert tech.version == "7.4.3"
        assert tech.category == "Programming Language"
        
        # ASP.NET
        tech = detector._parse_powered_by("ASP.NET")
        assert tech.name == "ASP.NET"
        assert tech.category == "Web Framework"
    
    def test_detect_from_server(self):
        """Test server header detection"""
        detector = TechDetector()
        
        # Nginx
        tech = detector._detect_from_server("nginx/1.18.0")
        assert tech.name == "nginx"
        assert tech.version == "1.18.0"
        assert tech.category == "Web Server"
        
        # Apache
        tech = detector._detect_from_server("Apache/2.4.41 (Ubuntu)")
        assert tech.name == "Apache"
        assert tech.version == "2.4.41"
    
    def test_deduplicate_technologies(self):
        """Test technology deduplication"""
        detector = TechDetector()
        
        techs = [
            TechnologyInfo(name="Nginx", version="1.18.0", category="Web Server", confidence=100, source="httpx"),
            TechnologyInfo(name="nginx", version=None, category="Web Server", confidence=80, source="wappalyzer"),
            TechnologyInfo(name="React", version="17.0.0", category="Framework", confidence=90, source="httpx"),
        ]
        
        deduplicated = detector._deduplicate_technologies(techs)
        
        # Should keep Nginx with version (higher confidence)
        assert len(deduplicated) == 2
        nginx = next(t for t in deduplicated if t.name.lower() == "nginx")
        assert nginx.version == "1.18.0"
    
    def test_merge_technologies(self):
        """Test merging technologies from different sources"""
        detector = TechDetector()
        
        httpx_techs = [
            TechnologyInfo(name="Nginx", version="1.18.0", category="Web Server", confidence=100, source="httpx"),
        ]
        
        wappalyzer_techs = [
            TechnologyInfo(name="React", version="17.0.0", category="Framework", confidence=90, source="wappalyzer"),
            TechnologyInfo(name="nginx", category="Web Server", confidence=80, source="wappalyzer"),
        ]
        
        merged = detector.merge_technologies(httpx_techs, wappalyzer_techs)
        
        assert len(merged) == 2  # Nginx deduplicated
        assert any(t.name == "React" for t in merged)


# FaviconHasher Tests

class TestFaviconHasher:
    """Tests for FaviconHasher class"""
    
    def test_initialization(self):
        """Test FaviconHasher initialization"""
        hasher = FaviconHasher(timeout=15)
        assert hasher.timeout == 15
    
    def test_get_favicon_urls(self):
        """Test favicon URL generation"""
        hasher = FaviconHasher()
        
        urls = hasher._get_favicon_urls("https://example.com/page")
        
        assert "https://example.com/favicon.ico" in urls
        assert "https://example.com/favicon.png" in urls
        assert len(urls) >= 4
    
    def test_generate_hashes(self):
        """Test hash generation"""
        hasher = FaviconHasher()
        
        test_data = b"test favicon data"
        favicon = hasher._generate_hashes("https://example.com/favicon.ico", test_data)
        
        assert favicon.md5 is not None
        assert favicon.sha256 is not None
        assert favicon.size_bytes == len(test_data)
    
    def test_search_shodan_by_favicon(self):
        """Test Shodan search query generation"""
        hasher = FaviconHasher()
        
        query = hasher.search_shodan_by_favicon(-123456)
        
        assert query == "http.favicon.hash:-123456"


# HttpProbeOrchestrator Tests

class TestHttpProbeOrchestrator:
    """Tests for HttpProbeOrchestrator class"""
    
    def test_initialization(self):
        """Test orchestrator initialization"""
        request = HttpProbeRequest(targets=["https://example.com"])
        orchestrator = HttpProbeOrchestrator(request)
        
        assert orchestrator.request == request
        assert orchestrator.http_probe is not None
        assert orchestrator.tls_inspector is not None
        assert orchestrator.tech_detector is not None
    
    def test_normalize_url(self):
        """Test URL normalization"""
        request = HttpProbeRequest(targets=["example.com"])
        orchestrator = HttpProbeOrchestrator(request)
        
        # Without scheme
        assert orchestrator._normalize_url("example.com") == "https://example.com"
        
        # With scheme
        assert orchestrator._normalize_url("http://example.com") == "http://example.com"
        assert orchestrator._normalize_url("https://example.com") == "https://example.com"
    
    @pytest.mark.asyncio
    async def test_calculate_stats(self):
        """Test statistics calculation"""
        request = HttpProbeRequest(targets=["https://example.com"])
        orchestrator = HttpProbeOrchestrator(request)
        
        results = [
            BaseURLInfo(
                url="https://example.com",
                scheme="https",
                host="example.com",
                port=443,
                success=True,
                response_time_ms=50.0,
                technologies=[
                    TechnologyInfo(name="Nginx", category="Web Server", confidence=100, source="httpx")
                ]
            ),
            BaseURLInfo(
                url="http://example.org",
                scheme="http",
                host="example.org",
                port=80,
                success=False,
                error="Connection timeout"
            )
        ]
        
        start_time = datetime.utcnow()
        stats = orchestrator._calculate_stats(results, start_time)
        
        assert stats.total_targets == 2
        assert stats.successful_probes == 1
        assert stats.failed_probes == 1
        assert stats.https_count == 1
        assert stats.http_count == 1
        assert stats.unique_technologies == 1


# Integration Tests

@pytest.mark.asyncio
async def test_http_probe_integration():
    """Integration test for HTTP probe (mocked)"""
    # This would be a real integration test in production
    # For now, we test the flow with mocked components
    
    request = HttpProbeRequest(
        targets=["https://example.com"],
        mode=ProbeMode.BASIC,
        tech_detection=False,
        wappalyzer=False,
        favicon_hash=False,
        tls_inspection=False
    )
    
    # In a real test, we would mock the httpx subprocess call
    # For now, we just verify the orchestrator can be instantiated
    orchestrator = HttpProbeOrchestrator(request)
    assert orchestrator is not None


# Performance Tests

def test_performance_targets_limit():
    """Test that request handles large number of targets"""
    targets = [f"https://example{i}.com" for i in range(1000)]
    request = HttpProbeRequest(targets=targets)
    
    assert len(request.targets) == 1000


# Error Handling Tests

def test_base_url_info_with_error():
    """Test BaseURLInfo with error state"""
    info = BaseURLInfo(
        url="https://invalid.example.com",
        scheme="https",
        host="invalid.example.com",
        port=443,
        success=False,
        error="Connection timeout"
    )
    
    assert info.success == False
    assert info.error == "Connection timeout"
    assert info.status_code is None
