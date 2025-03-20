"""
HTTP Probing Schemas - Month 5

Pydantic models for HTTP probing data validation and serialization.
"""

from typing import List, Optional, Dict
from pydantic import BaseModel, Field, field_validator
from enum import Enum
from datetime import datetime


class ProbeMode(str, Enum):
    """HTTP Probe mode options"""
    BASIC = "basic"  # Basic HTTP probing only
    FULL = "full"    # Full probing with all features
    STEALTH = "stealth"  # Minimal requests


class HttpProbeRequest(BaseModel):
    """Request model for HTTP probing"""
    targets: List[str] = Field(..., description="List of URLs or IPs to probe")
    mode: ProbeMode = Field(default=ProbeMode.FULL, description="Probing mode")
    follow_redirects: bool = Field(default=True, description="Follow HTTP redirects")
    max_redirects: int = Field(default=10, description="Maximum redirect chains")
    timeout: int = Field(default=10, description="Request timeout in seconds")
    threads: int = Field(default=50, description="Concurrent threads")
    tech_detection: bool = Field(default=True, description="Enable technology detection")
    wappalyzer: bool = Field(default=True, description="Use Wappalyzer for tech detection")
    screenshot: bool = Field(default=False, description="Capture screenshots")
    favicon_hash: bool = Field(default=True, description="Hash favicon")
    tls_inspection: bool = Field(default=True, description="Inspect TLS certificates")
    jarm_fingerprint: bool = Field(default=True, description="Generate JARM fingerprints")
    security_headers: bool = Field(default=True, description="Analyze security headers")
    
    @field_validator('threads')
    @classmethod
    def validate_threads(cls, v):
        if not 1 <= v <= 200:
            raise ValueError('threads must be between 1 and 200')
        return v
    
    @field_validator('timeout')
    @classmethod
    def validate_timeout(cls, v):
        if not 1 <= v <= 60:
            raise ValueError('timeout must be between 1 and 60 seconds')
        return v


class SecurityHeaders(BaseModel):
    """Security header analysis"""
    strict_transport_security: Optional[str] = None
    content_security_policy: Optional[str] = None
    x_frame_options: Optional[str] = None
    x_content_type_options: Optional[str] = None
    x_xss_protection: Optional[str] = None
    referrer_policy: Optional[str] = None
    permissions_policy: Optional[str] = None
    missing_headers: List[str] = Field(default_factory=list)
    security_score: int = Field(default=0, ge=0, le=100)


class TLSCertInfo(BaseModel):
    """TLS Certificate information"""
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    subject_alt_names: List[str] = Field(default_factory=list)
    signature_algorithm: Optional[str] = None
    public_key_type: Optional[str] = None
    public_key_bits: Optional[int] = None
    is_expired: bool = False
    is_self_signed: bool = False


class TLSInfo(BaseModel):
    """TLS connection information"""
    version: Optional[str] = None
    cipher_suite: Optional[str] = None
    cipher_strength: Optional[str] = None  # weak, medium, strong
    certificate: Optional[TLSCertInfo] = None
    jarm_fingerprint: Optional[str] = None
    has_weak_cipher: bool = False


class TechnologyInfo(BaseModel):
    """Detected technology information"""
    name: str
    version: Optional[str] = None
    category: Optional[str] = None
    confidence: int = Field(ge=0, le=100)
    source: str = Field(description="httpx or wappalyzer")
    cpe: Optional[str] = None
    website: Optional[str] = None
    icon: Optional[str] = None


class FaviconInfo(BaseModel):
    """Favicon hash information"""
    url: str
    md5: Optional[str] = None
    sha256: Optional[str] = None
    mmh3: Optional[int] = None  # Shodan's MurmurHash3
    content_type: Optional[str] = None
    size_bytes: Optional[int] = None


class RedirectChain(BaseModel):
    """HTTP redirect chain information"""
    url: str
    status_code: int
    location: Optional[str] = None


class ContentInfo(BaseModel):
    """HTTP content analysis"""
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    word_count: Optional[int] = None
    line_count: Optional[int] = None
    title: Optional[str] = None
    meta_description: Optional[str] = None
    meta_keywords: Optional[List[str]] = Field(default_factory=list)


class BaseURLInfo(BaseModel):
    """Complete HTTP probe result for a single URL"""
    url: str
    final_url: Optional[str] = None
    scheme: str  # http or https
    host: str
    port: int
    ip: Optional[str] = None
    status_code: Optional[int] = None
    status_text: Optional[str] = None
    
    # Response metadata
    headers: Dict[str, str] = Field(default_factory=dict)
    response_time_ms: Optional[float] = None
    content: Optional[ContentInfo] = None
    
    # Redirect information
    redirects: List[RedirectChain] = Field(default_factory=list)
    redirect_count: int = 0
    
    # TLS information
    tls: Optional[TLSInfo] = None
    
    # Technology detection
    technologies: List[TechnologyInfo] = Field(default_factory=list)
    
    # Security
    security_headers: Optional[SecurityHeaders] = None
    
    # Additional fingerprints
    favicon: Optional[FaviconInfo] = None
    server_header: Optional[str] = None
    powered_by: Optional[str] = None
    
    # CDN/ASN information
    cdn_name: Optional[str] = None
    cdn_detected: bool = False
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    
    # Screenshot
    screenshot_path: Optional[str] = None
    
    # Timestamp
    probed_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Error tracking
    error: Optional[str] = None
    success: bool = True


class HttpProbeStats(BaseModel):
    """Statistics from HTTP probing"""
    total_targets: int
    successful_probes: int
    failed_probes: int
    https_count: int
    http_count: int
    redirect_count: int
    technologies_found: int
    unique_technologies: int
    cdn_count: int
    tls_count: int
    avg_response_time_ms: Optional[float] = None
    duration_seconds: float


class HttpProbeResult(BaseModel):
    """Complete HTTP probing result"""
    request: HttpProbeRequest
    results: List[BaseURLInfo] = Field(default_factory=list)
    stats: HttpProbeStats
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None


class WappalyzerTechnology(BaseModel):
    """Wappalyzer technology detection result"""
    name: str
    version: Optional[str] = None
    categories: List[str] = Field(default_factory=list)
    confidence: int = 100
    icon: Optional[str] = None
    website: Optional[str] = None
    cpe: Optional[str] = None
