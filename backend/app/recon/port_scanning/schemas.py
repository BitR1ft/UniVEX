"""
Pydantic schemas for port scanning module
"""
from typing import Optional, List, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field, field_validator


class ScanMode(str, Enum):
    """Port scan mode"""
    ACTIVE = "active"
    PASSIVE = "passive"
    HYBRID = "hybrid"


class ScanType(str, Enum):
    """Naabu scan type"""
    SYN = "syn"
    CONNECT = "connect"


class ServiceInfo(BaseModel):
    """Service information for a port"""
    port: int
    protocol: str = "tcp"
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    cpe: Optional[str] = None
    confidence: Optional[int] = None


class CDNInfo(BaseModel):
    """CDN/WAF detection information"""
    is_cdn: bool = False
    provider: Optional[str] = None
    detection_method: Optional[str] = None  # "ip_range", "cname", "header"
    metadata: Optional[Dict[str, Any]] = None


class PortInfo(BaseModel):
    """Complete port information"""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[ServiceInfo] = None
    source: str  # "naabu", "shodan", "nmap"


class IPPortScan(BaseModel):
    """Port scan results for a single IP"""
    ip: str
    ports: List[PortInfo] = []
    cdn_info: Optional[CDNInfo] = None
    scan_duration: Optional[float] = None
    timestamp: Optional[str] = None


class PortScanRequest(BaseModel):
    """Port scan request parameters"""
    targets: List[str] = Field(..., description="IP addresses or domains to scan")
    mode: ScanMode = ScanMode.ACTIVE
    scan_type: ScanType = ScanType.SYN
    top_ports: Optional[int] = Field(1000, description="Number of top ports to scan")
    custom_ports: Optional[List[int]] = Field(None, description="Custom port list")
    port_range: Optional[str] = Field(None, description="Port range (e.g., '1-65535')")
    rate_limit: Optional[int] = Field(1000, description="Packets per second")
    threads: Optional[int] = Field(25, description="Number of threads")
    timeout: Optional[int] = Field(10, description="Timeout in seconds")
    exclude_cdn: bool = Field(False, description="Exclude CDN IPs from scanning")
    service_detection: bool = Field(True, description="Perform service detection")
    banner_grab: bool = Field(True, description="Grab service banners")
    shodan_api_key: Optional[str] = None
    
    @field_validator('top_ports')
    @classmethod
    def validate_top_ports(cls, v):
        if v is not None and (v < 1 or v > 65535):
            raise ValueError("top_ports must be between 1 and 65535")
        return v
    
    @field_validator('threads')
    @classmethod
    def validate_threads(cls, v):
        if v is not None and (v < 1 or v > 100):
            raise ValueError("threads must be between 1 and 100")
        return v


class PortScanResult(BaseModel):
    """Complete port scan results"""
    targets: List[IPPortScan] = []
    total_ips_scanned: int = 0
    total_ports_found: int = 0
    total_services_identified: int = 0
    cdn_ips_found: int = 0
    scan_mode: ScanMode
    scan_duration: float
    timestamp: str
    statistics: Optional[Dict[str, Any]] = None


class PortScanStats(BaseModel):
    """Statistics for port scanning"""
    total_ips: int
    scanned_ips: int
    total_ports_found: int
    open_ports: int
    filtered_ports: int
    closed_ports: int
    services_detected: int
    cdn_ips: int
    scan_duration: float


class ShodanHostInfo(BaseModel):
    """Shodan InternetDB host information"""
    ip: str
    ports: List[int] = []
    cpes: List[str] = []
    hostnames: List[str] = []
    tags: List[str] = []
    vulns: List[str] = []
