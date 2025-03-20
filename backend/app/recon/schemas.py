"""
Pydantic schemas for reconnaissance module.

Defines data models for API requests/responses and internal data structures.
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field, field_validator
from datetime import datetime


class WhoisData(BaseModel):
    """WHOIS information schema."""
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    name_servers: List[str] = Field(default_factory=list)
    status: List[str] = Field(default_factory=list)
    emails: List[str] = Field(default_factory=list)
    org: Optional[str] = None
    country: Optional[str] = None


class DNSRecords(BaseModel):
    """DNS records schema."""
    A: Optional[List[str]] = Field(default_factory=list, description="IPv4 addresses")
    AAAA: Optional[List[str]] = Field(default_factory=list, description="IPv6 addresses")
    MX: Optional[List[str]] = Field(default_factory=list, description="Mail exchange records")
    NS: Optional[List[str]] = Field(default_factory=list, description="Name server records")
    TXT: Optional[List[str]] = Field(default_factory=list, description="Text records")
    CNAME: Optional[List[str]] = Field(default_factory=list, description="Canonical name records")
    SOA: Optional[List[str]] = Field(default_factory=list, description="Start of authority records")


class IPAddresses(BaseModel):
    """IP addresses schema."""
    ipv4: List[str] = Field(default_factory=list, description="IPv4 addresses")
    ipv6: List[str] = Field(default_factory=list, description="IPv6 addresses")


class DNSResult(BaseModel):
    """DNS resolution result schema."""
    domain: str
    records: DNSRecords = Field(default_factory=DNSRecords)
    ips: IPAddresses = Field(default_factory=IPAddresses)
    errors: List[str] = Field(default_factory=list)


class ReconStatistics(BaseModel):
    """Reconnaissance statistics schema."""
    total_subdomains: int = 0
    resolved_subdomains: int = 0
    total_ips: int = 0
    ipv4_count: int = 0
    ipv6_count: int = 0
    record_types: Dict[str, int] = Field(default_factory=dict)


class DomainDiscoveryResult(BaseModel):
    """Complete domain discovery result schema."""
    domain: str
    timestamp: str
    whois: Optional[WhoisData] = None
    subdomains: List[str] = Field(default_factory=list)
    dns_records: Dict[str, DNSResult] = Field(default_factory=dict)
    ip_mapping: Dict[str, List[str]] = Field(default_factory=dict)
    statistics: ReconStatistics = Field(default_factory=ReconStatistics)
    duration: float = 0.0
    error: Optional[str] = None


class ReconTaskRequest(BaseModel):
    """Request to start a reconnaissance task."""
    domain: str = Field(..., min_length=3, max_length=253, description="Target domain name")
    hackertarget_api_key: Optional[str] = Field(None, description="HackerTarget API key")
    dns_nameservers: Optional[List[str]] = Field(None, description="Custom DNS nameservers")
    enable_bruteforce: bool = Field(False, description="Enable subdomain brute-forcing with Knockpy")
    wordlist: Optional[str] = Field(None, description="Custom wordlist path for brute-forcing")
    
    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Validate domain format."""
        if not v or len(v.strip()) < 3:
            raise ValueError("Domain must be at least 3 characters")
        
        # Basic domain validation
        domain = v.strip().lower()
        if not all(c.isalnum() or c in '.-' for c in domain):
            raise ValueError("Domain contains invalid characters")
        
        return domain


class ReconTaskStatus(BaseModel):
    """Status of a reconnaissance task."""
    task_id: str
    domain: str
    status: str = Field(..., description="Status: pending, running, completed, failed")
    progress: int = Field(0, ge=0, le=100, description="Progress percentage")
    message: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    user_id: str


class ReconTaskResponse(BaseModel):
    """Response for reconnaissance task operations."""
    status: str
    message: str
    task_id: Optional[str] = None
    data: Optional[Any] = None


class ReconTaskList(BaseModel):
    """List of reconnaissance tasks."""
    tasks: List[ReconTaskStatus]
    total: int
    page: int = 1
    per_page: int = 20
