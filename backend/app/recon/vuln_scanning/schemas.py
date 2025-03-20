"""
Vulnerability Scanning Schemas

Pydantic models for vulnerability scanning requests, responses, and data structures.
Supports Nuclei integration, CVE enrichment, and MITRE mapping.

Author: BitR1FT (BitR1FT)
Developed by: BitR1FT
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
from datetime import datetime


class ScanMode(str, Enum):
    """Vulnerability scanning modes."""
    BASIC = "basic"          # Nuclei with critical/high templates only
    FULL = "full"            # Nuclei with all templates + CVE enrichment + MITRE mapping
    PASSIVE = "passive"      # Non-intrusive checks only
    ACTIVE = "active"        # Nuclei DAST mode with fuzzing
    CVE_ONLY = "cve_only"    # CVE enrichment only (based on detected technologies)


class VulnSeverity(str, Enum):
    """Vulnerability severity levels (aligned with CVSS)."""
    CRITICAL = "critical"    # CVSS 9.0-10.0
    HIGH = "high"            # CVSS 7.0-8.9
    MEDIUM = "medium"        # CVSS 4.0-6.9
    LOW = "low"              # CVSS 0.1-3.9
    INFO = "info"            # CVSS 0.0 or informational


class VulnCategory(str, Enum):
    """Vulnerability categories."""
    CVE = "cve"                          # Known CVE
    XSS = "xss"                          # Cross-Site Scripting
    SQLI = "sqli"                        # SQL Injection
    RCE = "rce"                          # Remote Code Execution
    LFI = "lfi"                          # Local File Inclusion
    RFI = "rfi"                          # Remote File Inclusion
    SSRF = "ssrf"                        # Server-Side Request Forgery
    SSTI = "ssti"                        # Server-Side Template Injection
    XXE = "xxe"                          # XML External Entity
    IDOR = "idor"                        # Insecure Direct Object Reference
    AUTH_BYPASS = "auth_bypass"          # Authentication Bypass
    MISCONFIG = "misconfig"              # Misconfiguration
    EXPOSURE = "exposure"                # Information Exposure
    UNKNOWN = "unknown"                  # Unclassified


class CWEInfo(BaseModel):
    """Common Weakness Enumeration information."""
    cwe_id: str = Field(..., description="CWE identifier (e.g., CWE-79)")
    cwe_name: str = Field(..., description="CWE name")
    description: Optional[str] = Field(None, description="CWE description")
    parent_cwe: Optional[str] = Field(None, description="Parent CWE ID")
    abstraction_level: Optional[str] = Field(None, description="Abstraction level (Base, Variant, Class)")


class CAPECInfo(BaseModel):
    """Common Attack Pattern Enumeration and Classification information."""
    capec_id: str = Field(..., description="CAPEC identifier (e.g., CAPEC-63)")
    capec_name: str = Field(..., description="CAPEC attack pattern name")
    description: Optional[str] = Field(None, description="Attack pattern description")
    likelihood: Optional[str] = Field(None, description="Likelihood of success (Low, Medium, High)")
    severity: Optional[str] = Field(None, description="Attack severity")
    prerequisites: List[str] = Field(default_factory=list, description="Attack prerequisites")
    execution_flow: Optional[str] = Field(None, description="Attack execution flow")
    mitigations: List[str] = Field(default_factory=list, description="Mitigation strategies")
    examples: List[str] = Field(default_factory=list, description="Attack examples")
    references: List[str] = Field(default_factory=list, description="External references")


class MITREData(BaseModel):
    """MITRE ATT&CK framework mapping."""
    cwe: Optional[CWEInfo] = Field(None, description="CWE information")
    capec: List[CAPECInfo] = Field(default_factory=list, description="Related CAPEC attack patterns")


class CVEInfo(BaseModel):
    """CVE (Common Vulnerabilities and Exposures) information."""
    cve_id: str = Field(..., description="CVE identifier (e.g., CVE-2024-1234)")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="CVSS v3 base score")
    cvss_vector: Optional[str] = Field(None, description="CVSS v3 vector string")
    severity: VulnSeverity = Field(..., description="Severity rating")
    description: str = Field(..., description="CVE description")
    published_date: Optional[datetime] = Field(None, description="CVE publication date")
    modified_date: Optional[datetime] = Field(None, description="Last modification date")
    affected_products: List[str] = Field(default_factory=list, description="Affected products/versions")
    references: List[str] = Field(default_factory=list, description="External references")
    exploit_available: bool = Field(default=False, description="Whether public exploit exists")
    mitre: Optional[MITREData] = Field(None, description="MITRE ATT&CK mapping")


class VulnerabilityInfo(BaseModel):
    """Information about a discovered vulnerability."""
    id: str = Field(..., description="Unique vulnerability identifier")
    title: str = Field(..., description="Vulnerability title")
    description: str = Field(..., description="Detailed description")
    severity: VulnSeverity = Field(..., description="Severity level")
    category: VulnCategory = Field(default=VulnCategory.UNKNOWN, description="Vulnerability category")
    
    # Discovery details
    source: str = Field(..., description="Discovery source (nuclei, manual, etc.)")
    template_id: Optional[str] = Field(None, description="Nuclei template ID if applicable")
    matched_at: Optional[str] = Field(None, description="URL/endpoint where vulnerability was found")
    
    # Technical details
    http_method: Optional[str] = Field(None, description="HTTP method used")
    request: Optional[str] = Field(None, description="HTTP request that triggered the vulnerability")
    response: Optional[str] = Field(None, description="HTTP response snippet")
    matched_string: Optional[str] = Field(None, description="String/pattern that matched")
    curl_command: Optional[str] = Field(None, description="cURL command to reproduce")
    
    # CVE enrichment
    cve: Optional[CVEInfo] = Field(None, description="CVE information if applicable")
    
    # Metadata
    discovered_at: datetime = Field(default_factory=datetime.utcnow, description="Discovery timestamp")
    tags: List[str] = Field(default_factory=list, description="Associated tags")
    references: List[str] = Field(default_factory=list, description="External references")
    remediation: Optional[str] = Field(None, description="Remediation guidance")


class NucleiConfig(BaseModel):
    """Nuclei scanner configuration."""
    templates_path: Optional[str] = Field(None, description="Custom templates directory")
    severity_filter: List[VulnSeverity] = Field(
        default_factory=lambda: [VulnSeverity.CRITICAL, VulnSeverity.HIGH],
        description="Severity levels to scan for"
    )
    include_tags: List[str] = Field(
        default_factory=list,
        description="Tags to include (e.g., cve, xss, sqli)"
    )
    exclude_tags: List[str] = Field(
        default_factory=lambda: ["dos", "fuzz"],
        description="Tags to exclude"
    )
    template_folders: List[str] = Field(
        default_factory=list,
        description="Specific template folders to use"
    )
    
    # DAST mode settings
    dast_enabled: bool = Field(default=False, description="Enable DAST fuzzing mode")
    fuzz_payloads: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Custom fuzzing payloads by category"
    )
    
    # Interactsh settings
    interactsh_enabled: bool = Field(default=False, description="Enable Interactsh for blind vulnerabilities")
    interactsh_server: Optional[str] = Field(None, description="Custom Interactsh server URL")
    
    # Performance settings
    rate_limit: int = Field(default=100, ge=1, le=1000, description="Requests per second")
    bulk_size: int = Field(default=25, ge=1, le=100, description="Bulk size for parallel scans")
    concurrency: int = Field(default=25, ge=1, le=100, description="Template concurrency")
    timeout: int = Field(default=10, ge=1, le=60, description="Per-request timeout in seconds")
    retries: int = Field(default=1, ge=0, le=5, description="Number of retries on failure")
    
    # Advanced options
    headless_mode: bool = Field(default=False, description="Enable headless browser")
    follow_redirects: bool = Field(default=True, description="Follow HTTP redirects")
    custom_headers: Dict[str, str] = Field(default_factory=dict, description="Custom HTTP headers")
    proxy: Optional[str] = Field(None, description="HTTP/HTTPS proxy URL")
    
    # Template updates
    auto_update_templates: bool = Field(default=True, description="Auto-update templates before scanning")


class CVEEnrichmentConfig(BaseModel):
    """CVE enrichment configuration."""
    enabled: bool = Field(default=True, description="Enable CVE enrichment")
    nvd_api_key: Optional[str] = Field(None, description="NVD API key for higher rate limits")
    use_vulners: bool = Field(default=True, description="Use Vulners API as fallback")
    vulners_api_key: Optional[str] = Field(None, description="Vulners API key")
    cache_results: bool = Field(default=True, description="Cache CVE data locally")
    cache_ttl: int = Field(default=86400, description="Cache TTL in seconds (default 24h)")
    min_cvss_score: float = Field(default=0.0, ge=0.0, le=10.0, description="Minimum CVSS score to enrich")


class MITREConfig(BaseModel):
    """MITRE ATT&CK mapping configuration."""
    enabled: bool = Field(default=True, description="Enable MITRE mapping")
    cve_to_cwe: bool = Field(default=True, description="Map CVEs to CWEs")
    cwe_to_capec: bool = Field(default=True, description="Map CWEs to CAPEC attack patterns")
    auto_update_db: bool = Field(default=True, description="Auto-update MITRE database")
    db_path: Optional[str] = Field(None, description="Custom database path")


class VulnScanRequest(BaseModel):
    """Vulnerability scanning request configuration."""
    targets: List[str] = Field(..., description="List of target URLs or domains")
    mode: ScanMode = Field(default=ScanMode.FULL, description="Scanning mode")
    
    # Tool configurations
    nuclei_config: NucleiConfig = Field(default_factory=NucleiConfig, description="Nuclei configuration")
    cve_enrichment: CVEEnrichmentConfig = Field(default_factory=CVEEnrichmentConfig, description="CVE enrichment config")
    mitre_mapping: MITREConfig = Field(default_factory=MITREConfig, description="MITRE mapping config")
    
    # Technology context (for CVE enrichment)
    detected_technologies: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Pre-detected technologies from recon phase"
    )
    
    # General settings
    timeout: int = Field(default=600, ge=10, le=7200, description="Overall scan timeout in seconds")
    parallel_execution: bool = Field(default=True, description="Run enrichment in parallel")
    max_workers: int = Field(default=10, ge=1, le=50, description="Maximum parallel workers")
    
    @field_validator("targets")
    @classmethod
    def validate_targets(cls, v: List[str]) -> List[str]:
        """Validate that targets list is not empty."""
        if not v:
            raise ValueError("Targets list cannot be empty")
        return v


class VulnScanStats(BaseModel):
    """Statistics from vulnerability scanning."""
    total_vulnerabilities: int = Field(default=0, description="Total vulnerabilities found")
    by_severity: Dict[str, int] = Field(default_factory=dict, description="Vulnerabilities by severity")
    by_category: Dict[str, int] = Field(default_factory=dict, description="Vulnerabilities by category")
    by_source: Dict[str, int] = Field(default_factory=dict, description="Vulnerabilities by discovery source")
    
    # Nuclei-specific stats
    nuclei_scanned: int = Field(default=0, description="Targets scanned by Nuclei")
    templates_executed: int = Field(default=0, description="Total templates executed")
    
    # CVE enrichment stats
    cves_enriched: int = Field(default=0, description="CVEs successfully enriched")
    cves_failed: int = Field(default=0, description="CVEs failed to enrich")
    
    # MITRE mapping stats
    cwes_mapped: int = Field(default=0, description="CWEs mapped")
    capecs_mapped: int = Field(default=0, description="CAPEC patterns mapped")
    
    # Performance metrics
    execution_time: float = Field(default=0.0, description="Total execution time in seconds")
    nuclei_time: float = Field(default=0.0, description="Nuclei scan time")
    enrichment_time: float = Field(default=0.0, description="CVE enrichment time")
    mitre_time: float = Field(default=0.0, description="MITRE mapping time")


class VulnScanResult(BaseModel):
    """Complete vulnerability scanning result."""
    request: VulnScanRequest = Field(..., description="Original request configuration")
    vulnerabilities: List[VulnerabilityInfo] = Field(default_factory=list, description="Discovered vulnerabilities")
    stats: VulnScanStats = Field(..., description="Scanning statistics")
    errors: List[str] = Field(default_factory=list, description="Errors encountered during scanning")
    warnings: List[str] = Field(default_factory=list, description="Warnings during scanning")
    success: bool = Field(default=True, description="Overall success status")
    scan_completed_at: datetime = Field(default_factory=datetime.utcnow, description="Scan completion timestamp")
