"""
Canonical Schemas for Recon Tool Outputs

Provides a single, normalised representation for data produced by every
external reconnaissance tool.  All tool orchestrators must map their raw
output to these types before returning results to callers.

Schema hierarchy
----------------
    ReconResult             ← top-level envelope returned by every tool
      ├── target            ← what was scanned
      ├── tool_name         ← which tool produced this
      ├── Endpoint[]        ← discovered endpoints / URLs
      ├── Technology[]      ← detected technology stack entries
      └── Finding[]         ← vulnerability / weakness findings
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Normalised severity levels used across all tool outputs."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class EndpointMethod(str, Enum):
    """HTTP method associated with a discovered endpoint."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# Endpoint schema
# ---------------------------------------------------------------------------

class Endpoint(BaseModel):
    """
    A discovered HTTP endpoint or URL.

    Populated by tools such as Katana, GAU, Kiterunner, httpx.
    """

    url: str = Field(..., description="Full URL, e.g. https://api.example.com/v1/users")
    path: Optional[str] = Field(None, description="Path component of the URL")
    method: EndpointMethod = Field(
        EndpointMethod.UNKNOWN, description="HTTP method"
    )
    status_code: Optional[int] = Field(None, ge=100, le=599)
    content_type: Optional[str] = None
    content_length: Optional[int] = Field(None, ge=0)
    title: Optional[str] = Field(None, description="HTML page title")
    redirect_url: Optional[str] = None
    is_live: bool = True
    parameters: List[str] = Field(
        default_factory=list,
        description="Detected query / body parameters",
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Arbitrary classifier tags, e.g. ['api', 'login']",
    )
    discovered_by: Optional[str] = Field(None, description="Name of the tool that found this")
    confidence: float = Field(
        1.0, ge=0.0, le=1.0, description="Detection confidence (0–1)"
    )
    extra: Dict[str, Any] = Field(
        default_factory=dict,
        description="Tool-specific extra fields not covered by the schema",
    )


# ---------------------------------------------------------------------------
# Technology schema
# ---------------------------------------------------------------------------

class Technology(BaseModel):
    """
    A technology stack entry detected on a target.

    Populated by tools such as Wappalyzer, httpx, and header analysis.
    """

    name: str = Field(..., description="Technology name, e.g. 'nginx', 'React'")
    version: Optional[str] = Field(None, description="Detected version string")
    category: Optional[str] = Field(
        None, description="Category, e.g. 'Web Server', 'JavaScript Framework'"
    )
    url: Optional[str] = Field(None, description="URL where this technology was observed")
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    cpe: Optional[str] = Field(
        None, description="Common Platform Enumeration string, e.g. cpe:/a:nginx:nginx:1.24"
    )
    extra: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Finding schema
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """
    A vulnerability, weakness, or security-relevant observation.

    Populated by tools such as Nuclei, Nikto, and custom checks.
    """

    id: str = Field(..., description="Unique finding identifier (tool template ID or UUID)")
    name: str = Field(..., description="Short finding title")
    description: Optional[str] = None
    severity: Severity = Severity.UNKNOWN
    url: Optional[str] = Field(None, description="Affected URL or asset")
    cve_ids: List[str] = Field(
        default_factory=list, description="Associated CVE identifiers"
    )
    cwe_ids: List[str] = Field(
        default_factory=list, description="Associated CWE identifiers"
    )
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list, description="Reference URLs")
    evidence: Optional[str] = Field(
        None, description="Request/response snippet or other proof"
    )
    discovered_by: Optional[str] = Field(None, description="Tool that produced this finding")
    tags: List[str] = Field(default_factory=list)
    extra: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Top-level ReconResult envelope
# ---------------------------------------------------------------------------

class ReconResult(BaseModel):
    """
    Normalised envelope returned by every recon tool orchestrator.

    A single scan may produce multiple ``Endpoint``, ``Technology``, and
    ``Finding`` objects.  Tools that do not produce a particular type should
    return empty lists for the corresponding fields.
    """

    tool_name: str = Field(..., description="Canonical name of the tool, e.g. 'nuclei'")
    target: str = Field(..., description="Scan target (domain, IP, URL, or CIDR)")
    project_id: Optional[str] = None
    task_id: Optional[str] = None

    # Core result collections
    endpoints: List[Endpoint] = Field(default_factory=list)
    technologies: List[Technology] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)

    # Execution metadata
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = Field(None, ge=0.0)
    success: bool = True
    error_message: Optional[str] = None

    # Counts (auto-computed, useful for quick summaries)
    @property
    def endpoint_count(self) -> int:
        return len(self.endpoints)

    @property
    def technology_count(self) -> int:
        return len(self.technologies)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def summary(self) -> Dict[str, Any]:
        """Return a human-readable summary dict."""
        return {
            "tool": self.tool_name,
            "target": self.target,
            "endpoints": self.endpoint_count,
            "technologies": self.technology_count,
            "findings": self.finding_count,
            "critical": self.critical_count,
            "high": self.high_count,
            "success": self.success,
            "duration_seconds": self.duration_seconds,
        }
