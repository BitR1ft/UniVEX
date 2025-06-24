"""
GraphQL Types — Strawberry type definitions that mirror core REST models.

Types: Project, Scan, Finding, Campaign, Report, Agent, Tool, User
"""

from __future__ import annotations

import strawberry
from typing import List, Optional
from datetime import datetime
from enum import Enum


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

@strawberry.enum
class ProjectStatus(Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    ARCHIVED = "archived"
    PAUSED = "paused"


@strawberry.enum
class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@strawberry.enum
class FindingSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@strawberry.enum
class FindingStatus(Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    WONT_FIX = "wont_fix"
    FALSE_POSITIVE = "false_positive"


@strawberry.enum
class CampaignStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


@strawberry.enum
class ReportFormat(Enum):
    PDF = "pdf"
    HTML = "html"
    MARKDOWN = "markdown"
    JSON = "json"


@strawberry.enum
class AgentRole(Enum):
    PLANNER = "planner"
    RECON = "recon"
    EXPLOIT = "exploit"
    WEBAPP = "webapp"
    REPORT = "report"
    REFINER = "refiner"
    GENERATOR = "generator"
    ADVISER = "adviser"
    REFLECTOR = "reflector"
    ENRICHER = "enricher"
    CODER = "coder"
    INSTALLER = "installer"
    SIMPLE_JSON = "simple_json"


@strawberry.enum
class UserRole(Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


# ---------------------------------------------------------------------------
# Core Types
# ---------------------------------------------------------------------------

@strawberry.type
class User:
    id: str
    username: str
    email: str
    full_name: Optional[str]
    role: UserRole
    is_active: bool
    created_at: datetime


@strawberry.type
class Project:
    id: str
    name: str
    description: Optional[str]
    target: str
    project_type: str
    status: ProjectStatus
    created_at: datetime
    updated_at: datetime
    user_id: str
    enable_subdomain_enum: bool = False
    enable_port_scan: bool = False
    enable_web_crawl: bool = False
    enable_tech_detection: bool = False
    enable_vuln_scan: bool = False
    enable_nuclei: bool = False
    enable_auto_exploit: bool = False


@strawberry.type
class Scan:
    id: str
    project_id: str
    scan_type: str
    status: ScanStatus
    target: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    findings_count: int = 0
    error_message: Optional[str] = None
    metadata: Optional[strawberry.scalars.JSON] = None


@strawberry.type
class Evidence:
    id: str
    type: str
    content: str
    filename: Optional[str] = None
    created_at: Optional[datetime] = None


@strawberry.type
class Finding:
    id: str
    title: str
    severity: FindingSeverity
    status: FindingStatus
    description: str
    source: str
    cve_id: Optional[str]
    cwe_id: Optional[str]
    owasp_category: Optional[str]
    cvss_score: float
    cvss_vector: Optional[str]
    affected_component: str
    affected_url: Optional[str]
    affected_parameter: Optional[str]
    affected_method: str
    project_id: Optional[str]
    campaign_id: Optional[str]
    scan_id: Optional[str]
    remediation: str
    remediation_effort: str
    references: List[str]
    tool_name: Optional[str]
    tags: List[str]
    created_at: datetime
    updated_at: datetime
    evidence: List[Evidence] = strawberry.field(default_factory=list)


@strawberry.type
class CampaignTarget:
    id: str
    target: str
    status: str
    findings_count: int = 0


@strawberry.type
class Campaign:
    id: str
    name: str
    description: Optional[str]
    status: CampaignStatus
    targets: List[CampaignTarget]
    total_findings: int = 0
    created_at: datetime
    updated_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


@strawberry.type
class Report:
    id: str
    project_id: Optional[str]
    campaign_id: Optional[str]
    format: ReportFormat
    title: str
    created_at: datetime
    download_url: Optional[str] = None
    findings_count: int = 0


@strawberry.type
class AgentExecution:
    id: str
    role: AgentRole
    status: str
    target: Optional[str]
    phase: Optional[str]
    created_at: datetime
    completed_at: Optional[datetime] = None
    result_summary: Optional[str] = None
    tool_calls_count: int = 0
    tokens_used: int = 0


@strawberry.type
class ToolInfo:
    name: str
    description: str
    phase: str
    enabled: bool = True
    parameters: Optional[strawberry.scalars.JSON] = None


# ---------------------------------------------------------------------------
# Connection / Pagination Types
# ---------------------------------------------------------------------------

@strawberry.type
class PageInfo:
    total: int
    page: int
    page_size: int
    has_next: bool
    has_prev: bool


@strawberry.type
class ProjectConnection:
    items: List[Project]
    page_info: PageInfo


@strawberry.type
class ScanConnection:
    items: List[Scan]
    page_info: PageInfo


@strawberry.type
class FindingConnection:
    items: List[Finding]
    page_info: PageInfo


@strawberry.type
class CampaignConnection:
    items: List[Campaign]
    page_info: PageInfo


@strawberry.type
class ReportConnection:
    items: List[Report]
    page_info: PageInfo


# ---------------------------------------------------------------------------
# Mutation Input Types
# ---------------------------------------------------------------------------

@strawberry.input
class CreateProjectInput:
    name: str
    target: str
    description: Optional[str] = None
    project_type: str = "web"
    enable_subdomain_enum: bool = False
    enable_port_scan: bool = False
    enable_web_crawl: bool = False
    enable_tech_detection: bool = False
    enable_vuln_scan: bool = False
    enable_nuclei: bool = False
    enable_auto_exploit: bool = False


@strawberry.input
class UpdateProjectInput:
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[ProjectStatus] = None
    enable_subdomain_enum: Optional[bool] = None
    enable_port_scan: Optional[bool] = None
    enable_web_crawl: Optional[bool] = None
    enable_tech_detection: Optional[bool] = None
    enable_vuln_scan: Optional[bool] = None
    enable_nuclei: Optional[bool] = None
    enable_auto_exploit: Optional[bool] = None


@strawberry.input
class CreateScanInput:
    project_id: str
    scan_type: str
    target: str


@strawberry.input
class CreateFindingInput:
    title: str
    severity: FindingSeverity = FindingSeverity.INFO
    description: str = ""
    source: str = "manual"
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    cvss_score: float = 0.0
    cvss_vector: Optional[str] = None
    affected_component: str = ""
    affected_url: Optional[str] = None
    affected_parameter: Optional[str] = None
    affected_method: str = "GET"
    project_id: Optional[str] = None
    campaign_id: Optional[str] = None
    scan_id: Optional[str] = None
    remediation: str = ""
    remediation_effort: str = "medium"
    references: List[str] = strawberry.field(default_factory=list)
    tool_name: Optional[str] = None
    tags: List[str] = strawberry.field(default_factory=list)


@strawberry.input
class UpdateFindingInput:
    title: Optional[str] = None
    severity: Optional[FindingSeverity] = None
    status: Optional[FindingStatus] = None
    description: Optional[str] = None
    remediation: Optional[str] = None
    cvss_score: Optional[float] = None
    tags: Optional[List[str]] = None


@strawberry.input
class CreateCampaignInput:
    name: str
    description: Optional[str] = None
    targets: List[str] = strawberry.field(default_factory=list)


@strawberry.input
class GenerateReportInput:
    project_id: Optional[str] = None
    campaign_id: Optional[str] = None
    format: ReportFormat = ReportFormat.PDF
    title: Optional[str] = None
    include_evidence: bool = True


# ---------------------------------------------------------------------------
# Subscription Payload Types
# ---------------------------------------------------------------------------

@strawberry.type
class ScanStatusEvent:
    scan_id: str
    project_id: str
    status: ScanStatus
    message: Optional[str] = None
    timestamp: datetime = strawberry.field(default_factory=datetime.utcnow)


@strawberry.type
class FindingDiscoveredEvent:
    finding_id: str
    project_id: Optional[str]
    scan_id: Optional[str]
    title: str
    severity: FindingSeverity
    timestamp: datetime = strawberry.field(default_factory=datetime.utcnow)


@strawberry.type
class AgentProgressEvent:
    agent_role: AgentRole
    phase: str
    message: str
    progress_pct: float = 0.0
    timestamp: datetime = strawberry.field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Result / Error union types
# ---------------------------------------------------------------------------

@strawberry.type
class OperationError:
    message: str
    code: str = "OPERATION_ERROR"
    field: Optional[str] = None


@strawberry.type
class ProjectResult:
    project: Optional[Project] = None
    error: Optional[OperationError] = None
    success: bool = True


@strawberry.type
class FindingResult:
    finding: Optional[Finding] = None
    error: Optional[OperationError] = None
    success: bool = True


@strawberry.type
class ScanResult:
    scan: Optional[Scan] = None
    error: Optional[OperationError] = None
    success: bool = True


@strawberry.type
class CampaignResult:
    campaign: Optional[Campaign] = None
    error: Optional[OperationError] = None
    success: bool = True


@strawberry.type
class ReportResult:
    report: Optional[Report] = None
    error: Optional[OperationError] = None
    success: bool = True


@strawberry.type
class DeleteResult:
    id: str
    success: bool
    error: Optional[OperationError] = None
