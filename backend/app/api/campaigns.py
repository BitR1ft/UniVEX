"""

Endpoints:
  POST   /api/campaigns                             — create campaign
  GET    /api/campaigns                             — list campaigns
  GET    /api/campaigns/{id}                        — get campaign detail
  PATCH  /api/campaigns/{id}                        — update campaign
  DELETE /api/campaigns/{id}                        — delete campaign
  POST   /api/campaigns/{id}/targets                — add target
  DELETE /api/campaigns/{id}/targets/{target_id}    — remove target
  POST   /api/campaigns/{id}/targets/import         — import targets (CSV/JSON/text)
  POST   /api/campaigns/{id}/start                  — start / run campaign
  POST   /api/campaigns/{id}/pause                  — pause running campaign
  POST   /api/campaigns/{id}/cancel                 — cancel campaign
  GET    /api/campaigns/{id}/summary                — campaign summary stats
  GET    /api/campaigns/{id}/aggregate              — aggregated findings report
  GET    /api/campaigns/{id}/correlations           — cross-target correlations
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel, Field

from app.campaigns.campaign_engine import (
    Campaign,
    CampaignConfig,
    CampaignEngine,
    CampaignFinding,
    CampaignStatus,
    CampaignTarget,
    FindingSeverity,
)
from app.campaigns.target_manager import TargetManager
from app.campaigns.aggregator import CampaignAggregator, CorrelationGroup

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/campaigns", tags=["Campaigns"])

# Singletons
_engine = CampaignEngine()
_aggregator = CampaignAggregator()


# ---------------------------------------------------------------------------
# Request / Response Schemas
# ---------------------------------------------------------------------------

class CampaignConfigRequest(BaseModel):
    max_concurrent_targets: int = Field(3, ge=1, le=20)
    scan_timeout_seconds: int = Field(3600, ge=60)
    retry_failed_targets: bool = True
    max_retries: int = Field(2, ge=0, le=5)
    enable_correlation: bool = True
    rate_limit_rps: float = Field(10.0, ge=0.1)
    tags: List[str] = Field(default_factory=list)
    scan_profile: str = Field("standard", pattern="^(quick|standard|thorough|stealth)$")


class CreateCampaignRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field("", max_length=2000)
    config: CampaignConfigRequest = Field(default_factory=CampaignConfigRequest)
    created_by: str = Field("system")


class UpdateCampaignRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)


class AddTargetRequest(BaseModel):
    host: str = Field(..., min_length=1)
    port: Optional[int] = Field(None, ge=1, le=65535)
    protocol: str = Field("https", pattern="^(http|https)$")
    scope_notes: str = ""
    tags: List[str] = Field(default_factory=list)


class ImportTargetsRequest(BaseModel):
    content: str = Field(..., description="CSV, JSON, or plain-text target list")
    format: Optional[str] = Field(None, description="'csv', 'json', or 'text'. Auto-detected if omitted.")
    scope_whitelist: List[str] = Field(default_factory=list)
    scope_blacklist: List[str] = Field(default_factory=list)


class TargetResponse(BaseModel):
    id: str
    host: str
    port: Optional[int]
    protocol: str
    status: str
    scope_notes: str
    tags: List[str]
    finding_count: int
    risk_score: float
    started_at: Optional[str]
    completed_at: Optional[str]
    error_message: Optional[str]

    @classmethod
    def from_target(cls, t: CampaignTarget) -> "TargetResponse":
        return cls(
            id=t.id,
            host=t.host,
            port=t.port,
            protocol=t.protocol,
            status=t.status.value,
            scope_notes=t.scope_notes,
            tags=t.tags,
            finding_count=t.finding_count,
            risk_score=t.risk_score,
            started_at=t.started_at.isoformat() if t.started_at else None,
            completed_at=t.completed_at.isoformat() if t.completed_at else None,
            error_message=t.error_message,
        )


class CampaignSummaryResponse(BaseModel):
    id: str
    name: str
    description: str
    status: str
    target_count: int
    completed_targets: int
    failed_targets: int
    progress_percent: float
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    risk_score: float
    risk_level: str
    created_at: str
    started_at: Optional[str]
    completed_at: Optional[str]
    created_by: str

    @classmethod
    def from_campaign(cls, c: Campaign) -> "CampaignSummaryResponse":
        return cls(
            id=c.id,
            name=c.name,
            description=c.description,
            status=c.status.value,
            target_count=c.target_count,
            completed_targets=c.completed_target_count,
            failed_targets=c.failed_target_count,
            progress_percent=c.progress_percent,
            total_findings=c.total_findings,
            critical_findings=c.critical_findings,
            high_findings=c.high_findings,
            medium_findings=c.medium_findings,
            low_findings=c.low_findings,
            info_findings=c.info_findings,
            risk_score=c.risk_score,
            risk_level=c.risk_level,
            created_at=c.created_at.isoformat(),
            started_at=c.started_at.isoformat() if c.started_at else None,
            completed_at=c.completed_at.isoformat() if c.completed_at else None,
            created_by=c.created_by,
        )


class CampaignDetailResponse(CampaignSummaryResponse):
    targets: List[TargetResponse]

    @classmethod
    def from_campaign(cls, c: Campaign) -> "CampaignDetailResponse":  # type: ignore[override]
        base = CampaignSummaryResponse.from_campaign(c).model_dump()
        return cls(**base, targets=[TargetResponse.from_target(t) for t in c.targets])


class FindingResponse(BaseModel):
    id: str
    target_id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    cve_id: Optional[str]
    cwe_id: Optional[str]
    owasp_category: Optional[str]
    affected_component: str
    remediation: str
    evidence: Optional[str]
    discovered_at: str

    @classmethod
    def from_finding(cls, f: CampaignFinding) -> "FindingResponse":
        return cls(
            id=f.id,
            target_id=f.target_id,
            title=f.title,
            description=f.description,
            severity=f.severity.value,
            cvss_score=f.cvss_score,
            cve_id=f.cve_id,
            cwe_id=f.cwe_id,
            owasp_category=f.owasp_category,
            affected_component=f.affected_component,
            remediation=f.remediation,
            evidence=f.evidence,
            discovered_at=f.discovered_at.isoformat(),
        )


class CorrelationGroupResponse(BaseModel):
    id: str
    fingerprint: str
    title: str
    severity: str
    cvss_score: float
    cve_id: Optional[str]
    owasp_category: Optional[str]
    affected_hosts: List[str]
    host_count: int
    finding_ids: List[str]
    first_seen: str
    last_seen: str
    remediation: str

    @classmethod
    def from_group(cls, g: CorrelationGroup) -> "CorrelationGroupResponse":
        return cls(
            id=g.id,
            fingerprint=g.fingerprint,
            title=g.title,
            severity=g.severity.value,
            cvss_score=g.cvss_score,
            cve_id=g.cve_id,
            owasp_category=g.owasp_category,
            affected_hosts=g.affected_hosts,
            host_count=g.host_count,
            finding_ids=g.finding_ids,
            first_seen=g.first_seen.isoformat(),
            last_seen=g.last_seen.isoformat(),
            remediation=g.remediation,
        )


class AggregateResponse(BaseModel):
    campaign_id: str
    campaign_name: str
    total_targets: int
    scanned_targets: int
    total_findings: int
    unique_findings: int
    duplicate_count: int
    deduplication_ratio: float
    severity_breakdown: Dict[str, int]
    owasp_coverage: Dict[str, int]
    risk_score: float
    risk_level: str
    highest_risk_target: Optional[str]
    most_common_severity: str
    generated_at: str
    correlation_groups: List[CorrelationGroupResponse]


class ImportResultResponse(BaseModel):
    success_count: int
    error_count: int
    duplicates_removed: int
    errors: List[str]
    added_to_campaign: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("", response_model=CampaignSummaryResponse, status_code=201)
async def create_campaign(body: CreateCampaignRequest) -> CampaignSummaryResponse:
    """Create a new pentest campaign."""
    config = CampaignConfig(
        max_concurrent_targets=body.config.max_concurrent_targets,
        scan_timeout_seconds=body.config.scan_timeout_seconds,
        retry_failed_targets=body.config.retry_failed_targets,
        max_retries=body.config.max_retries,
        enable_correlation=body.config.enable_correlation,
        rate_limit_rps=body.config.rate_limit_rps,
        tags=body.config.tags,
        scan_profile=body.config.scan_profile,
    )
    campaign = _engine.create_campaign(
        name=body.name,
        description=body.description,
        config=config,
        created_by=body.created_by,
    )
    return CampaignSummaryResponse.from_campaign(campaign)


@router.get("", response_model=List[CampaignSummaryResponse])
async def list_campaigns(
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> List[CampaignSummaryResponse]:
    """List all campaigns, optionally filtered by status."""
    status_filter: Optional[CampaignStatus] = None
    if status:
        try:
            status_filter = CampaignStatus(status)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status!r}")

    campaigns = _engine.list_campaigns(status=status_filter)
    return [CampaignSummaryResponse.from_campaign(c) for c in campaigns[offset: offset + limit]]


@router.get("/{campaign_id}", response_model=CampaignDetailResponse)
async def get_campaign(campaign_id: str) -> CampaignDetailResponse:
    """Get full campaign details including targets."""
    campaign = _engine.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return CampaignDetailResponse.from_campaign(campaign)


@router.patch("/{campaign_id}", response_model=CampaignSummaryResponse)
async def update_campaign(campaign_id: str, body: UpdateCampaignRequest) -> CampaignSummaryResponse:
    """Update campaign name or description."""
    update_data = {k: v for k, v in body.model_dump().items() if v is not None}
    campaign = _engine.update_campaign(campaign_id, **update_data)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return CampaignSummaryResponse.from_campaign(campaign)


@router.delete("/{campaign_id}", status_code=204, response_model=None)
async def delete_campaign(campaign_id: str) -> None:
    """Delete a campaign and all its data."""
    if not _engine.delete_campaign(campaign_id):
        raise HTTPException(status_code=404, detail="Campaign not found")


# ------------------------------------------------------------------
# Target management
# ------------------------------------------------------------------

@router.post("/{campaign_id}/targets", response_model=TargetResponse, status_code=201)
async def add_target(campaign_id: str, body: AddTargetRequest) -> TargetResponse:
    """Add a single target to a campaign."""
    _require_campaign(campaign_id)
    target = _engine.add_target(
        campaign_id=campaign_id,
        host=body.host,
        port=body.port,
        protocol=body.protocol,
        scope_notes=body.scope_notes,
        tags=body.tags,
    )
    if not target:
        raise HTTPException(status_code=500, detail="Failed to add target")
    return TargetResponse.from_target(target)


@router.delete("/{campaign_id}/targets/{target_id}", status_code=204, response_model=None)
async def remove_target(campaign_id: str, target_id: str) -> None:
    """Remove a target from a campaign."""
    _require_campaign(campaign_id)
    if not _engine.remove_target(campaign_id, target_id):
        raise HTTPException(status_code=404, detail="Target not found")


@router.post("/{campaign_id}/targets/import", response_model=ImportResultResponse)
async def import_targets(campaign_id: str, body: ImportTargetsRequest) -> ImportResultResponse:
    """
    Bulk import targets from CSV, JSON array, or plain text (one host per line).
    Supports CIDR expansion, scope validation, and duplicate removal.
    """
    _require_campaign(campaign_id)

    tm = TargetManager(
        scope_whitelist=body.scope_whitelist or None,
        scope_blacklist=body.scope_blacklist or None,
    )
    result = tm.import_auto(body.content, fmt=body.format)

    # Add parsed targets to campaign
    added = _engine.add_targets_bulk(
        campaign_id=campaign_id,
        targets=[
            {
                "host": t.host,
                "port": t.port,
                "protocol": t.protocol,
                "scope_notes": t.scope_notes,
                "tags": t.tags,
            }
            for t in result.parsed
        ],
    )

    logger.info(
        "Target import: campaign=%s added=%d errors=%d duplicates=%d",
        campaign_id, added, result.error_count, result.duplicates_removed,
    )
    return ImportResultResponse(
        success_count=result.success_count,
        error_count=result.error_count,
        duplicates_removed=result.duplicates_removed,
        errors=result.errors,
        added_to_campaign=added,
    )


# ------------------------------------------------------------------
# Campaign control
# ------------------------------------------------------------------

@router.post("/{campaign_id}/start", response_model=CampaignSummaryResponse)
async def start_campaign(
    campaign_id: str,
    background_tasks: BackgroundTasks,
) -> CampaignSummaryResponse:
    """Start a campaign scan in the background."""
    campaign = _require_campaign(campaign_id)

    if campaign.status == CampaignStatus.RUNNING:
        raise HTTPException(status_code=409, detail="Campaign is already running")
    if campaign.status == CampaignStatus.COMPLETED:
        raise HTTPException(status_code=409, detail="Campaign has already completed")

    async def _run() -> None:
        try:
            await _engine.run_campaign(campaign_id)
        except Exception as exc:
            logger.error("Background campaign run failed: %s — %s", campaign_id, exc)

    background_tasks.add_task(_run)
    # Update status to running immediately so the response reflects it
    campaign.status = CampaignStatus.RUNNING
    return CampaignSummaryResponse.from_campaign(campaign)


@router.post("/{campaign_id}/pause", response_model=CampaignSummaryResponse)
async def pause_campaign(campaign_id: str) -> CampaignSummaryResponse:
    """Pause a running campaign."""
    campaign = _require_campaign(campaign_id)
    if not _engine.pause_campaign(campaign_id):
        raise HTTPException(
            status_code=409,
            detail=f"Campaign cannot be paused from status {campaign.status.value!r}",
        )
    return CampaignSummaryResponse.from_campaign(campaign)


@router.post("/{campaign_id}/cancel", response_model=CampaignSummaryResponse)
async def cancel_campaign(campaign_id: str) -> CampaignSummaryResponse:
    """Cancel a campaign."""
    campaign = _require_campaign(campaign_id)
    if not _engine.cancel_campaign(campaign_id):
        raise HTTPException(
            status_code=409,
            detail=f"Campaign cannot be cancelled from status {campaign.status.value!r}",
        )
    return CampaignSummaryResponse.from_campaign(campaign)


# ------------------------------------------------------------------
# Reporting
# ------------------------------------------------------------------

@router.get("/{campaign_id}/summary", response_model=Dict[str, Any])
async def campaign_summary(campaign_id: str) -> Dict[str, Any]:
    """Get high-level summary stats for a campaign."""
    summary = _engine.get_campaign_summary(campaign_id)
    if not summary:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return summary


@router.get("/{campaign_id}/aggregate", response_model=AggregateResponse)
async def aggregate_campaign(campaign_id: str) -> AggregateResponse:
    """
    Produce a full aggregated findings report with cross-target deduplication,
    OWASP coverage, and risk scoring.
    """
    campaign = _require_campaign(campaign_id)
    report = _aggregator.aggregate(campaign)
    return AggregateResponse(
        campaign_id=report.campaign_id,
        campaign_name=report.campaign_name,
        total_targets=report.total_targets,
        scanned_targets=report.scanned_targets,
        total_findings=report.total_findings,
        unique_findings=report.unique_findings,
        duplicate_count=report.duplicate_count,
        deduplication_ratio=report.deduplication_ratio,
        severity_breakdown=report.severity_breakdown,
        owasp_coverage=report.owasp_coverage,
        risk_score=report.risk_score,
        risk_level=report.risk_level,
        highest_risk_target=report.highest_risk_target,
        most_common_severity=report.most_common_severity,
        generated_at=report.generated_at.isoformat(),
        correlation_groups=[
            CorrelationGroupResponse.from_group(g) for g in report.correlation_groups
        ],
    )


@router.get("/{campaign_id}/correlations", response_model=List[CorrelationGroupResponse])
async def get_correlations(
    campaign_id: str,
    min_hosts: int = Query(2, ge=2, description="Minimum number of affected hosts"),
) -> List[CorrelationGroupResponse]:
    """
    Return cross-target vulnerability correlations — findings that appear on
    2 or more targets.
    """
    campaign = _require_campaign(campaign_id)
    groups = _aggregator.correlate(campaign)
    return [
        CorrelationGroupResponse.from_group(g)
        for g in groups
        if g.host_count >= min_hosts
    ]


@router.get("/{campaign_id}/targets/{target_id}/findings", response_model=List[FindingResponse])
async def get_target_findings(
    campaign_id: str,
    target_id: str,
    severity: Optional[str] = Query(None),
) -> List[FindingResponse]:
    """Get all findings for a specific target within a campaign."""
    _require_campaign(campaign_id)
    target = _engine.get_target(campaign_id, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    findings = list(target.findings)
    if severity:
        try:
            sev = FindingSeverity(severity)
            findings = [f for f in findings if f.severity == sev]
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid severity: {severity!r}")

    return [FindingResponse.from_finding(f) for f in findings]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_campaign(campaign_id: str) -> Campaign:
    campaign = _engine.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign
