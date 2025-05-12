"""

Endpoints:
  POST   /api/findings                          — create finding
  GET    /api/findings                          — list / search findings
  GET    /api/findings/{id}                     — get finding detail
  PATCH  /api/findings/{id}                     — update finding fields
  DELETE /api/findings/{id}                     — delete finding
  PATCH  /api/findings/{id}/triage              — triage workflow (status/assign/annotate/severity)
  POST   /api/findings/{id}/evidence            — attach evidence
  DELETE /api/findings/{id}/evidence/{ev_id}    — remove evidence
  POST   /api/findings/bulk-import              — bulk import from JSON list
  GET    /api/findings/stats                    — aggregate statistics
  POST   /api/findings/deduplicate              — run deduplication on current store
  POST   /api/findings/{id}/cvss               — calculate / update CVSS score
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from app.api.auth import get_current_user_id
from app.core.rbac import Permission, require_permission
from app.findings.finding_manager import (
    EvidenceType,
    FindingManager,
    FindingSeverity,
    FindingSource,
    FindingStatus,
)
from app.findings.deduplicator import Deduplicator
from app.findings.severity_calculator import (
    AV, AC, PR, UI, S, C, I, A, E, RL, RC, CR, IR, AR,
    CVSSVector,
    SeverityCalculator,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/findings", tags=["Findings"])

# ---------------------------------------------------------------------------
# Singletons
# ---------------------------------------------------------------------------

_manager = FindingManager()
_deduplicator = Deduplicator()
_cvss_calc = SeverityCalculator()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class CreateFindingRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=512)
    severity: str = Field("info")
    description: str = Field("", max_length=8192)
    source: str = Field("manual")
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    cvss_score: float = Field(0.0, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    affected_component: str = Field("")
    affected_url: Optional[str] = None
    affected_parameter: Optional[str] = None
    affected_method: str = Field("GET")
    project_id: Optional[str] = None
    campaign_id: Optional[str] = None
    target_id: Optional[str] = None
    scan_id: Optional[str] = None
    remediation: str = Field("")
    remediation_effort: str = Field("medium")
    references: List[str] = Field(default_factory=list)
    tool_name: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    raw_output: Optional[str] = None

    @field_validator("severity")
    @classmethod
    def _validate_severity(cls, v: str) -> str:
        allowed = {s.value for s in FindingSeverity}
        if v.lower() not in allowed:
            raise ValueError(f"severity must be one of {allowed}")
        return v.lower()

    @field_validator("source")
    @classmethod
    def _validate_source(cls, v: str) -> str:
        allowed = {s.value for s in FindingSource}
        if v.lower() not in allowed:
            raise ValueError(f"source must be one of {allowed}")
        return v.lower()


class UpdateFindingRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    owasp_category: Optional[str] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    affected_component: Optional[str] = None
    affected_url: Optional[str] = None
    affected_parameter: Optional[str] = None
    affected_method: Optional[str] = None
    remediation: Optional[str] = None
    remediation_effort: Optional[str] = None
    references: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    raw_output: Optional[str] = None


class TriageRequest(BaseModel):
    action: str = Field(..., description="status_change | severity_override | assign | annotate | false_positive | duplicate")
    value: str = Field(..., description="New status / severity / assignee / note / reason / original_id")
    actor: str = Field("analyst")
    note: str = Field("")


class EvidenceRequest(BaseModel):
    type: str = Field("description")
    title: str = Field("", max_length=256)
    content: str = Field(..., max_length=1_048_576)   # 1 MB limit
    mime_type: str = Field("text/plain")
    tool_name: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class BulkImportRequest(BaseModel):
    findings: List[Dict[str, Any]] = Field(..., min_length=1)


class CVSSRequest(BaseModel):
    attack_vector: str = Field("N")
    attack_complexity: str = Field("L")
    privileges_required: str = Field("N")
    user_interaction: str = Field("N")
    scope: str = Field("U")
    confidentiality: str = Field("N")
    integrity: str = Field("N")
    availability: str = Field("N")
    # Temporal
    exploit_code_maturity: str = Field("X")
    remediation_level: str = Field("X")
    report_confidence: str = Field("X")
    # Environmental
    confidentiality_requirement: str = Field("X")
    integrity_requirement: str = Field("X")
    availability_requirement: str = Field("X")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding_or_404(finding_id: str):
    f = _manager.get(finding_id)
    if f is None:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")
    return f


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("", status_code=201)
async def create_finding(
    req: CreateFindingRequest,
    current_user_id: str = Depends(get_current_user_id),
    _rbac: None = Depends(require_permission(Permission.SCAN_WRITE)),
) -> Dict[str, Any]:
    """Create a new finding. Requires SCAN_WRITE permission."""
    f = _manager.create(
        title=req.title,
        severity=FindingSeverity(req.severity),
        description=req.description,
        source=FindingSource(req.source),
        cve_id=req.cve_id,
        cwe_id=req.cwe_id,
        owasp_category=req.owasp_category,
        cvss_score=req.cvss_score,
        cvss_vector=req.cvss_vector,
        affected_component=req.affected_component,
        affected_url=req.affected_url,
        affected_parameter=req.affected_parameter,
        affected_method=req.affected_method,
        project_id=req.project_id,
        campaign_id=req.campaign_id,
        target_id=req.target_id,
        scan_id=req.scan_id,
        remediation=req.remediation,
        remediation_effort=req.remediation_effort,
        references=req.references,
        tool_name=req.tool_name,
        tags=req.tags,
        raw_output=req.raw_output,
    )
    return f.to_dict()


@router.get("")
async def list_findings(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    project_id: Optional[str] = Query(None),
    campaign_id: Optional[str] = Query(None),
    target_id: Optional[str] = Query(None),
    owasp_category: Optional[str] = Query(None),
    assigned_to: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    include_duplicates: bool = Query(False),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    """List and filter findings. Requires authentication."""
    try:
        status_enum = FindingStatus(status) if status else None
        severity_enum = FindingSeverity(severity) if severity else None
        source_enum = FindingSource(source) if source else None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    findings = _manager.list(
        status=status_enum,
        severity=severity_enum,
        source=source_enum,
        project_id=project_id,
        campaign_id=campaign_id,
        target_id=target_id,
        owasp_category=owasp_category,
        assigned_to=assigned_to,
        search=search,
        include_duplicates=include_duplicates,
        limit=limit,
        offset=offset,
    )
    return {
        "findings": [f.to_dict() for f in findings],
        "count": len(findings),
        "limit": limit,
        "offset": offset,
    }


@router.get("/stats")
async def get_stats(
    campaign_id: Optional[str] = Query(None),
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    """Get aggregate finding statistics. Requires authentication."""
    return _manager.stats(campaign_id=campaign_id)


@router.post("/deduplicate")
async def run_deduplication(
    campaign_id: Optional[str] = Query(None),
    fuzzy_threshold: float = Query(0.75, ge=0.0, le=1.0),
    apply: bool = Query(False, description="If true, mark duplicates in store"),
    current_user_id: str = Depends(get_current_user_id),
    _rbac: None = Depends(require_permission(Permission.SCAN_WRITE)),
) -> Dict[str, Any]:
    """Run deduplication on findings and optionally apply results. Requires SCAN_WRITE."""
    findings = _manager.list(
        campaign_id=campaign_id, limit=10_000, include_duplicates=False
    )
    deduplicator = Deduplicator(fuzzy_threshold=fuzzy_threshold)
    result = deduplicator.run(findings)

    if apply:
        for group in result.groups:
            for dup_id in group.duplicate_ids:
                try:
                    _manager.mark_duplicate(dup_id, group.canonical_id, actor="deduplicator")
                except KeyError:
                    pass

    return result.to_dict()


@router.post("/bulk-import", status_code=201)
async def bulk_import(
    req: BulkImportRequest,
    current_user_id: str = Depends(get_current_user_id),
    _rbac: None = Depends(require_permission(Permission.SCAN_WRITE)),
) -> Dict[str, Any]:
    """Bulk-import findings from a JSON list. Requires SCAN_WRITE permission."""
    created = _manager.bulk_import(req.findings)
    return {"imported": len(created), "finding_ids": [f.id for f in created]}


@router.get("/{finding_id}")
async def get_finding(
    finding_id: str,
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    """Get a specific finding by ID. Requires authentication."""
    return _finding_or_404(finding_id).to_dict()


@router.patch("/{finding_id}")
async def update_finding(
    finding_id: str,
    req: UpdateFindingRequest,
    current_user_id: str = Depends(get_current_user_id),
    _rbac: None = Depends(require_permission(Permission.SCAN_WRITE)),
) -> Dict[str, Any]:
    """Update finding fields. Requires SCAN_WRITE permission."""
    _finding_or_404(finding_id)
    updates = {k: v for k, v in req.model_dump(exclude_none=True).items()}
    if "severity" in updates:
        updates["severity"] = FindingSeverity(updates["severity"])
    f = _manager.update(finding_id, **updates)
    return f.to_dict()


@router.delete("/{finding_id}", status_code=204, response_model=None)
async def delete_finding(
    finding_id: str,
    current_user_id: str = Depends(get_current_user_id),
    _rbac: None = Depends(require_permission(Permission.SCAN_WRITE)),
) -> None:
    """Delete a finding. Requires SCAN_WRITE permission."""
    if not _manager.delete(finding_id):
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")


@router.patch("/{finding_id}/triage")
async def triage_finding(
    finding_id: str,
    req: TriageRequest,
    current_user_id: str = Depends(get_current_user_id),
    _rbac: None = Depends(require_permission(Permission.SCAN_WRITE)),
) -> Dict[str, Any]:
    """
    Triage a finding. Requires SCAN_WRITE permission.

    Supported actions:
      - ``status_change`` — value = new status (open/confirmed/in_progress/resolved/…)
      - ``severity_override`` — value = new severity
      - ``assign`` — value = assignee username
      - ``annotate`` — value = note text
      - ``false_positive`` — value = reason
      - ``duplicate`` — value = canonical finding ID
    """
    _finding_or_404(finding_id)
    action = req.action.lower()
    try:
        if action == "status_change":
            f = _manager.change_status(finding_id, FindingStatus(req.value), req.actor, req.note)
        elif action == "severity_override":
            f = _manager.override_severity(finding_id, FindingSeverity(req.value), req.actor, req.note)
        elif action == "assign":
            f = _manager.assign(finding_id, req.value, req.actor, req.note)
        elif action == "annotate":
            f = _manager.annotate(finding_id, req.value, req.actor)
        elif action == "false_positive":
            f = _manager.mark_false_positive(finding_id, req.value, req.actor)
        elif action == "duplicate":
            f = _manager.mark_duplicate(finding_id, req.value, req.actor)
        else:
            raise HTTPException(status_code=422, detail=f"Unknown triage action: {action}")
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return f.to_dict()


@router.post("/{finding_id}/evidence", status_code=201)
async def attach_evidence(
    finding_id: str,
    req: EvidenceRequest,
    current_user_id: str = Depends(get_current_user_id),
    _rbac: None = Depends(require_permission(Permission.SCAN_WRITE)),
) -> Dict[str, Any]:
    """Attach evidence to a finding. Requires SCAN_WRITE permission."""
    _finding_or_404(finding_id)
    try:
        ev_type = EvidenceType(req.type)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"Unknown evidence type: {req.type}")
    ev = _manager.attach_evidence(
        finding_id=finding_id,
        evidence_type=ev_type,
        title=req.title,
        content=req.content,
        mime_type=req.mime_type,
        tool_name=req.tool_name,
        metadata=req.metadata,
    )
    return ev.to_dict()


@router.delete("/{finding_id}/evidence/{evidence_id}", status_code=204, response_model=None)
async def remove_evidence(
    finding_id: str,
    evidence_id: str,
    current_user_id: str = Depends(get_current_user_id),
    _rbac: None = Depends(require_permission(Permission.SCAN_WRITE)),
) -> None:
    """Remove a piece of evidence from a finding. Requires SCAN_WRITE permission."""
    _finding_or_404(finding_id)
    if not _manager.remove_evidence(finding_id, evidence_id):
        raise HTTPException(status_code=404, detail=f"Evidence {evidence_id} not found")


@router.post("/{finding_id}/cvss")
async def calculate_cvss(
    finding_id: str,
    req: CVSSRequest,
    current_user_id: str = Depends(get_current_user_id),
    _rbac: None = Depends(require_permission(Permission.SCAN_WRITE)),
) -> Dict[str, Any]:
    """Calculate CVSS v3.1 score and update the finding. Requires SCAN_WRITE permission."""
    _finding_or_404(finding_id)
    try:
        vector = CVSSVector(
            attack_vector=AV(req.attack_vector),
            attack_complexity=AC(req.attack_complexity),
            privileges_required=PR(req.privileges_required),
            user_interaction=UI(req.user_interaction),
            scope=S(req.scope),
            confidentiality=C(req.confidentiality),
            integrity=I(req.integrity),
            availability=A(req.availability),
            exploit_code_maturity=E(req.exploit_code_maturity),
            remediation_level=RL(req.remediation_level),
            report_confidence=RC(req.report_confidence),
            confidentiality_requirement=CR(req.confidentiality_requirement),
            integrity_requirement=IR(req.integrity_requirement),
            availability_requirement=AR(req.availability_requirement),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    score = _cvss_calc.calculate(vector)
    _manager.update(
        finding_id,
        cvss_score=score.overall_score,
        cvss_vector=score.vector_string,
    )
    return {**score.to_dict(), "finding_id": finding_id}
