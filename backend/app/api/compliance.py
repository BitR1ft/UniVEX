"""

Endpoints:
  GET  /api/compliance/frameworks               — list available frameworks
  POST /api/compliance/map                      — map findings to a framework
  POST /api/compliance/gaps                     — get gap analysis
  POST /api/compliance/map-all                  — map findings to all frameworks
  GET  /api/compliance/controls/{framework}     — list controls for a framework
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.auth import get_current_user_id
from ..compliance.mapper import ComplianceMapper, Finding
from ..compliance.frameworks.owasp_top10 import OWASP_TOP10_CONTROLS
from ..compliance.frameworks.pci_dss import PCI_DSS_CONTROLS
from ..compliance.frameworks.nist_800_53 import NIST_CONTROLS
from ..compliance.frameworks.cis_benchmarks import CIS_BENCHMARKS

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/compliance", tags=["compliance"])

_mapper = ComplianceMapper()

FRAMEWORK_DESCRIPTIONS: Dict[str, str] = {
    "owasp": "OWASP Top 10 (2021) — Ten most critical web application security risks",
    "pci_dss": "PCI-DSS v4.0 — Payment Card Industry Data Security Standard (12 requirements)",
    "nist": "NIST SP 800-53 Rev 5 — Security and Privacy Controls (20 control families)",
    "cis": "CIS Benchmarks — Security configuration benchmarks for Linux, Docker, Kubernetes, AWS, Azure",
}


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class FindingRequest(BaseModel):
    id: str = Field(..., description="Unique finding identifier")
    title: str = Field(..., description="Finding title")
    description: str = Field("", description="Detailed description")
    severity: str = Field("medium", description="critical | high | medium | low | info")
    category: str = Field("", description="Finding category")
    source: str = Field("", description="Source tool or scanner")
    tested: bool = Field(True, description="Whether this was actively tested")


class MapRequest(BaseModel):
    findings: List[FindingRequest] = Field(..., description="List of pentest findings")
    framework: str = Field(..., description="Target framework: owasp | pci_dss | nist | cis")


class GapsRequest(BaseModel):
    findings: List[FindingRequest] = Field(..., description="List of pentest findings")
    framework: str = Field(..., description="Target framework: owasp | pci_dss | nist | cis")


class MapAllRequest(BaseModel):
    findings: List[FindingRequest] = Field(..., description="List of pentest findings")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_finding(req: FindingRequest) -> Finding:
    return Finding(
        id=req.id,
        title=req.title,
        description=req.description,
        severity=req.severity.lower(),
        category=req.category,
        source=req.source,
        tested=req.tested,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/frameworks")
async def list_frameworks() -> Dict[str, Any]:
    """List all available compliance frameworks with descriptions."""
    return {
        "frameworks": [
            {"id": fw_id, "description": desc}
            for fw_id, desc in FRAMEWORK_DESCRIPTIONS.items()
        ]
    }


@router.post("/map")
async def map_findings(
    body: MapRequest,
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    """Map a list of findings to a compliance framework. Requires authentication."""
    findings = [_to_finding(f) for f in body.findings]
    try:
        report = _mapper.map_findings(findings, body.framework)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return report.to_dict()


@router.post("/gaps")
async def get_gaps(
    body: GapsRequest,
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    """Get gap analysis for a list of findings against a framework. Requires authentication."""
    findings = [_to_finding(f) for f in body.findings]
    try:
        gap = _mapper.get_gap_analysis(findings, body.framework)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return gap.to_dict()


@router.post("/map-all")
async def map_all_frameworks(
    body: MapAllRequest,
    current_user_id: str = Depends(get_current_user_id),
) -> Dict[str, Any]:
    """Map a list of findings to all supported compliance frameworks. Requires authentication."""
    findings = [_to_finding(f) for f in body.findings]
    reports = _mapper.map_all_frameworks(findings)
    return {fw: report.to_dict() for fw, report in reports.items()}


@router.get("/controls/{framework}")
async def list_controls(framework: str) -> Dict[str, Any]:
    """List all controls/requirements defined for a framework."""
    fw = framework.lower()
    if fw == "owasp":
        controls = [
            {
                "control_id": c.control_id,
                "title": c.title,
                "description": c.description,
                "risk_level": c.risk_level,
                "cwe_ids": c.cwe_ids,
            }
            for c in OWASP_TOP10_CONTROLS.values()
        ]
    elif fw == "pci_dss":
        controls = [
            {
                "req_id": r.req_id,
                "title": r.title,
                "description": r.description,
                "sub_requirements": [
                    {"id": sr.id, "title": sr.title}
                    for sr in r.sub_requirements
                ],
            }
            for r in PCI_DSS_CONTROLS.values()
        ]
    elif fw == "nist":
        controls = [
            {
                "family_id": f.family_id,
                "title": f.title,
                "description": f.description,
                "key_controls": [
                    {"control_id": kc.control_id, "title": kc.title, "description": kc.description}
                    for kc in f.key_controls
                ],
            }
            for f in NIST_CONTROLS.values()
        ]
    elif fw == "cis":
        controls = []
        for plat_key, benchmark in CIS_BENCHMARKS.items():
            for section in benchmark.sections:
                controls.append({
                    "platform": benchmark.platform,
                    "version": benchmark.version,
                    "section_id": f"{plat_key}/{section.section_id}",
                    "title": section.title,
                    "level": section.level,
                    "recommendation": section.recommendation,
                })
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported framework '{framework}'. Supported: owasp, pci_dss, nist, cis",
        )

    return {"framework": fw, "controls": controls, "total": len(controls)}
