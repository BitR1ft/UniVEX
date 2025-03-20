"""
CWE/CAPEC & Risk Enrichment API

Filtered query endpoints exposing the enrichment pipeline:

    GET  /api/enrichment/cwe/{cwe_id}                – CWE lookup
    GET  /api/enrichment/capec/{capec_id}            – CAPEC lookup
    GET  /api/enrichment/cwe/{cwe_id}/attacks        – CWE → CAPEC attack patterns
    GET  /api/enrichment/capec/{capec_id}/weaknesses – CAPEC → CWE weaknesses
    POST /api/enrichment/score                       – risk score for a finding
    POST /api/enrichment/prioritise                  – sort + annotate findings
    GET  /api/enrichment/search                      – search CWE/CAPEC by keyword
    GET  /api/enrichment/audit-log                   – view update audit log
"""
from __future__ import annotations

import logging
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.core.security import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/enrichment", tags=["CWE/CAPEC Enrichment"])

# ---------------------------------------------------------------------------
# Shared service instances (lazy singletons)
# ---------------------------------------------------------------------------
_cwe_svc: Optional[Any] = None
_capec_svc: Optional[Any] = None
_mapper: Optional[Any] = None


async def _get_cwe() -> Any:
    global _cwe_svc
    if _cwe_svc is None or not _cwe_svc.is_loaded():
        from app.services.cwe_capec.cwe_service import CWEService
        _cwe_svc = CWEService()
        await _cwe_svc.load()
    return _cwe_svc


async def _get_capec() -> Any:
    global _capec_svc
    if _capec_svc is None or not _capec_svc.is_loaded():
        from app.services.cwe_capec.capec_service import CAPECService
        _capec_svc = CAPECService()
        await _capec_svc.load()
    return _capec_svc


async def _get_mapper() -> Any:
    global _mapper
    if _mapper is None or not _mapper._built:
        from app.services.cwe_capec.cwe_capec_mapper import CWECAPECMapper
        _mapper = CWECAPECMapper(await _get_cwe(), await _get_capec())
        await _mapper.build()
    return _mapper


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class FindingScoreRequest(BaseModel):
    """Input for /score and /prioritise endpoints."""
    id: str
    name: str
    severity: str = "unknown"
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cve_ids: List[str] = Field(default_factory=list)
    cwe_ids: List[str] = Field(default_factory=list)
    extra: Dict[str, Any] = Field(default_factory=dict)
    description: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)


class PrioritiseRequest(BaseModel):
    findings: List[FindingScoreRequest]
    exposure: str = Field("unknown", description="Target exposure context")


# ---------------------------------------------------------------------------
# CWE endpoints
# ---------------------------------------------------------------------------

@router.get("/cwe/{cwe_id}", response_model=Dict[str, Any])
async def get_cwe(
    cwe_id: str,
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """Look up a single CWE entry by ID (e.g. ``CWE-79`` or ``79``)."""
    svc = await _get_cwe()
    entry = svc.lookup(cwe_id)
    if not entry:
        raise HTTPException(status_code=404, detail=f"{cwe_id} not found in CWE database")
    return asdict(entry)


@router.get("/cwe/{cwe_id}/attacks", response_model=Dict[str, Any])
async def get_attacks_for_cwe(
    cwe_id: str,
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """Return CAPEC attack patterns that exploit a given CWE weakness."""
    mapper = await _get_mapper()
    patterns = mapper.attacks_for_cwe(cwe_id)
    return {
        "cwe_id": cwe_id.upper(),
        "attack_patterns": [asdict(p) for p in patterns],
        "count": len(patterns),
    }


# ---------------------------------------------------------------------------
# CAPEC endpoints
# ---------------------------------------------------------------------------

@router.get("/capec/{capec_id}", response_model=Dict[str, Any])
async def get_capec(
    capec_id: str,
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """Look up a single CAPEC attack pattern by ID."""
    svc = await _get_capec()
    entry = svc.lookup(capec_id)
    if not entry:
        raise HTTPException(status_code=404, detail=f"{capec_id} not found in CAPEC database")
    return asdict(entry)


@router.get("/capec/{capec_id}/weaknesses", response_model=Dict[str, Any])
async def get_weaknesses_for_capec(
    capec_id: str,
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """Return CWE weaknesses targeted by a given CAPEC attack pattern."""
    mapper = await _get_mapper()
    weaknesses = mapper.weaknesses_for_capec(capec_id)
    return {
        "capec_id": capec_id.upper(),
        "weaknesses": [asdict(w) for w in weaknesses],
        "count": len(weaknesses),
    }


# ---------------------------------------------------------------------------
# Risk scoring endpoints
# ---------------------------------------------------------------------------

@router.post("/score", response_model=Dict[str, Any])
async def score_finding(
    req: FindingScoreRequest,
    exposure: str = Query("unknown"),
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """Compute risk score for a single Finding-like object."""
    from app.services.cwe_capec.risk_scorer import compute_risk_score

    maturity = req.extra.get("cve_enrichment", {}).get("exploit_info", {}).get("maturity")
    risk = compute_risk_score(
        cvss_score=req.cvss_score,
        severity=req.severity,
        exploit_maturity=maturity,
        exposure=exposure,
    )
    return {
        "id": req.id,
        "risk_score": risk,
        "inputs": {
            "cvss_score": req.cvss_score,
            "severity": req.severity,
            "exploit_maturity": maturity,
            "exposure": exposure,
        },
    }


@router.post("/prioritise", response_model=Dict[str, Any])
async def prioritise_findings(
    body: PrioritiseRequest,
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Sort findings by descending risk score and annotate with priority rank.

    Also applies CWE extraction and CAPEC attack pattern enrichment.
    """
    from app.services.cwe_capec.risk_scorer import prioritise_findings as _prioritise
    from app.services.cwe_capec.vuln_cwe_mapper import apply_cwe_to_finding
    from app.recon.canonical_schemas import Finding

    # Convert request objects to Finding-like objects with mutable extras
    findings = []
    for req in body.findings:
        f = Finding(
            id=req.id,
            name=req.name,
            description=req.description,
            severity=_to_severity(req.severity),
            cvss_score=req.cvss_score,
            cve_ids=req.cve_ids,
            cwe_ids=list(req.cwe_ids),
            references=req.references,
            tags=req.tags,
            extra=dict(req.extra),
        )
        # Infer CWEs from description
        apply_cwe_to_finding(f)
        findings.append(f)

    # Enrich with CAPEC attack patterns
    mapper = await _get_mapper()
    for f in findings:
        mapper.enrich_with_attack_patterns(f)

    prioritised = _prioritise(findings, exposure=body.exposure)

    return {
        "total": len(prioritised),
        "exposure": body.exposure,
        "findings": [f.model_dump(mode="json") for f in prioritised],
    }


# ---------------------------------------------------------------------------
# Search endpoint
# ---------------------------------------------------------------------------

@router.get("/search", response_model=Dict[str, Any])
async def search_enrichment(
    q: str = Query(..., min_length=2, description="Keyword search in CWE/CAPEC names and descriptions"),
    kind: str = Query("all", description="'cwe', 'capec', or 'all'"),
    severity: Optional[str] = Query(None, description="Filter CAPEC by severity"),
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Search CWE and CAPEC databases by keyword.

    Returns matching entries with a ``match_score`` field (simple substring
    priority: name match > description match).
    """
    q_lower = q.lower()
    results: Dict[str, Any] = {}

    if kind in ("cwe", "all"):
        cwe_svc = await _get_cwe()
        cwe_matches = []
        for entry in cwe_svc.all():
            name_match = q_lower in entry.name.lower()
            desc_match = q_lower in (entry.description or "").lower()
            if name_match or desc_match:
                d = asdict(entry)
                d["match_score"] = 2 if name_match else 1
                cwe_matches.append(d)
        cwe_matches.sort(key=lambda x: x["match_score"], reverse=True)
        results["cwe"] = cwe_matches

    if kind in ("capec", "all"):
        capec_svc = await _get_capec()
        capec_matches = []
        for entry in capec_svc.all():
            if severity and (entry.severity or "").lower() != severity.lower():
                continue
            name_match = q_lower in entry.name.lower()
            desc_match = q_lower in (entry.description or "").lower()
            if name_match or desc_match:
                d = asdict(entry)
                d["match_score"] = 2 if name_match else 1
                capec_matches.append(d)
        capec_matches.sort(key=lambda x: x["match_score"], reverse=True)
        results["capec"] = capec_matches

    return {"query": q, "results": results}


# ---------------------------------------------------------------------------
# Audit log endpoint
# ---------------------------------------------------------------------------

@router.get("/audit-log", response_model=Dict[str, Any])
async def get_audit_log(
    last_n: int = Query(50, ge=1, le=500, description="Number of most recent entries to return"),
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """Return the most recent update scheduler audit log entries."""
    from app.services.cwe_capec.update_scheduler import read_audit_log
    entries = read_audit_log(last_n=last_n)
    return {"count": len(entries), "entries": entries}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _to_severity(raw: str) -> Any:
    from app.services.cwe_capec.risk_scorer import normalise_severity
    return normalise_severity(raw)
