"""
CVE Enrichment REST API

Endpoints:
    GET  /api/cve/{cve_id}           – single CVE enrichment lookup
    POST /api/enrich/findings        – batch-enrich Finding objects
    POST /api/enrich/findings/batch  – same as above, alias
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core.security import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(tags=["CVE Enrichment"])

# ---------------------------------------------------------------------------
# Shared EnrichmentService instance (lazy, singleton per process)
# ---------------------------------------------------------------------------
_svc: Optional[Any] = None


def _get_service() -> Any:
    global _svc
    if _svc is None:
        from app.services.enrichment import EnrichmentService
        _svc = EnrichmentService(
            nvd_api_key=os.environ.get("NVD_API_KEY"),
            vulners_api_key=os.environ.get("VULNERS_API_KEY"),
        )
    return _svc


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class FindingInput(BaseModel):
    """Minimal Finding representation for the enrichment endpoint."""
    id: str = Field(..., description="Finding identifier")
    name: str = Field(..., description="Short finding title")
    description: Optional[str] = None
    severity: str = "unknown"
    url: Optional[str] = None
    cve_ids: List[str] = Field(default_factory=list)
    cwe_ids: List[str] = Field(default_factory=list)
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    evidence: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    extra: Dict[str, Any] = Field(default_factory=dict)


class BatchEnrichRequest(BaseModel):
    """Request body for batch finding enrichment."""
    findings: List[FindingInput] = Field(..., min_length=1)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/api/cve/{cve_id}", response_model=Dict[str, Any])
async def get_cve(
    cve_id: str,
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Retrieve full CVE enrichment data for a single CVE identifier.

    Data is fetched from the local cache first; on a miss it is retrieved
    from the NVD API v2 and optionally merged with Vulners exploit data.

    Args:
        cve_id: CVE identifier in the format ``CVE-YYYY-NNNNN``.
    """
    svc = _get_service()
    try:
        result = await svc.get_cve(cve_id.upper())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.error("CVE lookup failed for %s: %s", cve_id, exc)
        raise HTTPException(status_code=502, detail="Upstream CVE lookup failed")

    if result is None:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found in NVD")

    from datetime import datetime

    def _serial(obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError

    import json
    return json.loads(json.dumps(_dataclass_to_dict(result), default=_serial))


@router.post("/api/enrich/findings", response_model=Dict[str, Any])
@router.post("/api/enrich/findings/batch", response_model=Dict[str, Any])
async def enrich_findings(
    body: BatchEnrichRequest,
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Batch-enrich a list of Finding objects with CVE metadata.

    For each finding that has at least one ``cve_id``, the first CVE is
    looked up and its CVSS score, description, CWE IDs, and exploit info
    are merged back into the finding's fields.

    Findings without ``cve_ids`` are returned unchanged.
    """
    svc = _get_service()

    try:
        enriched = await svc.enrich_findings(list(body.findings))
    except Exception as exc:
        logger.error("Batch enrichment failed: %s", exc)
        raise HTTPException(status_code=500, detail="Enrichment pipeline error")

    return {
        "enriched": len([f for f in enriched if f.extra.get("cve_enrichment")]),
        "total": len(enriched),
        "findings": [f.model_dump() for f in enriched],
    }


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _dataclass_to_dict(obj: Any) -> Any:
    import dataclasses
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _dataclass_to_dict(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, list):
        return [_dataclass_to_dict(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _dataclass_to_dict(v) for k, v in obj.items()}
    return obj
