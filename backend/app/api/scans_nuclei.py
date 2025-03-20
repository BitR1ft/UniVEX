"""
Vulnerability Scanning API Endpoints – /api/scans/nuclei

REST API for Nuclei-based vulnerability scanning:

    POST   /api/scans/nuclei           – start a new scan
    GET    /api/scans/nuclei/{id}       – get scan status
    GET    /api/scans/nuclei/{id}/results – get scan results
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core.security import get_current_user
from app.recon.vuln_scanning.nuclei_orchestrator import (
    NucleiOrchestratorConfig,
    NucleiOrchestrator,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans/nuclei", tags=["nuclei-scans"])

# ---------------------------------------------------------------------------
# In-memory task store (replaced with DB in Phase A)
# ---------------------------------------------------------------------------
_tasks: Dict[str, Dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class NucleiScanCreateRequest(BaseModel):
    """Parameters for a new Nuclei vulnerability scan."""

    targets: List[str] = Field(..., min_length=1, description="Target URLs or domains")
    severity_filter: List[str] = Field(
        default=["critical", "high"],
        description="Severity levels to include: critical, high, medium, low, info",
    )
    include_tags: List[str] = Field(default=[], description="Template tags to include")
    exclude_tags: List[str] = Field(
        default=["dos", "fuzz"],
        description="Template tags to exclude",
    )
    templates_path: Optional[str] = Field(None, description="Custom templates directory")
    rate_limit: int = Field(100, ge=1, le=1000, description="Requests per second")
    concurrency: int = Field(25, ge=1, le=100, description="Parallel template execution")
    timeout: int = Field(10, ge=1, le=60, description="Per-request timeout (seconds)")
    interactsh_enabled: bool = Field(False, description="Enable Interactsh for OOB detection")
    interactsh_server: Optional[str] = Field(None, description="Custom Interactsh server URL")
    max_concurrent_targets: int = Field(
        5, ge=1, le=20, description="Max parallel target scans"
    )


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

async def _run_scan(task_id: str, req: NucleiScanCreateRequest) -> None:
    _tasks[task_id]["status"] = "running"
    _tasks[task_id]["updated_at"] = datetime.utcnow().isoformat()

    cfg = NucleiOrchestratorConfig(
        severity_filter=req.severity_filter,
        include_tags=req.include_tags,
        exclude_tags=req.exclude_tags,
        templates_path=req.templates_path,
        rate_limit=req.rate_limit,
        concurrency=req.concurrency,
        timeout=req.timeout,
        interactsh_enabled=req.interactsh_enabled,
        interactsh_server=req.interactsh_server,
        max_concurrent_targets=req.max_concurrent_targets,
    )

    try:
        results = await NucleiOrchestrator.scan_targets(req.targets, config=cfg)
        serialised = [r.model_dump(mode="json") for r in results]
        total_findings = sum(len(r.get("findings", [])) for r in serialised)
        _tasks[task_id]["status"] = "completed"
        _tasks[task_id]["result"] = serialised
        _tasks[task_id]["total_findings"] = total_findings
    except Exception as exc:
        logger.error("Nuclei scan task %s failed: %s", task_id, exc)
        _tasks[task_id]["status"] = "failed"
        _tasks[task_id]["error"] = str(exc)
    finally:
        _tasks[task_id]["updated_at"] = datetime.utcnow().isoformat()


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

@router.post("", response_model=Dict[str, Any], status_code=202)
async def start_nuclei_scan(
    req: NucleiScanCreateRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Start a new Nuclei vulnerability scan.

    Returns a ``task_id`` for status polling.
    """
    task_id = str(uuid.uuid4())
    user_id = current_user.get("sub")

    _tasks[task_id] = {
        "task_id": task_id,
        "user_id": user_id,
        "status": "pending",
        "targets": req.targets,
        "severity_filter": req.severity_filter,
        "result": None,
        "total_findings": 0,
        "error": None,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
    }

    background_tasks.add_task(_run_scan, task_id, req)

    return {
        "task_id": task_id,
        "status": "pending",
        "message": f"Nuclei scan queued for {len(req.targets)} target(s)",
    }


@router.get("/{task_id}", response_model=Dict[str, Any])
async def get_nuclei_scan_status(
    task_id: str,
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get status of a Nuclei scan task."""
    task = _tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found")

    if task["user_id"] != current_user.get("sub"):
        raise HTTPException(status_code=403, detail="Not authorised to access this task")

    return {
        "task_id": task_id,
        "status": task["status"],
        "targets": task["targets"],
        "severity_filter": task.get("severity_filter"),
        "total_findings": task.get("total_findings", 0),
        "created_at": task["created_at"],
        "updated_at": task["updated_at"],
        "error": task.get("error"),
    }


@router.get("/{task_id}/results", response_model=Dict[str, Any])
async def get_nuclei_scan_results(
    task_id: str,
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """Retrieve results for a completed Nuclei scan task."""
    task = _tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found")

    if task["user_id"] != current_user.get("sub"):
        raise HTTPException(status_code=403, detail="Not authorised to access this task")

    if task["status"] != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Scan is not yet completed (status: {task['status']})",
        )

    return {
        "task_id": task_id,
        "status": "completed",
        "total_findings": task.get("total_findings", 0),
        "results": task["result"],
        "created_at": task["created_at"],
        "updated_at": task["updated_at"],
    }
