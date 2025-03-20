"""
Port Scanning API Endpoints – /api/scans/ports

Provides REST API endpoints aligned with the canonical plan:

    POST   /api/scans/ports           – start a new scan
    GET    /api/scans/ports/{id}       – get scan status
    GET    /api/scans/ports/{id}/results – get scan results
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core.security import get_current_user
from app.recon.port_scanning.naabu_orchestrator import NaabuConfig, NaabuOrchestrator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans/ports", tags=["port-scans"])

# ---------------------------------------------------------------------------
# In-memory task store (replaced with DB in production Phase A)
# ---------------------------------------------------------------------------
_tasks: Dict[str, Dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class PortScanCreateRequest(BaseModel):
    """Parameters for a new port scan."""

    targets: list[str] = Field(..., min_length=1, description="IP addresses, CIDRs, or domains")
    scan_type: str = Field("c", description="Naabu scan type: 's' (SYN) or 'c' (CONNECT)")
    top_ports: int = Field(1000, ge=1, le=65535, description="Top-N ports when no explicit list given")
    ports: Optional[str] = Field(None, description="Comma-separated port list, e.g. '80,443,8080'")
    port_range: Optional[str] = Field(None, description="Port range string, e.g. '1-1024'")
    rate_limit: int = Field(1000, ge=1, le=50000, description="Packets per second")
    exclude_private: bool = Field(True, description="Skip RFC-1918 / loopback targets")
    max_concurrent_hosts: int = Field(5, ge=1, le=50, description="Max parallel host scans")


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

async def _run_scan(task_id: str, req: PortScanCreateRequest) -> None:
    """Execute port scan and store result in ``_tasks``."""
    _tasks[task_id]["status"] = "running"
    _tasks[task_id]["updated_at"] = datetime.utcnow().isoformat()

    cfg = NaabuConfig(
        scan_type=req.scan_type,
        top_ports=req.top_ports,
        ports=req.ports,
        port_range=req.port_range,
        rate_limit=req.rate_limit,
        exclude_private=req.exclude_private,
        max_concurrent_hosts=req.max_concurrent_hosts,
    )

    try:
        results = await NaabuOrchestrator.scan_targets(req.targets, config=cfg)
        serialised = [r.model_dump(mode="json") for r in results]
        _tasks[task_id]["status"] = "completed"
        _tasks[task_id]["result"] = serialised
    except Exception as exc:
        logger.error("Port scan task %s failed: %s", task_id, exc)
        _tasks[task_id]["status"] = "failed"
        _tasks[task_id]["error"] = str(exc)
    finally:
        _tasks[task_id]["updated_at"] = datetime.utcnow().isoformat()


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

@router.post("", response_model=Dict[str, Any], status_code=202)
async def start_scan(
    req: PortScanCreateRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Start a new port scan.

    Returns a ``task_id`` that can be used to poll status and retrieve results.
    """
    task_id = str(uuid.uuid4())
    user_id = current_user.get("sub")

    _tasks[task_id] = {
        "task_id": task_id,
        "user_id": user_id,
        "status": "pending",
        "targets": req.targets,
        "result": None,
        "error": None,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
    }

    background_tasks.add_task(_run_scan, task_id, req)

    return {
        "task_id": task_id,
        "status": "pending",
        "message": f"Port scan queued for {len(req.targets)} target(s)",
    }


@router.get("/{task_id}", response_model=Dict[str, Any])
async def get_scan_status(
    task_id: str,
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get the status of a port scan task."""
    task = _tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found")

    if task["user_id"] != current_user.get("sub"):
        raise HTTPException(status_code=403, detail="Not authorised to access this task")

    return {
        "task_id": task_id,
        "status": task["status"],
        "targets": task["targets"],
        "created_at": task["created_at"],
        "updated_at": task["updated_at"],
        "error": task.get("error"),
    }


@router.get("/{task_id}/results", response_model=Dict[str, Any])
async def get_scan_results(
    task_id: str,
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """Retrieve results for a completed port scan task."""
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
        "results": task["result"],
        "created_at": task["created_at"],
        "updated_at": task["updated_at"],
    }
