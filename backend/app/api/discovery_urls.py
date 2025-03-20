"""
URL Discovery API Endpoints – /api/discovery/urls

REST API for web crawling and URL discovery:

    POST   /api/discovery/urls           – start a new discovery run
    GET    /api/discovery/urls/{id}       – poll status
    GET    /api/discovery/urls/{id}/results – retrieve results with filtering
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.core.security import get_current_user
from app.recon.resource_enum.katana_orchestrator import KatanaConfig, KatanaOrchestrator
from app.recon.resource_enum.gau_orchestrator import GAUConfig, GAUOrchestrator
from app.recon.resource_enum.kiterunner_orchestrator import KiterunnerConfig, KiterunnerOrchestrator
from app.recon.resource_enum.url_merger import URLMerger

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/discovery/urls", tags=["url-discovery"])

# ---------------------------------------------------------------------------
# In-memory task store
# NOTE: This is a temporary in-process store for Phase A.
# All task data is lost on application restart.
# This will be replaced with a persistent database store in Phase B.
# ---------------------------------------------------------------------------
_tasks: Dict[str, Dict[str, Any]] = {}
logger.warning(
    "discovery_urls: using in-memory task store — all tasks will be lost on restart. "
    "Replace with a persistent store before production deployment."
)


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class URLDiscoveryCreateRequest(BaseModel):
    """Parameters for a new URL discovery run."""

    targets: List[str] = Field(..., min_length=1, description="Target URLs or domains")

    # Tool selection
    use_katana: bool = Field(True, description="Run Katana web crawler")
    use_gau: bool = Field(True, description="Run GAU historical URL fetcher")
    use_kiterunner: bool = Field(False, description="Run Kiterunner API brute-forcer")

    # Katana options
    katana_depth: int = Field(3, ge=1, le=5, description="Katana crawl depth")
    katana_max_urls: int = Field(500, ge=1, le=10000)
    katana_js: bool = Field(False, description="Enable Katana JS rendering")
    katana_rate_limit: int = Field(100, ge=1, le=1000)

    # GAU options
    gau_providers: List[str] = Field(
        default=["wayback", "commoncrawl", "otx", "urlscan"],
        description="GAU providers to enable",
    )
    gau_max_urls: int = Field(1000, ge=1, le=50000)

    # Kiterunner options
    kr_wordlists: List[str] = Field(
        default=["routes-small"],
        description="Kiterunner wordlists",
    )
    kr_threads: int = Field(10, ge=1, le=50)


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

async def _run_discovery(task_id: str, req: URLDiscoveryCreateRequest) -> None:
    _tasks[task_id]["status"] = "running"
    _tasks[task_id]["updated_at"] = datetime.utcnow().isoformat()

    merger = URLMerger()
    errors: List[str] = []

    try:
        # Katana
        if req.use_katana:
            try:
                cfg = KatanaConfig(
                    depth=req.katana_depth,
                    max_urls=req.katana_max_urls,
                    js_crawl=req.katana_js,
                    rate_limit=req.katana_rate_limit,
                )
                results = await KatanaOrchestrator.crawl_targets(req.targets, config=cfg)
                for r in results:
                    merger.add(r.endpoints, source="katana")
            except Exception as exc:
                logger.warning("Katana failed: %s", exc)
                errors.append(f"katana: {exc}")

        # GAU
        if req.use_gau:
            try:
                cfg = GAUConfig(providers=req.gau_providers, max_urls=req.gau_max_urls)
                results = await GAUOrchestrator.fetch_targets(req.targets, config=cfg)
                for r in results:
                    merger.add(r.endpoints, source="gau")
            except Exception as exc:
                logger.warning("GAU failed: %s", exc)
                errors.append(f"gau: {exc}")

        # Kiterunner
        if req.use_kiterunner:
            try:
                cfg = KiterunnerConfig(
                    wordlists=req.kr_wordlists,
                    threads=req.kr_threads,
                )
                results = await KiterunnerOrchestrator.scan_targets(req.targets, config=cfg)
                for r in results:
                    merger.add(r.endpoints, source="kiterunner")
            except Exception as exc:
                logger.warning("Kiterunner failed: %s", exc)
                errors.append(f"kiterunner: {exc}")

        merged = merger.merge()
        stats = merger.stats()
        serialised = [ep.model_dump(mode="json") for ep in merged]

        _tasks[task_id]["status"] = "completed"
        _tasks[task_id]["result"] = serialised
        _tasks[task_id]["stats"] = stats
        _tasks[task_id]["errors"] = errors

    except Exception as exc:
        logger.error("URL discovery task %s failed: %s", task_id, exc)
        _tasks[task_id]["status"] = "failed"
        _tasks[task_id]["error"] = str(exc)
    finally:
        _tasks[task_id]["updated_at"] = datetime.utcnow().isoformat()


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

@router.post("", response_model=Dict[str, Any], status_code=202)
async def start_url_discovery(
    req: URLDiscoveryCreateRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Start a URL discovery run using the selected tools.

    Returns a ``task_id`` for polling status and results.
    """
    task_id = str(uuid.uuid4())
    tools = [t for t, en in [("katana", req.use_katana), ("gau", req.use_gau), ("kiterunner", req.use_kiterunner)] if en]

    _tasks[task_id] = {
        "task_id": task_id,
        "user_id": current_user.get("sub"),
        "status": "pending",
        "targets": req.targets,
        "tools": tools,
        "result": None,
        "stats": None,
        "errors": [],
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
    }

    background_tasks.add_task(_run_discovery, task_id, req)

    return {
        "task_id": task_id,
        "status": "pending",
        "tools": tools,
        "message": f"URL discovery queued for {len(req.targets)} target(s) using {tools}",
    }


@router.get("/{task_id}", response_model=Dict[str, Any])
async def get_discovery_status(
    task_id: str,
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get status of a URL discovery task."""
    task = _tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task["user_id"] != current_user.get("sub"):
        raise HTTPException(status_code=403, detail="Not authorised to access this task")

    return {
        "task_id": task_id,
        "status": task["status"],
        "targets": task["targets"],
        "tools": task.get("tools", []),
        "created_at": task["created_at"],
        "updated_at": task["updated_at"],
        "errors": task.get("errors", []),
        "stats": task.get("stats"),
    }


@router.get("/{task_id}/results", response_model=Dict[str, Any])
async def get_discovery_results(
    task_id: str,
    current_user: dict = Depends(get_current_user),
    category: Optional[str] = Query(None, description="Filter by URL category"),
    source: Optional[str] = Query(None, description="Filter by discovery source (katana/gau/kiterunner)"),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0, description="Minimum confidence score"),
) -> Dict[str, Any]:
    """
    Retrieve results for a completed URL discovery task.

    Supports optional filtering by category, source, and minimum confidence.
    """
    task = _tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task["user_id"] != current_user.get("sub"):
        raise HTTPException(status_code=403, detail="Not authorised to access this task")

    if task["status"] != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Task not yet completed (status: {task['status']})",
        )

    results = task.get("result", []) or []

    # Apply filters
    if category:
        results = [r for r in results if r.get("extra", {}).get("category") == category]
    if source:
        results = [r for r in results if source in (r.get("extra", {}).get("sources") or [])]
    if min_confidence > 0.0:
        results = [r for r in results if (r.get("confidence") or 0.0) >= min_confidence]

    return {
        "task_id": task_id,
        "status": "completed",
        "total": len(results),
        "stats": task.get("stats"),
        "results": results,
        "created_at": task["created_at"],
        "updated_at": task["updated_at"],
    }
