"""
Reconnaissance API Endpoints

Provides REST API endpoints for domain discovery and reconnaissance operations.
Integrates with WebSocket for real-time progress updates.
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from typing import Optional, Dict, Any
import logging
from datetime import datetime

from app.recon.domain_discovery import DomainDiscovery
from app.recon.schemas import (
    ReconTaskRequest,
    ReconTaskResponse,
    ReconTaskStatus,
    ReconTaskList,
    DomainDiscoveryResult
)
from app.core.security import get_current_user
from app.utils.job_tracker import JobTracker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/recon", tags=["reconnaissance"])


# In-memory task storage (will be replaced with database in production)
recon_tasks: Dict[str, Dict[str, Any]] = {}


@router.post("/discover", response_model=ReconTaskResponse)
async def start_domain_discovery(
    request: ReconTaskRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Start domain discovery for a target domain.
    
    This endpoint initiates a background task for comprehensive domain discovery
    including WHOIS lookup, subdomain enumeration, and DNS resolution.
    """
    try:
        import uuid
        task_id = str(uuid.uuid4())
        
        logger.info(f"Starting domain discovery for {request.domain} (task: {task_id})")
        
        # Store task status
        now = datetime.utcnow()
        recon_tasks[task_id] = {
            "task_id": task_id,
            "status": "pending",
            "domain": request.domain,
            "user_id": current_user.get("user_id"),
            "progress": 0,
            "message": "Task queued",
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
            "results": None
        }
        
        # Start background task
        background_tasks.add_task(
            run_domain_discovery,
            task_id,
            request.domain,
            request.hackertarget_api_key,
            request.dns_nameservers
        )
        
        return ReconTaskResponse(
            status="success",
            message=f"Domain discovery started for {request.domain}",
            task_id=task_id
        )
        
    except Exception as e:
        logger.error(f"Error starting domain discovery: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status/{task_id}", response_model=ReconTaskResponse)
async def get_recon_status(
    task_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Get the status of a reconnaissance task.
    
    Returns the current status, progress, and results (if completed).
    """
    if task_id not in recon_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task = recon_tasks[task_id]
    
    # Check if user owns this task
    if task["user_id"] != current_user.get("user_id"):
        raise HTTPException(status_code=403, detail="Not authorized to access this task")
    
    return ReconTaskResponse(
        status=task["status"],
        message=task.get("message", f"Task progress: {task['progress']}%"),
        task_id=task_id,
        data=task.get("results")
    )


@router.get("/results/{task_id}", response_model=DomainDiscoveryResult)
async def get_recon_results(
    task_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Get the full results of a completed reconnaissance task.
    """
    if task_id not in recon_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task = recon_tasks[task_id]
    
    # Check if user owns this task
    if task["user_id"] != current_user.get("user_id"):
        raise HTTPException(status_code=403, detail="Not authorized to access this task")
    
    if task["status"] != "completed":
        raise HTTPException(status_code=400, detail="Task not completed yet")
    
    return task.get("results", {})


async def run_domain_discovery(
    task_id: str,
    domain: str,
    hackertarget_api_key: Optional[str] = None,
    dns_nameservers: Optional[list] = None
):
    """
    Background task to run domain discovery.
    
    Updates task status and stores results upon completion.
    """
    tracker = JobTracker(task_id, recon_tasks)
    try:
        logger.info(f"Running domain discovery for {domain} (task: {task_id})")

        await tracker.start("Starting domain discovery")

        # Initialize discovery
        discovery = DomainDiscovery(
            domain=domain,
            hackertarget_api_key=hackertarget_api_key,
            dns_nameservers=dns_nameservers
        )

        # Run discovery
        await tracker.progress(25, "Running domain discovery")
        results = await discovery.run()

        # Store results
        await tracker.complete(results, result_key="domain_discovery", message="Discovery completed successfully")

        logger.info(f"Domain discovery completed for {domain} (task: {task_id})")

    except Exception as e:
        logger.error(f"Error in domain discovery task {task_id}: {str(e)}")
        await tracker.fail(str(e))


@router.delete("/tasks/{task_id}")
async def delete_recon_task(
    task_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Delete a reconnaissance task and its results.
    """
    if task_id not in recon_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task = recon_tasks[task_id]
    
    # Check if user owns this task
    if task["user_id"] != current_user.get("user_id"):
        raise HTTPException(status_code=403, detail="Not authorized to delete this task")
    
    del recon_tasks[task_id]
    
    return {"status": "success", "message": "Task deleted"}


@router.get("/tasks", response_model=ReconTaskList)
async def list_recon_tasks(
    page: int = 1,
    per_page: int = 20,
    current_user: dict = Depends(get_current_user)
):
    """
    List all reconnaissance tasks for the current user.
    """
    user_id = current_user.get("user_id")
    user_tasks = [
        ReconTaskStatus(
            task_id=task["task_id"],
            domain=task["domain"],
            status=task["status"],
            progress=task["progress"],
            message=task.get("message"),
            created_at=datetime.fromisoformat(task["created_at"]),
            updated_at=datetime.fromisoformat(task["updated_at"]),
            user_id=task["user_id"]
        )
        for task in recon_tasks.values()
        if task["user_id"] == user_id
    ]
    
    # Simple pagination
    total = len(user_tasks)
    start = (page - 1) * per_page
    end = start + per_page
    paginated_tasks = user_tasks[start:end]
    
    return ReconTaskList(
        tasks=paginated_tasks,
        total=total,
        page=page,
        per_page=per_page
    )
