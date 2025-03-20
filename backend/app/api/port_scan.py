"""
Port Scanning API Endpoints

Provides REST API endpoints for port scanning operations.
"""
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from typing import Dict, Any
import logging
from datetime import datetime
import uuid

from app.recon.port_scanning import (
    PortScanOrchestrator,
    PortScanRequest
)
from app.core.security import get_current_user
from app.utils.job_tracker import JobTracker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/port-scan", tags=["port-scanning"])


# In-memory task storage (will be replaced with database in production)
port_scan_tasks: Dict[str, Dict[str, Any]] = {}


async def execute_port_scan(task_id: str, request: PortScanRequest, user_id: str):
    """
    Background task to execute port scanning
    """
    tracker = JobTracker(task_id, port_scan_tasks)
    try:
        logger.info(f"Executing port scan task {task_id}")
        await tracker.start("Starting port scan")

        # Create orchestrator and run scan
        orchestrator = PortScanOrchestrator(request)
        result = await orchestrator.run()

        # Store results
        port_scan_tasks[task_id]["result"] = result.model_dump()
        await tracker.complete(result.model_dump(), result_key="port_scan", message="Port scan completed successfully")

        logger.info(f"Port scan task {task_id} completed successfully")

    except Exception as e:
        logger.error(f"Port scan task {task_id} failed: {str(e)}")
        await tracker.fail(str(e))


@router.post("/scan", response_model=Dict[str, Any])
async def start_port_scan(
    request: PortScanRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Start a port scanning task
    
    Initiates a background port scanning task for the specified targets.
    Returns a task ID for status tracking.
    """
    try:
        task_id = str(uuid.uuid4())
        user_id = current_user.get("sub")
        
        logger.info(f"Starting port scan for {len(request.targets)} targets (task: {task_id})")
        
        # Store task metadata
        port_scan_tasks[task_id] = {
            "task_id": task_id,
            "user_id": user_id,
            "status": "pending",
            "request": request.model_dump(),
            "result": None,
            "error": None,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        
        # Start background task
        background_tasks.add_task(execute_port_scan, task_id, request, user_id)
        
        return {
            "task_id": task_id,
            "status": "pending",
            "message": f"Port scan started for {len(request.targets)} targets"
        }
        
    except Exception as e:
        logger.error(f"Failed to start port scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status/{task_id}", response_model=Dict[str, Any])
async def get_scan_status(
    task_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Get the status of a port scanning task
    """
    if task_id not in port_scan_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task = port_scan_tasks[task_id]
    
    # Check ownership
    if task["user_id"] != current_user.get("sub"):
        raise HTTPException(status_code=403, detail="Not authorized to access this task")
    
    return {
        "task_id": task_id,
        "status": task["status"],
        "created_at": task["created_at"],
        "updated_at": task["updated_at"],
        "error": task.get("error")
    }


@router.get("/results/{task_id}", response_model=Dict[str, Any])
async def get_scan_results(
    task_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Get the results of a completed port scanning task
    """
    if task_id not in port_scan_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task = port_scan_tasks[task_id]
    
    # Check ownership
    if task["user_id"] != current_user.get("sub"):
        raise HTTPException(status_code=403, detail="Not authorized to access this task")
    
    if task["status"] != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Task is not completed. Current status: {task['status']}"
        )
    
    return {
        "task_id": task_id,
        "status": task["status"],
        "result": task["result"],
        "created_at": task["created_at"],
        "updated_at": task["updated_at"]
    }


@router.delete("/tasks/{task_id}")
async def delete_scan_task(
    task_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Delete a port scanning task
    """
    if task_id not in port_scan_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task = port_scan_tasks[task_id]
    
    # Check ownership
    if task["user_id"] != current_user.get("sub"):
        raise HTTPException(status_code=403, detail="Not authorized to delete this task")
    
    del port_scan_tasks[task_id]
    
    return {"message": "Task deleted successfully"}


@router.get("/tasks", response_model=Dict[str, Any])
async def list_scan_tasks(
    page: int = 1,
    per_page: int = 20,
    current_user: dict = Depends(get_current_user)
):
    """
    List all port scanning tasks for the current user
    """
    user_id = current_user.get("sub")
    
    # Filter tasks by user
    user_tasks = [
        task for task in port_scan_tasks.values()
        if task["user_id"] == user_id
    ]
    
    # Sort by created_at descending
    user_tasks.sort(key=lambda x: x["created_at"], reverse=True)
    
    # Pagination
    total = len(user_tasks)
    start = (page - 1) * per_page
    end = start + per_page
    paginated_tasks = user_tasks[start:end]
    
    return {
        "tasks": paginated_tasks,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page
    }
