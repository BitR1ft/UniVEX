"""
HTTP Probing API Endpoints - Month 5

REST API for HTTP probing functionality.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, status
from typing import List
from datetime import datetime
import logging

from ..recon.http_probing import (
    HttpProbeOrchestrator,
    HttpProbeRequest,
    ProbeMode
)
from app.utils.job_tracker import JobTracker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/http-probe", tags=["HTTP Probing"])


# In-memory storage for probe results (replace with database in production)
probe_results = {}


@router.post("/probe", status_code=status.HTTP_202_ACCEPTED)
async def start_http_probe(
    request: HttpProbeRequest,
    background_tasks: BackgroundTasks,
    # current_user: dict = Depends(get_current_user)  # Add auth when ready
):
    """
    Start HTTP probing for target URLs.
    
    Returns task ID for tracking progress.
    """
    try:
        # Generate task ID
        task_id = f"http_probe_{datetime.utcnow().timestamp()}"
        
        # Initialize result placeholder
        probe_results[task_id] = {
            "status": "running",
            "started_at": datetime.utcnow(),
            "result": None,
            "error": None
        }
        
        # Start background task
        background_tasks.add_task(
            execute_http_probe,
            task_id,
            request
        )
        
        return {
            "task_id": task_id,
            "status": "started",
            "message": f"HTTP probe started for {len(request.targets)} target(s)"
        }
        
    except Exception as e:
        logger.error(f"Failed to start HTTP probe: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


async def execute_http_probe(task_id: str, request: HttpProbeRequest):
    """Background task for HTTP probing"""
    tracker = JobTracker(task_id, probe_results)
    try:
        logger.info(f"Executing HTTP probe task {task_id}")

        # Run probe
        orchestrator = HttpProbeOrchestrator(request)
        result = await orchestrator.run()

        # Store result in in-memory dict (legacy callers read this directly)
        probe_results[task_id].update({
            "completed_at": datetime.utcnow(),
            "result": result,
        })
        result_data = result.model_dump() if hasattr(result, "model_dump") else result
        await tracker.complete(
            result_data,
            result_key="http_probe",
            message="HTTP probe completed successfully",
        )

        logger.info(f"HTTP probe task {task_id} completed successfully")

    except Exception as e:
        logger.error(f"HTTP probe task {task_id} failed: {e}")
        probe_results[task_id].update({
            "completed_at": datetime.utcnow(),
            "error": str(e),
        })
        await tracker.fail(str(e))


@router.get("/results/{task_id}")
async def get_probe_results(
    task_id: str,
    # current_user: dict = Depends(get_current_user)  # Add auth when ready
):
    """
    Get HTTP probe results by task ID.
    """
    if task_id not in probe_results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found"
        )
    
    task_data = probe_results[task_id]
    
    if task_data["status"] == "running":
        return {
            "task_id": task_id,
            "status": "running",
            "started_at": task_data["started_at"],
            "message": "Probe is still running"
        }
    
    elif task_data["status"] == "completed":
        return {
            "task_id": task_id,
            "status": "completed",
            "started_at": task_data["started_at"],
            "completed_at": task_data["completed_at"],
            "result": task_data["result"]
        }
    
    else:  # failed
        return {
            "task_id": task_id,
            "status": "failed",
            "started_at": task_data["started_at"],
            "completed_at": task_data["completed_at"],
            "error": task_data["error"]
        }


@router.get("/tasks")
async def list_probe_tasks(
    # current_user: dict = Depends(get_current_user)  # Add auth when ready
):
    """
    List all HTTP probe tasks.
    """
    tasks = []
    
    for task_id, task_data in probe_results.items():
        tasks.append({
            "task_id": task_id,
            "status": task_data["status"],
            "started_at": task_data["started_at"],
            "completed_at": task_data.get("completed_at"),
        })
    
    return {
        "total": len(tasks),
        "tasks": tasks
    }


@router.delete("/results/{task_id}")
async def delete_probe_results(
    task_id: str,
    # current_user: dict = Depends(get_current_user)  # Add auth when ready
):
    """
    Delete HTTP probe results.
    """
    if task_id not in probe_results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found"
        )
    
    del probe_results[task_id]
    
    return {
        "message": "Results deleted successfully"
    }


@router.post("/quick-probe")
async def quick_probe(
    targets: List[str],
    mode: ProbeMode = ProbeMode.FULL,
    # current_user: dict = Depends(get_current_user)  # Add auth when ready
):
    """
    Execute a quick synchronous HTTP probe (max 10 targets).
    
    For larger probes, use the async /probe endpoint.
    """
    if len(targets) > 10:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Quick probe limited to 10 targets. Use /probe for more."
        )
    
    try:
        # Create request
        request = HttpProbeRequest(
            targets=targets,
            mode=mode
        )
        
        # Execute probe
        orchestrator = HttpProbeOrchestrator(request)
        result = await orchestrator.run()
        
        return result
        
    except Exception as e:
        logger.error(f"Quick probe failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
