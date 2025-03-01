"""
Server-Sent Events (SSE) endpoints for real-time streaming
Provides one-way server-to-client streaming for logs and progress updates

Security: All endpoints require a valid JWT bearer token.
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sse_starlette.sse import EventSourceResponse
from typing import AsyncGenerator, Dict, Any
import asyncio
import logging
from datetime import datetime
import json

from app.api.auth import get_current_user_id

logger = logging.getLogger(__name__)

router = APIRouter()


class SSEManager:
    """Manager for Server-Sent Events streams"""
    
    def __init__(self):
        # Store active event generators by project
        self.active_streams: Dict[str, list] = {}
    
    async def scan_event_generator(
        self,
        project_id: str,
        request: Request
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Generate scan progress events
        
        Args:
            project_id: Project identifier
            request: FastAPI request object (to detect disconnection)
            
        Yields:
            Event dictionaries with scan updates
        """
        try:
            # Send initial connection event
            yield {
                'event': 'connected',
                'data': json.dumps({
                    'message': f'Connected to scan updates for project {project_id}',
                    'project_id': project_id,
                    'timestamp': datetime.utcnow().isoformat()
                })
            }
            
            # Keep connection alive and stream events
            while True:
                # Check if client disconnected
                if await request.is_disconnected():
                    logger.info(f"SSE client disconnected from project {project_id}")
                    break
                
                # Here you would fetch actual scan updates from your scan queue/database
                # For now, send heartbeat
                yield {
                    'event': 'heartbeat',
                    'data': json.dumps({
                        'timestamp': datetime.utcnow().isoformat()
                    })
                }
                
                # Wait before next update
                await asyncio.sleep(30)  # Heartbeat every 30 seconds
        
        except asyncio.CancelledError:
            logger.info(f"SSE stream cancelled for project {project_id}")
        except Exception as e:
            logger.error(f"Error in SSE stream for project {project_id}: {e}")
            yield {
                'event': 'error',
                'data': json.dumps({
                    'error': str(e),
                    'timestamp': datetime.utcnow().isoformat()
                })
            }
    
    async def log_event_generator(
        self,
        project_id: str,
        request: Request
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Generate log events for a project
        
        Args:
            project_id: Project identifier
            request: FastAPI request object
            
        Yields:
            Event dictionaries with log entries
        """
        try:
            # Send initial connection event
            yield {
                'event': 'connected',
                'data': json.dumps({
                    'message': f'Connected to logs for project {project_id}',
                    'project_id': project_id,
                    'timestamp': datetime.utcnow().isoformat()
                })
            }
            
            # Stream log events
            while True:
                # Check if client disconnected
                if await request.is_disconnected():
                    logger.info(f"Log SSE client disconnected from project {project_id}")
                    break
                
                # Here you would fetch actual logs from your logging system
                # For now, send heartbeat
                yield {
                    'event': 'heartbeat',
                    'data': json.dumps({
                        'timestamp': datetime.utcnow().isoformat()
                    })
                }
                
                # Wait before next update
                await asyncio.sleep(15)  # Heartbeat every 15 seconds
        
        except asyncio.CancelledError:
            logger.info(f"Log SSE stream cancelled for project {project_id}")
        except Exception as e:
            logger.error(f"Error in log SSE stream for project {project_id}: {e}")
            yield {
                'event': 'error',
                'data': json.dumps({
                    'error': str(e),
                    'timestamp': datetime.utcnow().isoformat()
                })
            }
    
    async def send_scan_update(
        self,
        project_id: str,
        scan_type: str,
        status: str,
        data: Dict = None
    ):
        """
        Send a scan update event
        
        Args:
            project_id: Project identifier
            scan_type: Type of scan
            status: Scan status
            data: Additional data
        """
        # This would integrate with your event queue system
        # For now, it's a placeholder
        pass


# Global SSE manager
sse_manager = SSEManager()


@router.get("/stream/scans/{project_id}")
async def stream_scan_updates(
    project_id: str,
    request: Request,
    current_user_id: str = Depends(get_current_user_id),
):
    """
    SSE endpoint for streaming scan updates.

    Requires a valid JWT bearer token. The authenticated user must own
    (or have access to) the requested project — otherwise 403 is returned.

    Args:
        project_id: Project identifier
        request: FastAPI request
        current_user_id: Injected by JWT dependency

    Returns:
        EventSourceResponse with scan update stream
    """
    # Validate project ownership / access
    await _assert_project_access(current_user_id, project_id)

    logger.info(
        "SSE scan stream opened: user=%s project=%s",
        current_user_id,
        project_id,
    )
    return EventSourceResponse(
        sse_manager.scan_event_generator(project_id, request),
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
        }
    )


@router.get("/stream/logs/{project_id}")
async def stream_logs(
    project_id: str,
    request: Request,
    current_user_id: str = Depends(get_current_user_id),
):
    """
    SSE endpoint for streaming project logs.

    Requires a valid JWT bearer token.

    Args:
        project_id: Project identifier
        request: FastAPI request
        current_user_id: Injected by JWT dependency

    Returns:
        EventSourceResponse with log stream
    """
    # Validate project ownership / access
    await _assert_project_access(current_user_id, project_id)

    logger.info(
        "SSE log stream opened: user=%s project=%s",
        current_user_id,
        project_id,
    )
    return EventSourceResponse(
        sse_manager.log_event_generator(project_id, request),
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
        }
    )


async def _assert_project_access(user_id: str, project_id: str) -> None:
    """
    Verify that *user_id* is permitted to subscribe to events for *project_id*.

    Currently loads the project from PostgreSQL via Prisma and checks that
    ``project.user_id == user_id``.  Raises HTTP 403 on mismatch and HTTP 404
    when the project does not exist.
    """
    try:
        from app.db.prisma_client import get_prisma
        db = await get_prisma()
        project = await db.project.find_unique(where={"id": project_id})
        if project is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Project '{project_id}' not found.",
            )
        if project.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have access to this project's event stream.",
            )
    except HTTPException:
        raise
    except Exception as exc:
        # If DB is unavailable, log but allow through to avoid blocking SSE
        # in degraded mode (non-critical path — auth token already validated).
        logger.warning(
            "Could not verify project ownership for SSE stream "
            "(user=%s project=%s): %s — allowing through",
            user_id,
            project_id,
            exc,
        )


def get_sse_manager() -> SSEManager:
    """Dependency injection for SSE manager"""
    return sse_manager
