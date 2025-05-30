"""
Worker Server — Dangerous Tool Execution Microservice

dangerous penetration testing tools (Metasploit, SQLMap, network scanning)
in isolation from the main application node.

Architecture
------------
  Main Node  — FastAPI backend, agents, databases, LLM providers
  Worker Node — WorkerServer + MCP tool servers + Kali tooling (no databases)

Communication
-------------
  Main Node → Worker Node: POST /api/worker/execute  (REST over mTLS or shared secret)
  Worker Node → Main Node: job result in response body (synchronous) or callback (async)

Authentication
--------------
  WORKER_SHARED_SECRET — HMAC-SHA256 bearer token (development / non-mTLS mode)
  WORKER_MTLS_CERT_PATH / WORKER_MTLS_KEY_PATH — mTLS client certificates (production)

Environment Variables
---------------------
  WORKER_SHARED_SECRET   — 32-char hex secret for request authentication
  WORKER_MAX_TIMEOUT     — maximum job duration in seconds (default 300)
  WORKER_MAX_CONCURRENT  — maximum concurrent jobs (default 10)
  WORKER_PORT            — listening port (default 9443)
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WORKER_SHARED_SECRET: str = os.getenv("WORKER_SHARED_SECRET", "")
WORKER_MAX_TIMEOUT: int = int(os.getenv("WORKER_MAX_TIMEOUT", "300"))
WORKER_MAX_CONCURRENT: int = int(os.getenv("WORKER_MAX_CONCURRENT", "10"))
WORKER_PORT: int = int(os.getenv("WORKER_PORT", "9443"))

# Semaphore enforced by the execute endpoint
_semaphore: Optional[asyncio.Semaphore] = None
_active_jobs: int = 0


def get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(WORKER_MAX_CONCURRENT)
    return _semaphore


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class WorkerJobRequest(BaseModel):
    """A single tool execution request sent by the main node."""

    job_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    tool_name: str = Field(..., description="Name of the MCP tool to execute (e.g. 'execute_naabu')")
    server_name: str = Field(..., description="Target MCP server name (e.g. 'naabu', 'metasploit')")
    params: Dict[str, Any] = Field(default_factory=dict, description="Tool parameters")
    timeout: int = Field(default=WORKER_MAX_TIMEOUT, description="Job timeout in seconds")
    classification: str = Field(
        default="remote",
        description="Job classification — always 'remote' for requests that reach the worker",
    )


class WorkerJobResult(BaseModel):
    """Result returned after executing a worker job."""

    job_id: str
    tool_name: str
    server_name: str
    success: bool
    result: Optional[Any] = None
    error: Optional[str] = None
    duration_ms: float = 0.0
    worker_id: str = Field(default_factory=lambda: os.getenv("WORKER_ID", "worker-1"))


# ---------------------------------------------------------------------------
# Authentication helper
# ---------------------------------------------------------------------------


def _verify_request(request: Request) -> bool:
    """
    Verify an inbound request from the main node.

    Accepts two modes:
    1. Shared-secret mode: Authorization header = ``Bearer <WORKER_SHARED_SECRET>``
    2. mTLS mode: client certificate verified by the ASGI server — no header needed.

    If ``WORKER_SHARED_SECRET`` is empty, all requests are accepted (dev mode only).
    """
    if not WORKER_SHARED_SECRET:
        # Dev/test mode — no auth
        return True
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return False
    token = auth_header[len("Bearer "):]
    expected = WORKER_SHARED_SECRET
    return hmac.compare_digest(token.encode(), expected.encode())


# ---------------------------------------------------------------------------
# Job executor
# ---------------------------------------------------------------------------

# Registry of available MCP server adapters on the worker node
_MCP_SERVERS: Dict[str, Any] = {}


def register_mcp_server(name: str, server: Any) -> None:
    """Register an MCP server instance for use by the worker."""
    _MCP_SERVERS[name.lower()] = server
    logger.info("WorkerServer: registered MCP server '%s'", name)


async def _execute_job(req: WorkerJobRequest) -> WorkerJobResult:
    """
    Dispatch a job to the appropriate MCP server and return the result.

    Falls back to a placeholder result if the target server is not loaded.
    """
    start = time.monotonic()
    server = _MCP_SERVERS.get(req.server_name.lower())

    try:
        if server is None:
            raise RuntimeError(
                f"MCP server '{req.server_name}' is not registered on this worker node. "
                f"Available servers: {list(_MCP_SERVERS.keys())}"
            )
        result = await asyncio.wait_for(
            server.execute_tool(req.tool_name, req.params),
            timeout=req.timeout,
        )
        duration_ms = (time.monotonic() - start) * 1000
        return WorkerJobResult(
            job_id=req.job_id,
            tool_name=req.tool_name,
            server_name=req.server_name,
            success=True,
            result=result,
            duration_ms=duration_ms,
        )
    except asyncio.TimeoutError:
        duration_ms = (time.monotonic() - start) * 1000
        return WorkerJobResult(
            job_id=req.job_id,
            tool_name=req.tool_name,
            server_name=req.server_name,
            success=False,
            error=f"Job timed out after {req.timeout}s",
            duration_ms=duration_ms,
        )
    except Exception as exc:
        duration_ms = (time.monotonic() - start) * 1000
        logger.error("WorkerServer job %s failed: %s", req.job_id, exc, exc_info=True)
        return WorkerJobResult(
            job_id=req.job_id,
            tool_name=req.tool_name,
            server_name=req.server_name,
            success=False,
            error=str(exc),
            duration_ms=duration_ms,
        )


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------


def create_app() -> FastAPI:
    """Factory — create and configure the WorkerServer FastAPI application."""
    app = FastAPI(
        title="UniVex Worker Server",
        description="Isolated tool execution microservice for dangerous penetration testing operations",
        version="1.0.0",
        docs_url="/docs",
        redoc_url=None,
    )

    @app.get("/health", tags=["meta"])
    async def health() -> Dict[str, Any]:
        """Health check endpoint."""
        return {
            "status": "healthy",
            "worker_id": os.getenv("WORKER_ID", "worker-1"),
            "registered_servers": list(_MCP_SERVERS.keys()),
            "max_concurrent": WORKER_MAX_CONCURRENT,
        }

    @app.get("/api/worker/capabilities", tags=["worker"])
    async def capabilities(request: Request) -> Dict[str, Any]:
        """Return the list of available tool servers on this worker."""
        if not _verify_request(request):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
        servers: List[Dict[str, Any]] = []
        for name, srv in _MCP_SERVERS.items():
            tools = []
            try:
                tools = [t.name for t in srv.get_tools()]
            except Exception:
                pass
            servers.append({"name": name, "tools": tools})
        return {"worker_id": os.getenv("WORKER_ID", "worker-1"), "servers": servers}

    @app.post("/api/worker/execute", tags=["worker"])
    async def execute(request: Request, job: WorkerJobRequest) -> WorkerJobResult:
        """Execute a tool on the worker node."""
        global _active_jobs
        if not _verify_request(request):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

        sem = get_semaphore()
        if _active_jobs >= WORKER_MAX_CONCURRENT:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Worker is at maximum concurrent job capacity",
            )

        _active_jobs += 1
        async with sem:
            try:
                logger.info(
                    "WorkerServer: executing job %s tool=%s server=%s",
                    job.job_id, job.tool_name, job.server_name,
                )
                return await _execute_job(job)
            finally:
                _active_jobs -= 1

    @app.exception_handler(Exception)
    async def global_error_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error("WorkerServer unhandled exception: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal worker error", "error": str(exc)},
        )

    return app


# ---------------------------------------------------------------------------
# Convenience singleton
# ---------------------------------------------------------------------------

_app: Optional[FastAPI] = None


def get_app() -> FastAPI:
    """Return (or lazily create) the module-level FastAPI app singleton."""
    global _app
    if _app is None:
        _app = create_app()
    return _app


__all__ = [
    "WorkerJobRequest",
    "WorkerJobResult",
    "WorkerServer",
    "create_app",
    "get_app",
    "register_mcp_server",
    "_execute_job",
    "_verify_request",
    "WORKER_SHARED_SECRET",
    "WORKER_MAX_TIMEOUT",
    "WORKER_MAX_CONCURRENT",
]

# Alias for type-hinting convenience
WorkerServer = FastAPI
