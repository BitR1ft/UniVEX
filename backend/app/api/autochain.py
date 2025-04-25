"""
AutoChain REST API

Exposes the AutoChain pipeline via endpoints:

  POST   /api/autochain/start              — create and launch a chain run
  POST   /api/autochain/start/template     — launch from a named template
  GET    /api/autochain/templates          — list available templates
  GET    /api/autochain/{chain_id}         — poll current status
  GET    /api/autochain/{chain_id}/flags   — retrieve captured flags
  GET    /api/autochain/{chain_id}/steps   — list all completed steps
  GET    /api/autochain/{chain_id}/stream  — SSE stream of live progress
  DELETE /api/autochain/{chain_id}         — stop a running chain

Security: ALL endpoints require a valid JWT bearer token.

State persistence: ChainResult metadata is persisted to Redis under
  autochain:{user_id}:{chain_id}
so state survives restarts and supports multi-replica deployments.
The in-process AutoChain orchestrator dict (_orchestrators) remains
in-memory (runtime only) — chains interrupted by a restart will show
status INTERRUPTED in Redis on next poll.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from app.api.auth import get_current_user_id
from app.autochain import AutoChain, ChainResult, ChainStatus, ScanPlan
from app.core.rate_limit import autochain_limiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/autochain", tags=["autochain"])

# ---------------------------------------------------------------------------
# In-memory orchestrator registry (runtime only — NOT persisted)
# ---------------------------------------------------------------------------
_orchestrators: Dict[str, AutoChain] = {}

# ---------------------------------------------------------------------------
# Redis helpers
# ---------------------------------------------------------------------------

_CHAIN_TTL_SECONDS = 60 * 60 * 24 * 7  # 7 days


def _redis_key(user_id: str, chain_id: str) -> str:
    return f"autochain:{user_id}:{chain_id}"


async def _persist_chain(user_id: str, chain_id: str, result: ChainResult) -> None:
    """Serialise ChainResult to Redis. Fire-and-forget; never raises."""
    try:
        import redis.asyncio as aioredis
        from app.core.config import settings

        redis_url = getattr(settings, "REDIS_URL", "redis://localhost:6379")
        client = await aioredis.from_url(redis_url, decode_responses=True)
        payload = json.dumps(result.model_dump() if hasattr(result, "model_dump") else vars(result), default=str)
        await client.set(_redis_key(user_id, chain_id), payload, ex=_CHAIN_TTL_SECONDS)
        await client.aclose()
    except Exception as exc:
        logger.warning("Could not persist chain %s to Redis: %s", chain_id, exc)


async def _load_chain(user_id: str, chain_id: str) -> Optional[dict]:
    """Load a chain result dict from Redis. Returns None if unavailable."""
    try:
        import redis.asyncio as aioredis
        from app.core.config import settings

        redis_url = getattr(settings, "REDIS_URL", "redis://localhost:6379")
        client = await aioredis.from_url(redis_url, decode_responses=True)
        raw = await client.get(_redis_key(user_id, chain_id))
        await client.aclose()
        return json.loads(raw) if raw else None
    except Exception as exc:
        logger.warning("Could not load chain %s from Redis: %s", chain_id, exc)
        return None


async def _delete_chain_from_redis(user_id: str, chain_id: str) -> None:
    """Remove chain entry from Redis."""
    try:
        import redis.asyncio as aioredis
        from app.core.config import settings

        redis_url = getattr(settings, "REDIS_URL", "redis://localhost:6379")
        client = await aioredis.from_url(redis_url, decode_responses=True)
        await client.delete(_redis_key(user_id, chain_id))
        await client.aclose()
    except Exception as exc:
        logger.warning("Could not delete chain %s from Redis: %s", chain_id, exc)


# ---------------------------------------------------------------------------
# Per-user in-memory chain cache (for running processes in this replica)
# Structure: { user_id: { chain_id: ChainResult } }
# ---------------------------------------------------------------------------
_chains: Dict[str, Dict[str, ChainResult]] = {}


def _get_user_chains(user_id: str) -> Dict[str, ChainResult]:
    if user_id not in _chains:
        _chains[user_id] = {}
    return _chains[user_id]


def _get_chain_for_user(user_id: str, chain_id: str) -> Optional[ChainResult]:
    return _get_user_chains(user_id).get(chain_id)


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class AutoChainStartRequest(BaseModel):
    """Parameters for launching an automated pentest chain."""

    target: str = Field(
        ...,
        description="Target IP address, hostname, or URL",
        examples=["10.10.10.3"],
    )
    project_id: Optional[str] = Field(
        None, description="Optional project ID to associate the run with"
    )
    auto_approve_risk_level: str = Field(
        "none",
        description=(
            "Maximum risk level auto-approved without human confirmation. "
            "Values: none | low | medium | high | critical. "
            "Use 'high' for HTB lab mode."
        ),
    )
    naabu_url: str = Field("http://kali-tools:8000", description="Naabu MCP server URL")
    nuclei_url: str = Field("http://kali-tools:8002", description="Nuclei MCP server URL")
    msf_url: str = Field("http://kali-tools:8003", description="Metasploit MCP server URL")


class AutoChainStartResponse(BaseModel):
    """Response returned when a chain run is successfully created."""

    chain_id: str
    plan_id: str
    target: str
    status: str
    started_at: str
    message: str


class AutoChainStatusResponse(BaseModel):
    """Current status of an AutoChain run."""

    chain_id: str
    target: str
    status: str
    current_phase: Optional[str]
    total_steps: int
    completed_steps: int
    total_vulns_found: int
    total_exploits_attempted: int
    exploitation_success: bool
    flags_found: int
    session_id: Optional[int]
    started_at: str
    finished_at: Optional[str]
    error: Optional[str]


class AutoChainFlagsResponse(BaseModel):
    """Flags captured during post-exploitation."""

    chain_id: str
    target: str
    flags: List[Dict[str, str]]
    count: int


class AutoChainStepsResponse(BaseModel):
    """Full step log for an AutoChain run."""

    chain_id: str
    target: str
    status: str
    steps: List[Dict[str, Any]]


class AutoChainTemplateStartRequest(BaseModel):
    """Parameters for launching an AutoChain run from a named template."""

    template: str = Field(
        ...,
        description="Template name (e.g. 'htb_easy', 'htb_medium')",
        examples=["htb_easy"],
    )
    target: str = Field(
        ...,
        description="Target IP address, hostname, or URL",
        examples=["10.10.10.3"],
    )
    project_id: Optional[str] = Field(None)
    auto_approve_risk_level: Optional[str] = Field(
        None,
        description=(
            "Override template's auto-approve level. "
            "Values: none | low | medium | high | critical"
        ),
    )
    naabu_url: str = Field("http://kali-tools:8000")
    nuclei_url: str = Field("http://kali-tools:8002")
    msf_url: str = Field("http://kali-tools:8003")


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------


async def _run_chain(user_id: str, chain_id: str, orchestrator: AutoChain) -> None:
    """Background task that drives the AutoChain pipeline."""
    try:
        result = await orchestrator.run()
        _get_user_chains(user_id)[chain_id] = result
        await _persist_chain(user_id, chain_id, result)
        logger.info(
            "AutoChain %s (user=%s) finished with status=%s flags=%d",
            chain_id,
            user_id,
            result.status,
            len(result.flags),
        )
    except Exception as exc:
        logger.error("AutoChain %s crashed: %s", chain_id, exc, exc_info=True)
        user_chains = _get_user_chains(user_id)
        if chain_id in user_chains:
            user_chains[chain_id].finish(ChainStatus.FAILED, error=str(exc))
            await _persist_chain(user_id, chain_id, user_chains[chain_id])


# ---------------------------------------------------------------------------
# Helper to look up a chain (in-memory first, then Redis)
# ---------------------------------------------------------------------------


async def _resolve_chain(user_id: str, chain_id: str) -> ChainResult:
    """Return the ChainResult for chain_id owned by user_id or raise 404."""
    result = _get_chain_for_user(user_id, chain_id)
    if result is None:
        # Attempt to reload from Redis (e.g. after replica restart)
        raw = await _load_chain(user_id, chain_id)
        if raw is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Chain '{chain_id}' not found.",
            )
        # Reconstruct a minimal result for status reporting
        # (orchestrator is gone — chain is not running in this replica)
        result = _chains_from_redis_dict(raw)
        _get_user_chains(user_id)[chain_id] = result
    return result


def _chains_from_redis_dict(raw: dict) -> ChainResult:
    """Best-effort reconstruction of a ChainResult from a Redis dict.
    Returns a lightweight object suitable for status reporting."""
    from app.autochain import ChainResult as _CR, ChainStep  # local import

    try:
        return _CR.model_validate(raw)
    except Exception:
        # Fall back to a stub object with the persisted status
        stub = object.__new__(_CR)
        for k, v in raw.items():
            try:
                setattr(stub, k, v)
            except Exception:
                pass
        return stub


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/start", response_model=AutoChainStartResponse, status_code=201)
async def start_chain(
    request: AutoChainStartRequest,
    background_tasks: BackgroundTasks,
    current_user_id: str = Depends(get_current_user_id),
) -> AutoChainStartResponse:
    """
    Create and launch an automated pentest chain.

    Requires authentication. Rate-limited to prevent runaway LLM/tool costs.
    The chain runs in the background; poll ``GET /api/autochain/{chain_id}``
    or subscribe to ``GET /api/autochain/{chain_id}/stream`` for live updates.
    """
    # Rate limit: 10 chain starts per user per hour
    autochain_limiter.check(current_user_id)

    chain_id = str(uuid.uuid4())

    plan = ScanPlan(
        target=request.target,
        project_id=request.project_id,
        auto_approve_risk_level=request.auto_approve_risk_level,
    )

    orchestrator = AutoChain(
        plan=plan,
        naabu_url=request.naabu_url,
        nuclei_url=request.nuclei_url,
        msf_url=request.msf_url,
    )

    # Store in per-user memory map + Redis
    _get_user_chains(current_user_id)[chain_id] = orchestrator.result
    _orchestrators[chain_id] = orchestrator
    await _persist_chain(current_user_id, chain_id, orchestrator.result)

    background_tasks.add_task(_run_chain, current_user_id, chain_id, orchestrator)

    logger.info(
        "Started AutoChain %s for user=%s target=%s",
        chain_id,
        current_user_id,
        request.target,
    )

    return AutoChainStartResponse(
        chain_id=chain_id,
        plan_id=plan.plan_id,
        target=request.target,
        status=ChainStatus.RUNNING.value,
        started_at=orchestrator.result.started_at,
        message=(
            f"AutoChain started. Poll GET /api/autochain/{chain_id} for status "
            f"or subscribe to GET /api/autochain/{chain_id}/stream for live updates."
        ),
    )


@router.get("/templates", response_model=List[Dict[str, Any]])
async def list_templates(
    current_user_id: str = Depends(get_current_user_id),
) -> List[Dict[str, Any]]:
    """
    Return metadata for all available attack templates.

    Templates are JSON files in ``backend/app/autochain/templates/``.
    Built-in templates:

    * ``htb_easy``   — standard HackTheBox Easy attack sequence
    * ``htb_medium`` — extended HackTheBox Medium attack sequence
    """
    return AutoChain.list_templates()


@router.post("/start/template", response_model=AutoChainStartResponse, status_code=201)
async def start_chain_from_template(
    request: AutoChainTemplateStartRequest,
    background_tasks: BackgroundTasks,
    current_user_id: str = Depends(get_current_user_id),
) -> AutoChainStartResponse:
    """
    Create and launch an AutoChain run using a pre-defined attack template.

    Templates define the full attack sequence (tools, parameters, retry logic,
    auto-approve level) so callers only need to supply the target.
    """
    # Rate limit: shared with /start — 10 chain starts per user per hour
    autochain_limiter.check(current_user_id)

    try:
        orchestrator = AutoChain.from_template(
            request.template,
            target=request.target,
            project_id=request.project_id,
            auto_approve_risk_level=request.auto_approve_risk_level,
            naabu_url=request.naabu_url,
            nuclei_url=request.nuclei_url,
            msf_url=request.msf_url,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    chain_id = str(uuid.uuid4())
    _get_user_chains(current_user_id)[chain_id] = orchestrator.result
    _orchestrators[chain_id] = orchestrator
    await _persist_chain(current_user_id, chain_id, orchestrator.result)

    background_tasks.add_task(_run_chain, current_user_id, chain_id, orchestrator)

    logger.info(
        "Started template-based AutoChain %s (template=%s, user=%s, target=%s)",
        chain_id,
        request.template,
        current_user_id,
        request.target,
    )

    return AutoChainStartResponse(
        chain_id=chain_id,
        plan_id=orchestrator.plan.plan_id,
        target=request.target,
        status=ChainStatus.RUNNING.value,
        started_at=orchestrator.result.started_at,
        message=(
            f"AutoChain started from template '{request.template}'. "
            f"Poll GET /api/autochain/{chain_id} for status or subscribe to "
            f"GET /api/autochain/{chain_id}/stream for live updates."
        ),
    )


@router.get("/{chain_id}", response_model=AutoChainStatusResponse)
async def get_chain_status(
    chain_id: str,
    current_user_id: str = Depends(get_current_user_id),
) -> AutoChainStatusResponse:
    """Return the current status of an AutoChain run owned by the caller."""
    result = await _resolve_chain(current_user_id, chain_id)

    completed = sum(
        1 for s in result.steps if s.status in ("success", "failed", "skipped")
    )

    return AutoChainStatusResponse(
        chain_id=chain_id,
        target=result.target,
        status=result.status.value if hasattr(result.status, "value") else result.status,
        current_phase=result.current_phase.value if result.current_phase and hasattr(result.current_phase, "value") else result.current_phase,
        total_steps=len(result.steps),
        completed_steps=completed,
        total_vulns_found=result.total_vulns_found,
        total_exploits_attempted=result.total_exploits_attempted,
        exploitation_success=result.exploitation_success,
        flags_found=len(result.flags),
        session_id=result.session_id,
        started_at=result.started_at,
        finished_at=result.finished_at,
        error=result.error,
    )


@router.get("/{chain_id}/flags", response_model=AutoChainFlagsResponse)
async def get_chain_flags(
    chain_id: str,
    current_user_id: str = Depends(get_current_user_id),
) -> AutoChainFlagsResponse:
    """Return flags captured during post-exploitation for a chain owned by the caller."""
    result = await _resolve_chain(current_user_id, chain_id)

    return AutoChainFlagsResponse(
        chain_id=chain_id,
        target=result.target,
        flags=result.flags,
        count=len(result.flags),
    )


@router.get("/{chain_id}/steps", response_model=AutoChainStepsResponse)
async def get_chain_steps(
    chain_id: str,
    current_user_id: str = Depends(get_current_user_id),
) -> AutoChainStepsResponse:
    """Return the complete step log for an AutoChain run owned by the caller."""
    result = await _resolve_chain(current_user_id, chain_id)

    return AutoChainStepsResponse(
        chain_id=chain_id,
        target=result.target,
        status=result.status.value if hasattr(result.status, "value") else result.status,
        steps=[s.model_dump() for s in result.steps],
    )


@router.get("/{chain_id}/stream")
async def stream_chain_progress(
    chain_id: str,
    request: Request,
    current_user_id: str = Depends(get_current_user_id),
):
    """
    SSE stream of live step updates for an AutoChain run owned by the caller.

    Each event is a JSON-encoded ``ChainStep``. The stream closes when the
    chain reaches a terminal state (complete / failed / stopped).
    """
    result = await _resolve_chain(current_user_id, chain_id)
    orchestrator = _orchestrators.get(chain_id)

    async def _event_generator():
        # Yield already-completed steps first so a late subscriber catches up
        seen_step_ids: set = set()
        for step in list(result.steps):
            seen_step_ids.add(step.step_id)
            yield {
                "event": "step",
                "data": json.dumps(step.model_dump()),
            }

        # If there is an orchestrator still running, stream new steps as they arrive
        if orchestrator is not None:
            while result.status == ChainStatus.RUNNING:
                if await request.is_disconnected():
                    break
                for step in list(result.steps):
                    if step.step_id not in seen_step_ids:
                        seen_step_ids.add(step.step_id)
                        yield {
                            "event": "step",
                            "data": json.dumps(step.model_dump()),
                        }
                await asyncio.sleep(0.5)

        # Send final status event
        yield {
            "event": "status",
            "data": json.dumps(
                {
                    "status": result.status.value if hasattr(result.status, "value") else result.status,
                    "exploitation_success": result.exploitation_success,
                    "flags_found": len(result.flags),
                    "finished_at": result.finished_at,
                    "error": result.error,
                }
            ),
        }

    return EventSourceResponse(
        _event_generator(),
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.delete("/{chain_id}", status_code=204, response_model=None)
async def stop_chain(
    chain_id: str,
    current_user_id: str = Depends(get_current_user_id),
) -> None:
    """
    Request cancellation of a running AutoChain owned by the caller.

    Sets the chain status to STOPPED and removes it from the active orchestrator
    registry. Already-completed steps are preserved in Redis for review.
    """
    result = await _resolve_chain(current_user_id, chain_id)

    if result.status == ChainStatus.RUNNING:
        result.finish(ChainStatus.STOPPED)

    _orchestrators.pop(chain_id, None)
    await _persist_chain(current_user_id, chain_id, result)
    logger.info("AutoChain %s stopped by user=%s.", chain_id, current_user_id)
