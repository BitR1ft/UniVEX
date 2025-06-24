"""
GraphQL Subscriptions — WebSocket-based real-time event streams.

Subscriptions:
  onScanStatusChange(scanId)   — emits ScanStatusEvent whenever a scan transitions state
  onFindingDiscovered(projectId) — emits FindingDiscoveredEvent when a new finding is created
  onAgentProgress(sessionId)   — emits AgentProgressEvent with agent execution updates
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import AsyncGenerator

import strawberry
from strawberry.types import Info

from app.graphql.types import (
    ScanStatusEvent, ScanStatus,
    FindingDiscoveredEvent, FindingSeverity,
    AgentProgressEvent, AgentRole,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal pub/sub broker
# ---------------------------------------------------------------------------
# Lightweight in-process broker backed by asyncio.Queue.
# For multi-process deployments, replace with Redis Pub/Sub.
# ---------------------------------------------------------------------------

_scan_subscribers: dict[str, list[asyncio.Queue]] = {}
_finding_subscribers: dict[str, list[asyncio.Queue]] = {}
_agent_subscribers: dict[str, list[asyncio.Queue]] = {}

_HEARTBEAT_INTERVAL = 30  # seconds


async def _publish_scan_event(event: ScanStatusEvent) -> None:
    """Publish a scan status event to all interested subscribers."""
    queues = _scan_subscribers.get(event.scan_id, []) + _scan_subscribers.get("*", [])
    for q in queues:
        await q.put(event)


async def _publish_finding_event(event: FindingDiscoveredEvent) -> None:
    """Publish a finding discovered event."""
    project_id = event.project_id or "*"
    queues = _finding_subscribers.get(project_id, []) + _finding_subscribers.get("*", [])
    for q in queues:
        await q.put(event)


async def _publish_agent_event(event: AgentProgressEvent, session_id: str) -> None:
    """Publish an agent progress event."""
    queues = _agent_subscribers.get(session_id, []) + _agent_subscribers.get("*", [])
    for q in queues:
        await q.put(event)


@strawberry.type
class Subscription:
    # -----------------------------------------------------------------------
    # onScanStatusChange
    # -----------------------------------------------------------------------

    @strawberry.subscription(
        description=(
            "Subscribe to scan status changes. "
            "Pass scanId='*' to receive events for all scans."
        )
    )
    async def on_scan_status_change(
        self,
        info: Info,
        scan_id: str = "*",
    ) -> AsyncGenerator[ScanStatusEvent, None]:
        """Emit ScanStatusEvent whenever a scan transitions state."""
        queue: asyncio.Queue[ScanStatusEvent] = asyncio.Queue(maxsize=100)

        # Register subscriber
        _scan_subscribers.setdefault(scan_id, []).append(queue)

        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=_HEARTBEAT_INTERVAL)
                    yield event
                except asyncio.TimeoutError:
                    # Send heartbeat to keep the connection alive
                    yield ScanStatusEvent(
                        scan_id=scan_id,
                        project_id="",
                        status=ScanStatus.RUNNING,
                        message="heartbeat",
                        timestamp=datetime.utcnow(),
                    )
        except asyncio.CancelledError:
            pass
        finally:
            try:
                _scan_subscribers[scan_id].remove(queue)
                if not _scan_subscribers[scan_id]:
                    del _scan_subscribers[scan_id]
            except (KeyError, ValueError):
                pass

    # -----------------------------------------------------------------------
    # onFindingDiscovered
    # -----------------------------------------------------------------------

    @strawberry.subscription(
        description=(
            "Subscribe to new finding discoveries. "
            "Pass projectId='*' to receive events for all projects."
        )
    )
    async def on_finding_discovered(
        self,
        info: Info,
        project_id: str = "*",
    ) -> AsyncGenerator[FindingDiscoveredEvent, None]:
        """Emit FindingDiscoveredEvent whenever a new finding is created."""
        queue: asyncio.Queue[FindingDiscoveredEvent] = asyncio.Queue(maxsize=100)
        _finding_subscribers.setdefault(project_id, []).append(queue)

        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=_HEARTBEAT_INTERVAL)
                    yield event
                except asyncio.TimeoutError:
                    # Yield a synthetic heartbeat
                    yield FindingDiscoveredEvent(
                        finding_id="__heartbeat__",
                        project_id=project_id if project_id != "*" else None,
                        scan_id=None,
                        title="heartbeat",
                        severity=FindingSeverity.INFO,
                        timestamp=datetime.utcnow(),
                    )
        except asyncio.CancelledError:
            pass
        finally:
            try:
                _finding_subscribers[project_id].remove(queue)
                if not _finding_subscribers[project_id]:
                    del _finding_subscribers[project_id]
            except (KeyError, ValueError):
                pass

    # -----------------------------------------------------------------------
    # onAgentProgress
    # -----------------------------------------------------------------------

    @strawberry.subscription(
        description=(
            "Subscribe to agent execution progress events for a given session. "
            "Pass sessionId='*' to receive all agent events."
        )
    )
    async def on_agent_progress(
        self,
        info: Info,
        session_id: str = "*",
    ) -> AsyncGenerator[AgentProgressEvent, None]:
        """Emit AgentProgressEvent with phase/progress updates during execution."""
        queue: asyncio.Queue[AgentProgressEvent] = asyncio.Queue(maxsize=100)
        _agent_subscribers.setdefault(session_id, []).append(queue)

        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=_HEARTBEAT_INTERVAL)
                    yield event
                except asyncio.TimeoutError:
                    yield AgentProgressEvent(
                        agent_role=AgentRole.PLANNER,
                        phase="idle",
                        message="heartbeat",
                        progress_pct=0.0,
                        timestamp=datetime.utcnow(),
                    )
        except asyncio.CancelledError:
            pass
        finally:
            try:
                _agent_subscribers[session_id].remove(queue)
                if not _agent_subscribers[session_id]:
                    del _agent_subscribers[session_id]
            except (KeyError, ValueError):
                pass
