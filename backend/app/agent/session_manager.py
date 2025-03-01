"""
Agent Session Manager.

Provides:
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncIterator, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class DangerLevel(str, Enum):
    """Classification of how dangerous an operation is."""
    SAFE = "safe"           # Read-only, no system changes
    LOW = "low"             # Minor changes, easily reversible
    MEDIUM = "medium"       # Moderate impact, may affect services
    HIGH = "high"           # Significant impact, hard to reverse
    CRITICAL = "critical"   # Potentially destructive or irreversible


#: Map tool names → danger level (used by ApprovalWorkflow)
TOOL_DANGER_MAP: Dict[str, DangerLevel] = {
    # Safe read-only tools
    "echo": DangerLevel.SAFE,
    "calculator": DangerLevel.SAFE,
    "query_graph": DangerLevel.SAFE,
    "attack_surface_query": DangerLevel.SAFE,
    "vulnerability_lookup": DangerLevel.SAFE,
    "nuclei_template_select": DangerLevel.SAFE,
    "cve_lookup": DangerLevel.SAFE,
    # Low-risk recon
    "web_search": DangerLevel.LOW,
    "exploit_search": DangerLevel.LOW,
    "domain_discovery": DangerLevel.LOW,
    "port_scan": DangerLevel.LOW,
    "http_probe": DangerLevel.LOW,
    "tech_detection": DangerLevel.LOW,
    "naabu_scan": DangerLevel.LOW,
    "curl": DangerLevel.LOW,
    # Medium-risk scanning
    "endpoint_enumeration": DangerLevel.MEDIUM,
    "nuclei_scan": DangerLevel.MEDIUM,
    "system_enumeration": DangerLevel.MEDIUM,
    # High-risk exploitation
    "brute_force": DangerLevel.HIGH,
    "session_manager": DangerLevel.HIGH,
    "metasploit_search": DangerLevel.HIGH,
    # Critical — irreversible
    "exploit_execute": DangerLevel.CRITICAL,
    "file_operations": DangerLevel.CRITICAL,
    "privilege_escalation": DangerLevel.CRITICAL,
}


class ApprovalWorkflow:
    """
    Approval gate system for dangerous agent operations.

    Classifies each tool call, determines whether approval is required
    (based on a configurable threshold), and creates/resolves approval requests.
    """

    def __init__(
        self,
        require_approval_from: DangerLevel = DangerLevel.HIGH,
        custom_tool_map: Optional[Dict[str, DangerLevel]] = None,
    ):
        """
        Args:
            require_approval_from: Minimum danger level that triggers approval.
            custom_tool_map: Optional overrides to the default tool danger map.
        """
        self.require_approval_from = require_approval_from
        self._tool_map: Dict[str, DangerLevel] = dict(TOOL_DANGER_MAP)
        if custom_tool_map:
            self._tool_map.update(custom_tool_map)
        # Pending approvals: request_id → approval dict
        self._pending: Dict[str, Dict[str, Any]] = {}

    def classify_tool(self, tool_name: str) -> DangerLevel:
        """
        Return the DangerLevel for *tool_name*.

        Unknown tools default to MEDIUM (conservative).
        """
        return self._tool_map.get(tool_name, DangerLevel.MEDIUM)

    def requires_approval(self, tool_name: str) -> bool:
        """
        Return True if *tool_name* requires human approval.

        The threshold is set by ``require_approval_from``.
        """
        danger_order = list(DangerLevel)
        tool_level = self.classify_tool(tool_name)
        return danger_order.index(tool_level) >= danger_order.index(self.require_approval_from)

    def create_approval_request(
        self,
        tool_name: str,
        tool_input: Dict[str, Any],
        thread_id: str,
        project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a pending approval request for a tool execution.

        Args:
            tool_name: Name of the tool requiring approval
            tool_input: Parameters the tool will be called with
            thread_id: Agent thread ID
            project_id: Project context

        Returns:
            Approval request dict (include in AgentState.pending_approval)
        """
        request_id = str(uuid.uuid4())
        request = {
            "request_id": request_id,
            "tool": tool_name,
            "tool_input": tool_input,
            "thread_id": thread_id,
            "project_id": project_id,
            "danger_level": self.classify_tool(tool_name).value,
            "reason": (
                f"Tool '{tool_name}' is classified as "
                f"'{self.classify_tool(tool_name).value}' and requires human approval."
            ),
            "status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._pending[request_id] = request
        logger.info(f"Approval request created: {request_id} for tool '{tool_name}'")
        return request

    def resolve_approval(self, request_id: str, approved: bool) -> Optional[Dict[str, Any]]:
        """
        Resolve a pending approval request.

        Args:
            request_id: ID of the approval request
            approved: True to approve, False to reject

        Returns:
            Updated request dict, or None if not found
        """
        request = self._pending.get(request_id)
        if not request:
            logger.warning(f"Approval request {request_id} not found.")
            return None
        request["status"] = "approved" if approved else "rejected"
        request["resolved_at"] = datetime.now(timezone.utc).isoformat()
        del self._pending[request_id]
        logger.info(
            f"Approval {request_id} {'approved' if approved else 'rejected'} "
            f"for tool '{request['tool']}'"
        )
        return request

    def get_pending_requests(self) -> List[Dict[str, Any]]:
        """Return all pending approval requests."""
        return list(self._pending.values())

    def set_tool_danger(self, tool_name: str, level: DangerLevel) -> None:
        """Override the danger level for a specific tool."""
        self._tool_map[tool_name] = level


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class StopResumeManager:
    """
    Manages agent stop/pause and resume from checkpoint.

    Stores the last known AgentState for each thread so that the agent
    can be cleanly stopped and later resumed.
    """

    def __init__(self):
        # thread_id → saved state snapshot
        self._checkpoints: Dict[str, Dict[str, Any]] = {}
        self._stopped_threads: set = set()

    def save_checkpoint(self, thread_id: str, state: Dict[str, Any]) -> None:
        """
        Save a state snapshot for *thread_id*.

        Args:
            thread_id: Agent thread identifier
            state: Current AgentState to checkpoint
        """
        import copy

        snapshot = copy.deepcopy(dict(state))
        snapshot["_checkpoint_time"] = datetime.now(timezone.utc).isoformat()
        self._checkpoints[thread_id] = snapshot
        logger.info(f"Checkpoint saved for thread {thread_id}")

    def stop_agent(self, thread_id: str, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stop the agent for *thread_id*, saving its current state.

        Args:
            thread_id: Agent thread to stop
            state: Current state to save

        Returns:
            Updated state with should_stop=True
        """
        self.save_checkpoint(thread_id, state)
        self._stopped_threads.add(thread_id)
        updated = dict(state)
        updated["should_stop"] = True
        updated["next_action"] = "end"
        logger.info(f"Agent stopped for thread {thread_id}")
        return updated

    def resume_agent(
        self,
        thread_id: str,
        message: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Resume a previously stopped agent from its checkpoint.

        Args:
            thread_id: Thread to resume
            message: Optional new message to inject into state

        Returns:
            Restored state with should_stop=False, or None if no checkpoint
        """
        checkpoint = self._checkpoints.get(thread_id)
        if not checkpoint:
            logger.warning(f"No checkpoint found for thread {thread_id}")
            return None

        state = dict(checkpoint)
        state["should_stop"] = False
        state["next_action"] = "think"
        self._stopped_threads.discard(thread_id)

        if message:
            from langchain_core.messages import HumanMessage

            messages = list(state.get("messages", []))
            messages.append(HumanMessage(content=message))
            state["messages"] = messages

        logger.info(f"Agent resumed for thread {thread_id}")
        return state

    def is_stopped(self, thread_id: str) -> bool:
        """Return True if *thread_id* has been stopped."""
        return thread_id in self._stopped_threads

    def get_checkpoint(self, thread_id: str) -> Optional[Dict[str, Any]]:
        """Return the saved checkpoint for *thread_id*, or None."""
        return self._checkpoints.get(thread_id)

    def clear_checkpoint(self, thread_id: str) -> None:
        """Remove the checkpoint for *thread_id*."""
        self._checkpoints.pop(thread_id, None)
        self._stopped_threads.discard(thread_id)

    def list_stopped_threads(self) -> List[str]:
        """Return IDs of all currently stopped threads."""
        return list(self._stopped_threads)


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class AgentSSEStreamer:
    """
    Generates Server-Sent Events for agent execution steps.

    Yields structured JSON events for: thought, action, observation,
    phase_change, approval_required, complete, and error.
    """

    @staticmethod
    def _make_event(event_type: str, data: Dict[str, Any]) -> Dict[str, str]:
        """Build an SSE-compatible event dict."""
        return {
            "event": event_type,
            "data": json.dumps(
                {**data, "timestamp": datetime.now(timezone.utc).isoformat()}
            ),
        }

    @classmethod
    def thought_event(cls, thought: str, phase: str) -> Dict[str, str]:
        """Agent reasoning step."""
        return cls._make_event("thought", {"thought": thought, "phase": phase})

    @classmethod
    def action_event(cls, tool_name: str, tool_input: Dict[str, Any]) -> Dict[str, str]:
        """Agent selected a tool."""
        return cls._make_event(
            "action", {"tool": tool_name, "input_summary": str(tool_input)[:200]}
        )

    @classmethod
    def observation_event(cls, tool_name: str, output: str) -> Dict[str, str]:
        """Tool execution result."""
        return cls._make_event(
            "observation",
            {"tool": tool_name, "output_preview": output[:300]},
        )

    @classmethod
    def phase_change_event(cls, old_phase: str, new_phase: str) -> Dict[str, str]:
        """Agent advanced to a new phase."""
        return cls._make_event(
            "phase_change", {"from": old_phase, "to": new_phase}
        )

    @classmethod
    def approval_required_event(
        cls, request: Dict[str, Any]
    ) -> Dict[str, str]:
        """Approval gate triggered."""
        return cls._make_event("approval_required", {"request": request})

    @classmethod
    def complete_event(cls, summary: str, phase: str) -> Dict[str, str]:
        """Agent completed successfully."""
        return cls._make_event("complete", {"summary": summary[:500], "phase": phase})

    @classmethod
    def error_event(cls, error_message: str) -> Dict[str, str]:
        """Agent encountered an unrecoverable error."""
        return cls._make_event("error", {"error": error_message[:500]})

    @classmethod
    def progress_event(cls, progress: Dict[str, Any]) -> Dict[str, str]:
        """Progress update (steps completed, percentage, etc.)."""
        return cls._make_event("progress", progress)

    @classmethod
    async def stream_state_updates(
        cls,
        state_updates: AsyncIterator[Dict[str, Any]],
    ) -> AsyncIterator[Dict[str, str]]:
        """
        Convert raw LangGraph state chunks into SSE events.

        Args:
            state_updates: Async iterator of state dicts from graph.astream()

        Yields:
            SSE event dicts suitable for EventSourceResponse
        """
        async for chunk in state_updates:
            for node_name, state in chunk.items():
                if not isinstance(state, dict):
                    continue

                # Emit thought if present
                messages = state.get("messages", [])
                for msg in messages:
                    content = getattr(msg, "content", "")
                    if content.startswith("THOUGHT:"):
                        thought = content.replace("THOUGHT:", "", 1).strip()
                        yield cls.thought_event(
                            thought, state.get("current_phase", "unknown")
                        )
                    elif content.startswith("Tool output:"):
                        tool_out = content.replace("Tool output:", "", 1).strip()
                        selected = state.get("selected_tool", "tool")
                        yield cls.observation_event(selected, tool_out)

                # Emit action
                if state.get("selected_tool") and state.get("next_action") == "act":
                    yield cls.action_event(
                        state["selected_tool"],
                        state.get("tool_input") or {},
                    )

                # Emit approval required
                if state.get("pending_approval"):
                    approval = state["pending_approval"]
                    if approval.get("status") == "pending":
                        yield cls.approval_required_event(approval)

                # Emit progress if present
                if state.get("progress"):
                    yield cls.progress_event(state["progress"])

                # Emit complete
                if state.get("should_stop") and state.get("next_action") == "end":
                    msgs = state.get("messages", [])
                    last_msg = msgs[-1] if msgs else None
                    summary = getattr(last_msg, "content", "Task complete.")
                    yield cls.complete_event(
                        summary, str(state.get("current_phase", "complete"))
                    )


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class AgentWebSocketHandler:
    """
    Handles bidirectional agent communication over WebSocket.

    Sends real-time events to the client and processes incoming messages
    (user guidance, approval decisions, stop requests).
    """

    def __init__(self, connection_manager=None):
        """
        Args:
            connection_manager: Optional ConnectionManager from websocket.manager.
                If None, falls back to module-level singleton.
        """
        self._cm = connection_manager

    def _get_manager(self):
        if self._cm:
            return self._cm
        from app.websocket.manager import connection_manager
        return connection_manager

    async def stream_agent_events(
        self,
        project_id: str,
        thread_id: str,
        state_updates: AsyncIterator[Dict[str, Any]],
    ) -> None:
        """
        Stream agent execution events to all WebSocket clients in *project_id*.

        Args:
            project_id: Project room to broadcast to
            thread_id: Agent thread identifier (included in all events)
            state_updates: Async iterator from graph.astream()
        """
        cm = self._get_manager()
        streamer = AgentSSEStreamer()

        async for event in streamer.stream_state_updates(state_updates):
            message = {
                "event_type": event["event"],
                "thread_id": thread_id,
                **json.loads(event["data"]),
            }
            await cm.broadcast_to_project(message, project_id)

    async def send_approval_request(
        self,
        project_id: str,
        thread_id: str,
        approval_request: Dict[str, Any],
    ) -> None:
        """
        Broadcast an approval request to all clients in *project_id*.

        Args:
            project_id: Project room
            thread_id: Agent thread
            approval_request: Approval request dict from ApprovalWorkflow
        """
        cm = self._get_manager()
        await cm.send_approval_request(project_id, approval_request, thread_id)
        logger.info(
            f"Approval request {approval_request.get('request_id')} "
            f"broadcast to project {project_id}"
        )

    async def handle_incoming_message(
        self,
        message: Dict[str, Any],
        approval_workflow: ApprovalWorkflow,
        stop_manager: StopResumeManager,
    ) -> Optional[Dict[str, Any]]:
        """
        Process an incoming WebSocket message from the client.

        Supported message types:
          - ``"approve"`` — resolve a pending approval (approved=True)
          - ``"reject"``  — resolve a pending approval (approved=False)
          - ``"stop"``    — request agent stop
          - ``"guidance"``— inject live guidance into the agent state

        Args:
            message: Parsed JSON message from client
            approval_workflow: Active ApprovalWorkflow instance
            stop_manager: Active StopResumeManager instance

        Returns:
            Dict describing the result, or None for unrecognised messages
        """
        msg_type = message.get("type", "")

        if msg_type == "approve":
            request_id = message.get("request_id", "")
            result = approval_workflow.resolve_approval(request_id, approved=True)
            return {"action": "approved", "request_id": request_id, "result": result}

        elif msg_type == "reject":
            request_id = message.get("request_id", "")
            result = approval_workflow.resolve_approval(request_id, approved=False)
            return {"action": "rejected", "request_id": request_id, "result": result}

        elif msg_type == "stop":
            thread_id = message.get("thread_id", "")
            return {"action": "stop_requested", "thread_id": thread_id}

        elif msg_type == "guidance":
            return {
                "action": "guidance_received",
                "thread_id": message.get("thread_id", ""),
                "guidance": message.get("guidance", ""),
            }

        logger.debug(f"Unrecognised WebSocket message type: {msg_type}")
        return None


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class AgentSession:
    """Represents a single agent session."""

    def __init__(
        self,
        session_id: str,
        thread_id: str,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self.session_id = session_id
        self.thread_id = thread_id
        self.project_id = project_id
        self.user_id = user_id
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.last_active = self.created_at
        self.is_active = True
        self.metadata: Dict[str, Any] = {}

    def touch(self) -> None:
        """Update last_active timestamp."""
        self.last_active = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "thread_id": self.thread_id,
            "project_id": self.project_id,
            "user_id": self.user_id,
            "created_at": self.created_at,
            "last_active": self.last_active,
            "is_active": self.is_active,
            "metadata": self.metadata,
        }


class AgentSessionManager:
    """
    Manages agent session lifecycle: creation, lookup, and cleanup.

    Sessions tie together a thread_id, project_id, and user_id so that
    the front-end can reconnect to an existing conversation.
    """

    def __init__(self, max_sessions_per_user: int = 10, ttl_seconds: int = 3600):
        """
        Args:
            max_sessions_per_user: Maximum concurrent sessions per user.
            ttl_seconds: Idle session TTL in seconds (default 1 hour).
        """
        self.max_sessions_per_user = max_sessions_per_user
        self.ttl_seconds = ttl_seconds
        self._sessions: Dict[str, AgentSession] = {}  # session_id → session
        self._thread_map: Dict[str, str] = {}          # thread_id → session_id

    def create_session(
        self,
        thread_id: Optional[str] = None,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> AgentSession:
        """
        Create a new agent session.

        Args:
            thread_id: Optional existing thread ID (auto-generated if not provided)
            project_id: Project context
            user_id: Owning user

        Returns:
            New AgentSession
        """
        session_id = str(uuid.uuid4())
        if not thread_id:
            thread_id = str(uuid.uuid4())

        session = AgentSession(
            session_id=session_id,
            thread_id=thread_id,
            project_id=project_id,
            user_id=user_id,
        )
        self._sessions[session_id] = session
        self._thread_map[thread_id] = session_id
        logger.info(f"Session created: {session_id} (thread={thread_id})")
        return session

    def get_session(self, session_id: str) -> Optional[AgentSession]:
        """Look up a session by session_id."""
        session = self._sessions.get(session_id)
        if session:
            session.touch()
        return session

    def get_session_by_thread(self, thread_id: str) -> Optional[AgentSession]:
        """Look up a session by thread_id."""
        session_id = self._thread_map.get(thread_id)
        if session_id:
            return self.get_session(session_id)
        return None

    def list_sessions(
        self,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        active_only: bool = True,
    ) -> List[AgentSession]:
        """
        List sessions with optional filters.

        Args:
            user_id: Filter by user
            project_id: Filter by project
            active_only: If True, return only active sessions

        Returns:
            List of matching AgentSession objects
        """
        results = list(self._sessions.values())
        if active_only:
            results = [s for s in results if s.is_active]
        if user_id:
            results = [s for s in results if s.user_id == user_id]
        if project_id:
            results = [s for s in results if s.project_id == project_id]
        return results

    def close_session(self, session_id: str) -> bool:
        """
        Mark a session as inactive.

        Args:
            session_id: Session to close

        Returns:
            True if the session was found and closed
        """
        session = self._sessions.get(session_id)
        if not session:
            return False
        session.is_active = False
        session.touch()
        logger.info(f"Session closed: {session_id}")
        return True

    def cleanup_expired(self) -> int:
        """
        Remove sessions that have been idle longer than ``ttl_seconds``.

        Returns:
            Number of sessions removed
        """
        from datetime import timedelta

        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.ttl_seconds)
        expired = []
        for sid, session in self._sessions.items():
            last_str = session.last_active
            last = datetime.fromisoformat(last_str)
            # Make timezone-aware if needed
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            if last < cutoff:
                expired.append(sid)

        for sid in expired:
            session = self._sessions.pop(sid)
            self._thread_map.pop(session.thread_id, None)

        if expired:
            logger.info(f"Cleaned up {len(expired)} expired sessions")
        return len(expired)

    def get_stats(self) -> Dict[str, Any]:
        """Return session statistics."""
        all_sessions = list(self._sessions.values())
        return {
            "total_sessions": len(all_sessions),
            "active_sessions": sum(1 for s in all_sessions if s.is_active),
            "inactive_sessions": sum(1 for s in all_sessions if not s.is_active),
        }


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class AuditAction(str, Enum):
    """Standardised audit event action types."""
    AGENT_START = "agent_start"
    AGENT_STOP = "agent_stop"
    AGENT_RESUME = "agent_resume"
    PHASE_CHANGE = "phase_change"
    TOOL_SELECTED = "tool_selected"
    TOOL_EXECUTED = "tool_executed"
    TOOL_FAILED = "tool_failed"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_REJECTED = "approval_rejected"
    USER_GUIDANCE = "user_guidance"
    SESSION_CREATED = "session_created"
    SESSION_CLOSED = "session_closed"
    FINDING_RECORDED = "finding_recorded"
    CREDENTIAL_FOUND = "credential_found"


class AgentAuditLogger:
    """
    Comprehensive audit logger for all agent actions and decisions.

    Records an immutable ordered log of every significant event during
    an agent run so that the full engagement can be replayed or reviewed.
    """

    def __init__(self, thread_id: Optional[str] = None):
        self.thread_id = thread_id or ""
        self._log: List[Dict[str, Any]] = []

    def _record(
        self,
        action: AuditAction,
        details: Dict[str, Any],
        actor: str = "agent",
        severity: str = "info",
    ) -> Dict[str, Any]:
        """Write a single audit entry."""
        entry = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "thread_id": self.thread_id,
            "actor": actor,
            "action": action.value,
            "severity": severity,
            **details,
        }
        self._log.append(entry)
        logger.info(f"[AUDIT] {action.value}: {json.dumps(details)[:200]}")
        return entry

    # ── Convenience methods ─────────────────────────────────────────────────

    def log_agent_start(self, phase: str, project_id: Optional[str] = None) -> None:
        self._record(
            AuditAction.AGENT_START,
            {"phase": phase, "project_id": project_id},
        )

    def log_agent_stop(self, reason: str = "user_requested") -> None:
        self._record(AuditAction.AGENT_STOP, {"reason": reason}, severity="warning")

    def log_agent_resume(self, message: Optional[str] = None) -> None:
        self._record(AuditAction.AGENT_RESUME, {"message": message})

    def log_phase_change(self, old_phase: str, new_phase: str) -> None:
        self._record(
            AuditAction.PHASE_CHANGE,
            {"from_phase": old_phase, "to_phase": new_phase},
            severity="info",
        )

    def log_tool_selected(self, tool_name: str, tool_input: Dict[str, Any]) -> None:
        self._record(
            AuditAction.TOOL_SELECTED,
            {"tool": tool_name, "input_summary": str(tool_input)[:300]},
        )

    def log_tool_executed(
        self,
        tool_name: str,
        output_preview: str,
        duration_ms: Optional[float] = None,
    ) -> None:
        self._record(
            AuditAction.TOOL_EXECUTED,
            {
                "tool": tool_name,
                "output_preview": output_preview[:200],
                "duration_ms": duration_ms,
            },
        )

    def log_tool_failed(
        self,
        tool_name: str,
        error: str,
        attempt: int = 1,
    ) -> None:
        self._record(
            AuditAction.TOOL_FAILED,
            {"tool": tool_name, "error": error[:300], "attempt": attempt},
            severity="error",
        )

    def log_approval_requested(self, request: Dict[str, Any]) -> None:
        self._record(
            AuditAction.APPROVAL_REQUESTED,
            {
                "request_id": request.get("request_id"),
                "tool": request.get("tool"),
                "danger_level": request.get("danger_level"),
            },
            severity="warning",
        )

    def log_approval_decision(
        self, request_id: str, approved: bool, actor: str = "user"
    ) -> None:
        action = AuditAction.APPROVAL_GRANTED if approved else AuditAction.APPROVAL_REJECTED
        self._record(
            action,
            {"request_id": request_id},
            actor=actor,
            severity="info" if approved else "warning",
        )

    def log_user_guidance(self, guidance: str) -> None:
        self._record(
            AuditAction.USER_GUIDANCE,
            {"guidance": guidance[:500]},
            actor="user",
        )

    def log_finding(
        self,
        finding_type: str,
        target: str,
        severity: str,
        details: Optional[str] = None,
    ) -> None:
        self._record(
            AuditAction.FINDING_RECORDED,
            {
                "finding_type": finding_type,
                "target": target,
                "severity": severity,
                "details": (details or "")[:300],
            },
            severity=severity,
        )

    def log_credential_found(
        self,
        credential_type: str,
        target: str,
        username: Optional[str] = None,
    ) -> None:
        self._record(
            AuditAction.CREDENTIAL_FOUND,
            {
                "credential_type": credential_type,
                "target": target,
                "username": username,
                # Password intentionally omitted from audit log for security
            },
            severity="critical",
        )

    # ── Log access ──────────────────────────────────────────────────────────

    def get_log(self) -> List[Dict[str, Any]]:
        """Return the full audit log."""
        return list(self._log)

    def get_log_by_action(self, action: AuditAction) -> List[Dict[str, Any]]:
        """Filter log by action type."""
        return [e for e in self._log if e["action"] == action.value]

    def get_tool_executions(self) -> List[Dict[str, Any]]:
        """Return all tool execution entries."""
        return self.get_log_by_action(AuditAction.TOOL_EXECUTED)

    def get_findings(self) -> List[Dict[str, Any]]:
        """Return all finding entries."""
        return self.get_log_by_action(AuditAction.FINDING_RECORDED)

    def summarise(self) -> Dict[str, Any]:
        """
        Produce a high-level summary of the audit log.

        Returns:
            Dict with counts of key event types
        """
        tools_used: Dict[str, int] = {}
        for entry in self.get_tool_executions():
            name = entry.get("tool", "unknown")
            tools_used[name] = tools_used.get(name, 0) + 1

        return {
            "thread_id": self.thread_id,
            "total_events": len(self._log),
            "tool_executions": len(self.get_tool_executions()),
            "tools_used": tools_used,
            "findings": len(self.get_findings()),
            "approvals_requested": len(self.get_log_by_action(AuditAction.APPROVAL_REQUESTED)),
            "approvals_granted": len(self.get_log_by_action(AuditAction.APPROVAL_GRANTED)),
            "approvals_rejected": len(self.get_log_by_action(AuditAction.APPROVAL_REJECTED)),
            "failures": len(self.get_log_by_action(AuditAction.TOOL_FAILED)),
        }
