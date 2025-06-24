"""
Tests for Week 16 — Safety & Streaming.

Covers:
"""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, Mock, patch
from langchain_core.messages import AIMessage, HumanMessage

from app.agent.session_manager import (
    DangerLevel,
    ApprovalWorkflow,
    StopResumeManager,
    AgentSSEStreamer,
    AgentWebSocketHandler,
    AgentSession,
    AgentSessionManager,
    AgentAuditLogger,
    AuditAction,
    TOOL_DANGER_MAP,
)
from app.agent.state.agent_state import Phase
from app.agent.testing import build_initial_state


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class TestDangerLevelClassification:
    def test_safe_tools(self):
        wf = ApprovalWorkflow()
        assert wf.classify_tool("echo") == DangerLevel.SAFE
        assert wf.classify_tool("query_graph") == DangerLevel.SAFE

    def test_low_risk_tools(self):
        wf = ApprovalWorkflow()
        assert wf.classify_tool("port_scan") == DangerLevel.LOW
        assert wf.classify_tool("web_search") == DangerLevel.LOW

    def test_high_risk_tools(self):
        wf = ApprovalWorkflow()
        assert wf.classify_tool("brute_force") == DangerLevel.HIGH

    def test_critical_tools(self):
        wf = ApprovalWorkflow()
        assert wf.classify_tool("exploit_execute") == DangerLevel.CRITICAL
        assert wf.classify_tool("file_operations") == DangerLevel.CRITICAL

    def test_unknown_tool_defaults_medium(self):
        wf = ApprovalWorkflow()
        assert wf.classify_tool("completely_unknown_tool") == DangerLevel.MEDIUM

    def test_custom_override(self):
        wf = ApprovalWorkflow(custom_tool_map={"port_scan": DangerLevel.SAFE})
        assert wf.classify_tool("port_scan") == DangerLevel.SAFE

    def test_all_mapped_tools_are_valid_danger_levels(self):
        wf = ApprovalWorkflow()
        for tool_name in TOOL_DANGER_MAP:
            level = wf.classify_tool(tool_name)
            assert isinstance(level, DangerLevel)


class TestApprovalWorkflowRequires:
    def test_safe_does_not_require_approval(self):
        wf = ApprovalWorkflow(require_approval_from=DangerLevel.HIGH)
        assert wf.requires_approval("echo") is False
        assert wf.requires_approval("port_scan") is False

    def test_high_requires_approval(self):
        wf = ApprovalWorkflow(require_approval_from=DangerLevel.HIGH)
        assert wf.requires_approval("brute_force") is True
        assert wf.requires_approval("exploit_execute") is True

    def test_critical_always_requires(self):
        wf = ApprovalWorkflow(require_approval_from=DangerLevel.HIGH)
        assert wf.requires_approval("privilege_escalation") is True

    def test_threshold_medium_catches_more(self):
        wf = ApprovalWorkflow(require_approval_from=DangerLevel.MEDIUM)
        assert wf.requires_approval("nuclei_scan") is True
        assert wf.requires_approval("port_scan") is False


class TestApprovalWorkflowRequests:
    def test_create_approval_request(self):
        wf = ApprovalWorkflow()
        req = wf.create_approval_request(
            tool_name="exploit_execute",
            tool_input={"module_path": "exploit/unix/ftp/vsftpd", "rhosts": "10.0.0.1"},
            thread_id="thread-1",
            project_id="proj-1",
        )
        assert req["tool"] == "exploit_execute"
        assert req["status"] == "pending"
        assert "request_id" in req
        assert req["danger_level"] == DangerLevel.CRITICAL.value

    def test_resolve_approval_granted(self):
        wf = ApprovalWorkflow()
        req = wf.create_approval_request("exploit_execute", {}, "t-1")
        resolved = wf.resolve_approval(req["request_id"], approved=True)
        assert resolved["status"] == "approved"

    def test_resolve_approval_rejected(self):
        wf = ApprovalWorkflow()
        req = wf.create_approval_request("exploit_execute", {}, "t-1")
        resolved = wf.resolve_approval(req["request_id"], approved=False)
        assert resolved["status"] == "rejected"

    def test_resolve_nonexistent_returns_none(self):
        wf = ApprovalWorkflow()
        result = wf.resolve_approval("nonexistent-id", approved=True)
        assert result is None

    def test_get_pending_requests(self):
        wf = ApprovalWorkflow()
        wf.create_approval_request("exploit_execute", {}, "t-1")
        wf.create_approval_request("brute_force", {}, "t-2")
        pending = wf.get_pending_requests()
        assert len(pending) == 2

    def test_pending_cleared_after_resolve(self):
        wf = ApprovalWorkflow()
        req = wf.create_approval_request("exploit_execute", {}, "t-1")
        wf.resolve_approval(req["request_id"], approved=True)
        assert len(wf.get_pending_requests()) == 0

    def test_set_tool_danger(self):
        wf = ApprovalWorkflow()
        wf.set_tool_danger("echo", DangerLevel.CRITICAL)
        assert wf.classify_tool("echo") == DangerLevel.CRITICAL


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class TestStopResumeManager:
    def test_save_checkpoint(self):
        mgr = StopResumeManager()
        state = build_initial_state(thread_id="t-1")
        mgr.save_checkpoint("t-1", state)
        cp = mgr.get_checkpoint("t-1")
        assert cp is not None
        assert "_checkpoint_time" in cp

    def test_stop_sets_should_stop(self):
        mgr = StopResumeManager()
        state = build_initial_state(thread_id="t-1")
        updated = mgr.stop_agent("t-1", state)
        assert updated["should_stop"] is True
        assert updated["next_action"] == "end"

    def test_stop_marks_thread_as_stopped(self):
        mgr = StopResumeManager()
        state = build_initial_state(thread_id="t-1")
        mgr.stop_agent("t-1", state)
        assert mgr.is_stopped("t-1") is True

    def test_resume_restores_state(self):
        mgr = StopResumeManager()
        state = build_initial_state(thread_id="t-1", phase=Phase.EXPLOITATION)
        mgr.stop_agent("t-1", state)
        restored = mgr.resume_agent("t-1")
        assert restored is not None
        assert restored["should_stop"] is False
        assert restored["next_action"] == "think"

    def test_resume_injects_message(self):
        mgr = StopResumeManager()
        state = build_initial_state(thread_id="t-1")
        mgr.stop_agent("t-1", state)
        restored = mgr.resume_agent("t-1", message="Continue scanning port 8080")
        messages = restored["messages"]
        assert any(
            "Continue scanning" in getattr(m, "content", "")
            for m in messages
        )

    def test_resume_no_checkpoint_returns_none(self):
        mgr = StopResumeManager()
        result = mgr.resume_agent("nonexistent")
        assert result is None

    def test_resume_clears_stopped_flag(self):
        mgr = StopResumeManager()
        state = build_initial_state(thread_id="t-1")
        mgr.stop_agent("t-1", state)
        mgr.resume_agent("t-1")
        assert mgr.is_stopped("t-1") is False

    def test_clear_checkpoint(self):
        mgr = StopResumeManager()
        state = build_initial_state(thread_id="t-1")
        mgr.save_checkpoint("t-1", state)
        mgr.clear_checkpoint("t-1")
        assert mgr.get_checkpoint("t-1") is None

    def test_list_stopped_threads(self):
        mgr = StopResumeManager()
        for tid in ["t-1", "t-2", "t-3"]:
            mgr.stop_agent(tid, build_initial_state(thread_id=tid))
        stopped = mgr.list_stopped_threads()
        assert set(stopped) == {"t-1", "t-2", "t-3"}

    def test_is_not_stopped_by_default(self):
        mgr = StopResumeManager()
        assert mgr.is_stopped("unknown-thread") is False


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class TestAgentSSEStreamer:
    def test_thought_event_structure(self):
        event = AgentSSEStreamer.thought_event("I should scan port 80", "informational")
        assert event["event"] == "thought"
        data = json.loads(event["data"])
        assert "I should scan port 80" in data["thought"]
        assert "timestamp" in data

    def test_action_event_structure(self):
        event = AgentSSEStreamer.action_event("naabu_scan", {"target": "10.0.0.1"})
        assert event["event"] == "action"
        data = json.loads(event["data"])
        assert data["tool"] == "naabu_scan"

    def test_observation_event_structure(self):
        event = AgentSSEStreamer.observation_event("naabu_scan", "Port 80 open")
        assert event["event"] == "observation"
        data = json.loads(event["data"])
        assert "Port 80 open" in data["output_preview"]

    def test_phase_change_event(self):
        event = AgentSSEStreamer.phase_change_event("informational", "exploitation")
        data = json.loads(event["data"])
        assert data["from"] == "informational"
        assert data["to"] == "exploitation"

    def test_approval_required_event(self):
        req = {"request_id": "r1", "tool": "exploit_execute", "status": "pending"}
        event = AgentSSEStreamer.approval_required_event(req)
        assert event["event"] == "approval_required"
        data = json.loads(event["data"])
        assert data["request"]["tool"] == "exploit_execute"

    def test_complete_event(self):
        event = AgentSSEStreamer.complete_event("Scan finished successfully.", "complete")
        assert event["event"] == "complete"
        data = json.loads(event["data"])
        assert "Scan finished" in data["summary"]

    def test_error_event(self):
        event = AgentSSEStreamer.error_event("Unrecoverable failure")
        assert event["event"] == "error"
        data = json.loads(event["data"])
        assert "Unrecoverable" in data["error"]

    def test_progress_event(self):
        event = AgentSSEStreamer.progress_event({"steps_done": 3, "total_steps": 10})
        assert event["event"] == "progress"
        data = json.loads(event["data"])
        assert data["steps_done"] == 3

    def test_stream_state_updates_thought(self):
        async def fake_stream():
            yield {
                "think": {
                    "messages": [AIMessage(content="THOUGHT: scanning now")],
                    "current_phase": "informational",
                    "next_action": "think",
                }
            }

        events = []

        async def collect():
            async for evt in AgentSSEStreamer.stream_state_updates(fake_stream()):
                events.append(evt)

        run(collect())
        assert any(e["event"] == "thought" for e in events)

    def test_stream_state_updates_complete(self):
        async def fake_stream():
            yield {
                "observe": {
                    "messages": [AIMessage(content="Task complete.")],
                    "should_stop": True,
                    "next_action": "end",
                    "current_phase": "complete",
                }
            }

        events = []

        async def collect():
            async for evt in AgentSSEStreamer.stream_state_updates(fake_stream()):
                events.append(evt)

        run(collect())
        assert any(e["event"] == "complete" for e in events)


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class TestAgentWebSocketHandler:
    def _mock_cm(self):
        cm = Mock()
        cm.broadcast_to_project = AsyncMock()
        cm.send_approval_request = AsyncMock()
        return cm

    def test_send_approval_request(self):
        cm = self._mock_cm()
        handler = AgentWebSocketHandler(connection_manager=cm)
        req = {"request_id": "r1", "tool": "exploit_execute", "status": "pending"}
        run(handler.send_approval_request("proj-1", "t-1", req))
        cm.send_approval_request.assert_called_once()

    def test_handle_approve_message(self):
        wf = ApprovalWorkflow()
        req = wf.create_approval_request("exploit_execute", {}, "t-1")
        mgr = StopResumeManager()
        handler = AgentWebSocketHandler()
        msg = {"type": "approve", "request_id": req["request_id"]}
        result = run(handler.handle_incoming_message(msg, wf, mgr))
        assert result["action"] == "approved"

    def test_handle_reject_message(self):
        wf = ApprovalWorkflow()
        req = wf.create_approval_request("exploit_execute", {}, "t-1")
        mgr = StopResumeManager()
        handler = AgentWebSocketHandler()
        msg = {"type": "reject", "request_id": req["request_id"]}
        result = run(handler.handle_incoming_message(msg, wf, mgr))
        assert result["action"] == "rejected"

    def test_handle_stop_message(self):
        wf = ApprovalWorkflow()
        mgr = StopResumeManager()
        handler = AgentWebSocketHandler()
        msg = {"type": "stop", "thread_id": "t-1"}
        result = run(handler.handle_incoming_message(msg, wf, mgr))
        assert result["action"] == "stop_requested"
        assert result["thread_id"] == "t-1"

    def test_handle_guidance_message(self):
        wf = ApprovalWorkflow()
        mgr = StopResumeManager()
        handler = AgentWebSocketHandler()
        msg = {"type": "guidance", "thread_id": "t-1", "guidance": "Focus on port 8080"}
        result = run(handler.handle_incoming_message(msg, wf, mgr))
        assert result["action"] == "guidance_received"
        assert "8080" in result["guidance"]

    def test_handle_unknown_message_returns_none(self):
        wf = ApprovalWorkflow()
        mgr = StopResumeManager()
        handler = AgentWebSocketHandler()
        result = run(handler.handle_incoming_message({"type": "unknown"}, wf, mgr))
        assert result is None

    def test_stream_agent_events_broadcasts(self):
        cm = self._mock_cm()
        handler = AgentWebSocketHandler(connection_manager=cm)

        async def fake_stream():
            yield {
                "think": {
                    "messages": [AIMessage(content="THOUGHT: starting")],
                    "current_phase": "informational",
                    "next_action": "think",
                }
            }

        run(handler.stream_agent_events("proj-1", "t-1", fake_stream()))
        cm.broadcast_to_project.assert_called()


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class TestAgentSessionManager:
    def test_create_session_generates_ids(self):
        mgr = AgentSessionManager()
        session = mgr.create_session(project_id="proj-1", user_id="user-1")
        assert session.session_id
        assert session.thread_id
        assert session.project_id == "proj-1"
        assert session.is_active is True

    def test_create_with_existing_thread(self):
        mgr = AgentSessionManager()
        session = mgr.create_session(thread_id="my-thread")
        assert session.thread_id == "my-thread"

    def test_get_session(self):
        mgr = AgentSessionManager()
        session = mgr.create_session()
        fetched = mgr.get_session(session.session_id)
        assert fetched is not None
        assert fetched.session_id == session.session_id

    def test_get_session_not_found(self):
        mgr = AgentSessionManager()
        assert mgr.get_session("nonexistent") is None

    def test_get_session_by_thread(self):
        mgr = AgentSessionManager()
        session = mgr.create_session(thread_id="t-abc")
        fetched = mgr.get_session_by_thread("t-abc")
        assert fetched.session_id == session.session_id

    def test_list_active_sessions(self):
        mgr = AgentSessionManager()
        s1 = mgr.create_session(user_id="u1", project_id="p1")
        s2 = mgr.create_session(user_id="u1", project_id="p1")
        sessions = mgr.list_sessions(user_id="u1", active_only=True)
        assert len(sessions) == 2

    def test_list_sessions_filters_by_project(self):
        mgr = AgentSessionManager()
        mgr.create_session(project_id="proj-A")
        mgr.create_session(project_id="proj-B")
        result = mgr.list_sessions(project_id="proj-A")
        assert all(s.project_id == "proj-A" for s in result)

    def test_close_session(self):
        mgr = AgentSessionManager()
        session = mgr.create_session()
        closed = mgr.close_session(session.session_id)
        assert closed is True
        fetched = mgr.get_session(session.session_id)
        assert fetched.is_active is False

    def test_close_nonexistent_session(self):
        mgr = AgentSessionManager()
        assert mgr.close_session("nonexistent") is False

    def test_cleanup_expired(self):
        import time
        mgr = AgentSessionManager(ttl_seconds=0)  # All sessions expire immediately
        mgr.create_session()
        # Force last_active to be in the past by sleeping a tiny bit
        import datetime
        session = list(mgr._sessions.values())[0]
        session.last_active = (
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(seconds=1)
        ).isoformat()
        removed = mgr.cleanup_expired()
        assert removed == 1

    def test_get_stats(self):
        mgr = AgentSessionManager()
        s1 = mgr.create_session()
        s2 = mgr.create_session()
        mgr.close_session(s1.session_id)
        stats = mgr.get_stats()
        assert stats["total_sessions"] == 2
        assert stats["active_sessions"] == 1
        assert stats["inactive_sessions"] == 1


class TestAgentSession:
    def test_to_dict(self):
        session = AgentSession("sid", "tid", project_id="p1", user_id="u1")
        d = session.to_dict()
        assert d["session_id"] == "sid"
        assert d["thread_id"] == "tid"
        assert d["project_id"] == "p1"

    def test_touch_updates_last_active(self):
        import time
        session = AgentSession("sid", "tid")
        original = session.last_active
        time.sleep(0.01)
        session.touch()
        assert session.last_active > original


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class TestAgentAuditLogger:
    def test_log_agent_start(self):
        logger = AgentAuditLogger(thread_id="t-1")
        logger.log_agent_start("informational", project_id="p-1")
        log = logger.get_log()
        assert len(log) == 1
        assert log[0]["action"] == AuditAction.AGENT_START.value

    def test_log_agent_stop(self):
        logger = AgentAuditLogger()
        logger.log_agent_stop("user_requested")
        entries = logger.get_log_by_action(AuditAction.AGENT_STOP)
        assert len(entries) == 1

    def test_log_agent_resume(self):
        logger = AgentAuditLogger()
        logger.log_agent_resume("Continue from checkpoint")
        entries = logger.get_log_by_action(AuditAction.AGENT_RESUME)
        assert len(entries) == 1

    def test_log_phase_change(self):
        logger = AgentAuditLogger()
        logger.log_phase_change("informational", "exploitation")
        entries = logger.get_log_by_action(AuditAction.PHASE_CHANGE)
        assert entries[0]["from_phase"] == "informational"
        assert entries[0]["to_phase"] == "exploitation"

    def test_log_tool_selected(self):
        logger = AgentAuditLogger()
        logger.log_tool_selected("naabu_scan", {"target": "10.0.0.1"})
        entries = logger.get_log_by_action(AuditAction.TOOL_SELECTED)
        assert entries[0]["tool"] == "naabu_scan"

    def test_log_tool_executed(self):
        logger = AgentAuditLogger()
        logger.log_tool_executed("naabu_scan", "Port 80 open", duration_ms=1234.5)
        execs = logger.get_tool_executions()
        assert len(execs) == 1
        assert execs[0]["tool"] == "naabu_scan"

    def test_log_tool_failed(self):
        logger = AgentAuditLogger()
        logger.log_tool_failed("nuclei_scan", "Connection refused", attempt=2)
        entries = logger.get_log_by_action(AuditAction.TOOL_FAILED)
        assert entries[0]["attempt"] == 2

    def test_log_approval_requested(self):
        logger = AgentAuditLogger()
        req = {"request_id": "r1", "tool": "exploit_execute", "danger_level": "critical"}
        logger.log_approval_requested(req)
        entries = logger.get_log_by_action(AuditAction.APPROVAL_REQUESTED)
        assert entries[0]["tool"] == "exploit_execute"

    def test_log_approval_decision_granted(self):
        logger = AgentAuditLogger()
        logger.log_approval_decision("r1", approved=True)
        entries = logger.get_log_by_action(AuditAction.APPROVAL_GRANTED)
        assert len(entries) == 1

    def test_log_approval_decision_rejected(self):
        logger = AgentAuditLogger()
        logger.log_approval_decision("r1", approved=False)
        entries = logger.get_log_by_action(AuditAction.APPROVAL_REJECTED)
        assert len(entries) == 1

    def test_log_user_guidance(self):
        logger = AgentAuditLogger()
        logger.log_user_guidance("Focus on port 8080")
        entries = logger.get_log_by_action(AuditAction.USER_GUIDANCE)
        assert "8080" in entries[0]["guidance"]

    def test_log_finding(self):
        logger = AgentAuditLogger()
        logger.log_finding("sqli", "https://example.com/login", "critical", "Error-based SQLi")
        findings = logger.get_findings()
        assert len(findings) == 1
        assert findings[0]["target"] == "https://example.com/login"

    def test_log_credential_found(self):
        logger = AgentAuditLogger()
        logger.log_credential_found("ssh", "10.0.0.1", username="admin")
        entries = logger.get_log_by_action(AuditAction.CREDENTIAL_FOUND)
        assert entries[0]["username"] == "admin"
        # Ensure password is NOT logged
        entry_str = json.dumps(entries[0])
        assert "password" not in entry_str.lower()

    def test_summarise(self):
        logger = AgentAuditLogger(thread_id="t-1")
        logger.log_agent_start("informational")
        logger.log_tool_selected("naabu_scan", {})
        logger.log_tool_executed("naabu_scan", "port 80 open")
        logger.log_tool_executed("nuclei_scan", "XSS found")
        logger.log_tool_failed("naabu_scan", "timeout")
        logger.log_finding("xss", "https://example.com", "high")
        req = {"request_id": "r1", "tool": "exploit_execute", "danger_level": "critical"}
        logger.log_approval_requested(req)
        logger.log_approval_decision("r1", approved=True)

        summary = logger.summarise()
        assert summary["thread_id"] == "t-1"
        assert summary["tool_executions"] == 2
        assert summary["findings"] == 1
        assert summary["approvals_requested"] == 1
        assert summary["approvals_granted"] == 1
        assert summary["failures"] == 1
        assert "naabu_scan" in summary["tools_used"]

    def test_get_log_all_entries_ordered(self):
        logger = AgentAuditLogger()
        logger.log_agent_start("informational")
        logger.log_phase_change("informational", "exploitation")
        logger.log_agent_stop()
        log = logger.get_log()
        assert len(log) == 3
        # Should be in insertion order
        assert log[0]["action"] == AuditAction.AGENT_START.value
        assert log[2]["action"] == AuditAction.AGENT_STOP.value

    def test_thread_id_in_all_entries(self):
        logger = AgentAuditLogger(thread_id="test-thread-42")
        logger.log_agent_start("informational")
        logger.log_tool_executed("naabu_scan", "done")
        for entry in logger.get_log():
            assert entry["thread_id"] == "test-thread-42"
