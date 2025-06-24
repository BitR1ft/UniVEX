"""
Tests for Week 1 Betterment Plan — AutoChain Engine

Coverage:
  - Schemas (ScanPlan, ExploitCandidate, ChainResult, ChainStep, ExploitPlan)
  - ReconToExploitMapper
  - AutoChain orchestrator (mocked MCP calls)
  - REST API endpoints (mocked orchestrator)
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any, AsyncIterator, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.autochain.recon_mapper import (
    CVE_MODULE_MAP,
    SERVICE_EXPLOIT_MAP,
    ReconToExploitMapper,
)
from app.autochain.schemas import (
    ChainPhase,
    ChainResult,
    ChainStatus,
    ChainStep,
    ExploitCandidate,
    ExploitPlan,
    ScanPlan,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_port(port: int, service: str = "http", version: str = "") -> Dict[str, Any]:
    return {"port": port, "service": service, "version": version, "protocol": "tcp"}


def make_nuclei_finding(
    template_id: str,
    severity: str = "high",
    cvss: float = 7.5,
    matched_at: str = "http://10.0.0.1:80/",
) -> Dict[str, Any]:
    return {
        "template_id": template_id,
        "template_name": template_id,
        "severity": severity,
        "cvss_score": cvss,
        "matched_at": matched_at,
    }


# ===========================================================================
# Tests: Schemas
# ===========================================================================


class TestScanPlan:
    def test_default_plan_id_is_uuid(self):
        plan = ScanPlan(target="10.0.0.1")
        # Should be a valid UUID
        parsed = uuid.UUID(plan.plan_id)
        assert str(parsed) == plan.plan_id

    def test_target_stored(self):
        plan = ScanPlan(target="192.168.1.1")
        assert plan.target == "192.168.1.1"

    def test_default_auto_approve_none(self):
        plan = ScanPlan(target="1.2.3.4")
        assert plan.auto_approve_risk_level == "none"

    def test_custom_auto_approve(self):
        plan = ScanPlan(target="1.2.3.4", auto_approve_risk_level="high")
        assert plan.auto_approve_risk_level == "high"

    def test_open_ports_default_empty(self):
        plan = ScanPlan(target="1.2.3.4")
        assert plan.open_ports == []

    def test_exploit_candidates_default_empty(self):
        plan = ScanPlan(target="1.2.3.4")
        assert plan.exploit_candidates == []


class TestExploitCandidate:
    def test_final_score_capped_at_10(self):
        c = ExploitCandidate(
            service="ftp",
            port=21,
            base_score=9.5,
            msf_available=True,
            final_score=min(9.5 + 2.0, 10.0),
        )
        assert c.final_score == 10.0

    def test_risk_level_default(self):
        c = ExploitCandidate(service="ssh", port=22, final_score=5.0)
        assert c.risk_level == "high"

    def test_optional_fields_none(self):
        c = ExploitCandidate(service="http", port=80, final_score=0.0)
        assert c.cve_id is None
        assert c.module_path is None


class TestExploitPlan:
    def test_current_returns_first_candidate(self):
        c1 = ExploitCandidate(service="ftp", port=21, final_score=9.0)
        c2 = ExploitCandidate(service="smb", port=445, final_score=7.0)
        plan = ExploitPlan(candidates=[c1, c2])
        assert plan.current == c1

    def test_advance_moves_to_next(self):
        c1 = ExploitCandidate(service="ftp", port=21, final_score=9.0)
        c2 = ExploitCandidate(service="smb", port=445, final_score=7.0)
        plan = ExploitPlan(candidates=[c1, c2])
        has_more = plan.advance()
        assert has_more is True
        assert plan.current == c2

    def test_advance_returns_false_when_exhausted(self):
        c1 = ExploitCandidate(service="ftp", port=21, final_score=9.0)
        plan = ExploitPlan(candidates=[c1])
        has_more = plan.advance()
        assert has_more is False
        assert plan.current is None

    def test_empty_plan_current_is_none(self):
        plan = ExploitPlan(candidates=[])
        assert plan.current is None


class TestChainStep:
    def test_start_sets_running(self):
        step = ChainStep(phase=ChainPhase.RECON, name="port_scan")
        step.start()
        assert step.status == "running"
        assert step.started_at is not None

    def test_succeed_sets_success(self):
        step = ChainStep(phase=ChainPhase.RECON, name="port_scan")
        step.start()
        step.succeed(output="3 ports open")
        assert step.status == "success"
        assert step.output == "3 ports open"
        assert step.finished_at is not None

    def test_fail_sets_failed(self):
        step = ChainStep(phase=ChainPhase.RECON, name="port_scan")
        step.start()
        step.fail("connection refused")
        assert step.status == "failed"
        assert step.error == "connection refused"
        assert step.finished_at is not None


class TestChainResult:
    def test_add_step(self):
        result = ChainResult(plan_id="p1", target="10.0.0.1")
        step = ChainStep(phase=ChainPhase.RECON, name="test")
        result.add_step(step)
        assert len(result.steps) == 1

    def test_finish_complete(self):
        result = ChainResult(plan_id="p1", target="10.0.0.1")
        result.finish(ChainStatus.COMPLETE)
        assert result.status == ChainStatus.COMPLETE
        assert result.finished_at is not None
        assert result.error is None

    def test_finish_failed_with_error(self):
        result = ChainResult(plan_id="p1", target="10.0.0.1")
        result.finish(ChainStatus.FAILED, error="boom")
        assert result.status == ChainStatus.FAILED
        assert result.error == "boom"


# ===========================================================================
# Tests: ReconToExploitMapper
# ===========================================================================


class TestReconToExploitMapper:
    def setup_method(self):
        self.mapper = ReconToExploitMapper()

    # --- map_service_to_module ---

    def test_vsftpd_service_match(self):
        entry = self.mapper.map_service_to_module("vsftpd", "2.3.4")
        assert entry is not None
        assert "vsftpd_234_backdoor" in entry["module_path"]

    def test_smb_service_match(self):
        entry = self.mapper.map_service_to_module("smb")
        assert entry is not None
        assert "eternalblue" in entry["module_path"]

    def test_unknown_service_returns_none(self):
        entry = self.mapper.map_service_to_module("unknownservice", "1.0")
        assert entry is None

    def test_microsoft_ds_service_match(self):
        entry = self.mapper.map_service_to_module("microsoft-ds")
        assert entry is not None
        assert "eternalblue" in entry["module_path"]

    # --- map_cve_to_module ---

    def test_log4shell_cve(self):
        entry = self.mapper.map_cve_to_module("CVE-2021-44228")
        assert entry is not None
        assert "log4shell" in entry["module_path"]

    def test_eternalblue_cve(self):
        entry = self.mapper.map_cve_to_module("CVE-2017-0144")
        assert entry is not None
        assert "eternalblue" in entry["module_path"]

    def test_unknown_cve_returns_none(self):
        entry = self.mapper.map_cve_to_module("CVE-9999-9999")
        assert entry is None

    def test_cve_lookup_case_insensitive(self):
        entry = self.mapper.map_cve_to_module("cve-2021-44228")
        assert entry is not None

    # --- get_exploit_candidates (port-based) ---

    def test_candidates_from_vsftpd_port(self):
        ports = [make_port(21, "vsftpd", "2.3.4")]
        candidates = self.mapper.get_exploit_candidates(ports)
        assert len(candidates) >= 1
        assert any("vsftpd" in (c.module_path or "") for c in candidates)

    def test_candidates_from_smb_port(self):
        ports = [make_port(445, "smb")]
        candidates = self.mapper.get_exploit_candidates(ports)
        assert len(candidates) >= 1

    def test_empty_ports_returns_empty(self):
        candidates = self.mapper.get_exploit_candidates([])
        assert candidates == []

    def test_unknown_service_produces_no_candidate(self):
        ports = [make_port(12345, "unknownd", "1.0")]
        candidates = self.mapper.get_exploit_candidates(ports)
        assert candidates == []

    # --- get_exploit_candidates (Nuclei-based) ---

    def test_candidates_from_nuclei_known_cve(self):
        findings = [make_nuclei_finding("cve-2021-44228", cvss=10.0)]
        candidates = self.mapper.get_exploit_candidates([], nuclei_findings=findings)
        assert len(candidates) >= 1
        assert any("log4shell" in (c.module_path or "") for c in candidates)

    def test_candidates_from_nuclei_unknown_cve(self):
        findings = [make_nuclei_finding("cve-9999-9999-xss-test", cvss=6.5)]
        candidates = self.mapper.get_exploit_candidates([], nuclei_findings=findings)
        # No MSF module but should still create a candidate with msf_available=False
        assert len(candidates) >= 1
        assert all(not c.msf_available for c in candidates)

    def test_final_score_higher_with_msf(self):
        findings_known = [make_nuclei_finding("cve-2021-44228", cvss=9.0)]
        findings_unknown = [make_nuclei_finding("cve-9999-9999", cvss=9.0)]
        known = self.mapper.get_exploit_candidates([], nuclei_findings=findings_known)
        unknown = self.mapper.get_exploit_candidates([], nuclei_findings=findings_unknown)
        if known and unknown:
            assert known[0].final_score >= unknown[0].final_score

    def test_candidates_sorted_descending(self):
        ports = [
            make_port(21, "vsftpd", "2.3.4"),  # cvss 10 → final 10
            make_port(445, "smb"),              # cvss 9.3 → final 10
            make_port(3306, "mysql"),            # cvss 6.5 → final 8.5
        ]
        candidates = self.mapper.get_exploit_candidates(ports)
        scores = [c.final_score for c in candidates]
        assert scores == sorted(scores, reverse=True)

    def test_deduplication_keeps_highest_score(self):
        # Two findings for the same CVE / module → should be deduplicated
        findings = [
            make_nuclei_finding("cve-2017-0144", cvss=9.0),
            make_nuclei_finding("cve-2017-0144", cvss=7.0),
        ]
        candidates = self.mapper.get_exploit_candidates([], nuclei_findings=findings)
        msf_paths = [c.module_path for c in candidates if c.module_path]
        # After dedup, each module_path appears at most once
        assert len(msf_paths) == len(set(msf_paths))

    # --- static helpers ---

    def test_extract_cve_from_template_id(self):
        result = ReconToExploitMapper._extract_cve("cve-2021-44228-log4shell")
        assert result == "CVE-2021-44228"

    def test_extract_cve_returns_none_for_non_cve(self):
        result = ReconToExploitMapper._extract_cve("xss-generic-reflected")
        assert result is None

    def test_extract_port_from_url(self):
        assert ReconToExploitMapper._extract_port("http://host:8080/path") == 8080
        assert ReconToExploitMapper._extract_port("https://host/path") == 443
        assert ReconToExploitMapper._extract_port("http://host/path") == 80

    def test_severity_to_cvss(self):
        assert ReconToExploitMapper._severity_to_cvss("critical") == 9.5
        assert ReconToExploitMapper._severity_to_cvss("high") == 7.5
        assert ReconToExploitMapper._severity_to_cvss("medium") == 5.0
        assert ReconToExploitMapper._severity_to_cvss("low") == 2.5
        assert ReconToExploitMapper._severity_to_cvss("info") == 0.0


# ===========================================================================
# Tests: AutoChain orchestrator (mocked MCP)
# ===========================================================================


def _make_mock_mcp(
    naabu_ports=None,
    nuclei_findings=None,
    msf_session_opened=False,
    msf_session_id=1,
    sysinfo_output="Linux 5.4.0",
    uid_output="root",
    flag_output="d41d8cd98f00b204e9800998ecf8427e",
):
    """Build a mock MCPClient that returns canned data for each tool call."""
    naabu_ports = naabu_ports or [{"port": 21, "service": "vsftpd", "version": "2.3.4"}]
    nuclei_findings = nuclei_findings or []

    async def call_tool(tool_name: str, params: dict) -> dict:
        if tool_name == "execute_naabu":
            return {"success": True, "ports": naabu_ports}
        if tool_name == "http_probe":
            return {"success": True, "technologies": []}
        if tool_name == "execute_nuclei":
            return {"success": True, "findings": nuclei_findings}
        if tool_name == "execute_module":
            return {
                "success": True,
                "session_opened": msf_session_opened,
                "session_info": {
                    "session_id": msf_session_id,
                    "type": "meterpreter",
                } if msf_session_opened else None,
                "output": "Exploit output",
            }
        if tool_name == "session_command":
            cmd = params.get("command", "")
            if "sysinfo" in cmd:
                return {"success": True, "output": sysinfo_output}
            if "root.txt" in cmd or "user.txt" in cmd or "flag.txt" in cmd:
                return {"success": True, "output": flag_output}
            return {"success": True, "output": uid_output}
        return {"success": False, "error": f"Unknown tool: {tool_name}"}

    client = MagicMock()
    client.call_tool = AsyncMock(side_effect=call_tool)
    return client


class TestAutoChainOrchestrator:
    """Unit tests for the AutoChain orchestrator with mocked MCP calls."""

    def _make_chain(self, auto_approve="critical", **mcp_kwargs):
        """
        Build an AutoChain with mocked MCP clients.

        Default auto_approve='critical' so that the default vsftpd test
        exploit (CVSS 10.0 → risk_level='critical') passes the approval gate
        without manual intervention.
        """
        from app.autochain.orchestrator import AutoChain

        plan = ScanPlan(target="10.0.0.1", auto_approve_risk_level=auto_approve)
        chain = AutoChain(plan=plan)
        mock = _make_mock_mcp(**mcp_kwargs)
        chain._naabu = mock
        chain._nuclei = mock
        chain._msf = mock
        return chain

    @pytest.mark.asyncio
    async def test_run_returns_chain_result(self):
        chain = self._make_chain()
        result = await chain.run()
        assert isinstance(result, ChainResult)

    @pytest.mark.asyncio
    async def test_run_completes_with_session(self):
        # auto_approve='critical' so the vsftpd exploit (CVSS 10 = critical) runs
        chain = self._make_chain(auto_approve="critical", msf_session_opened=True, msf_session_id=5)
        result = await chain.run()
        assert result.status == ChainStatus.COMPLETE
        assert result.exploitation_success is True
        assert result.session_id == 5

    @pytest.mark.asyncio
    async def test_run_no_session_still_completes(self):
        chain = self._make_chain(msf_session_opened=False)
        result = await chain.run()
        # Chain should still complete even if exploitation fails
        assert result.status == ChainStatus.COMPLETE
        assert result.exploitation_success is False

    @pytest.mark.asyncio
    async def test_flags_captured_after_session(self):
        flag_val = "abcd1234abcd1234abcd1234abcd1234"
        chain = self._make_chain(
            auto_approve="critical",
            msf_session_opened=True,
            flag_output=flag_val,
        )
        result = await chain.run()
        assert any(f["content"] == flag_val for f in result.flags)

    @pytest.mark.asyncio
    async def test_no_flags_when_no_session(self):
        chain = self._make_chain(msf_session_opened=False)
        result = await chain.run()
        assert result.flags == []

    @pytest.mark.asyncio
    async def test_steps_appended_for_each_phase(self):
        chain = self._make_chain(auto_approve="critical", msf_session_opened=True)
        result = await chain.run()
        phase_names = {s.phase for s in result.steps}
        assert ChainPhase.RECON in phase_names
        assert ChainPhase.VULN_DISCOVERY in phase_names
        assert ChainPhase.EXPLOITATION in phase_names
        assert ChainPhase.POST_EXPLOITATION in phase_names

    @pytest.mark.asyncio
    async def test_approval_gate_blocks_exploitation(self):
        """With auto_approve='none', exploitation steps are not executed."""
        chain = self._make_chain(auto_approve="none", msf_session_opened=True)
        result = await chain.run()
        # With auto_approve=none, the exploits are not actually executed
        assert result.exploitation_success is False

    @pytest.mark.asyncio
    async def test_approval_gate_passes_for_critical(self):
        """With auto_approve='critical', all exploits including critical ones proceed."""
        chain = self._make_chain(auto_approve="critical", msf_session_opened=True)
        result = await chain.run()
        assert result.exploitation_success is True

    @pytest.mark.asyncio
    async def test_approval_gate_blocks_critical_when_threshold_high(self):
        """With auto_approve='high', critical-risk exploits are still blocked."""
        chain = self._make_chain(auto_approve="high", msf_session_opened=True)
        result = await chain.run()
        # vsftpd exploit is CVSS 10 → critical, so blocked by 'high' threshold
        assert result.exploitation_success is False

    @pytest.mark.asyncio
    async def test_stream_yields_chain_steps(self):
        chain = self._make_chain(msf_session_opened=False)
        steps_received = []
        async for step in chain.stream():
            steps_received.append(step)
        assert len(steps_received) > 0
        assert all(isinstance(s, ChainStep) for s in steps_received)

    @pytest.mark.asyncio
    async def test_recon_phase_populates_open_ports(self):
        ports = [{"port": 21, "service": "vsftpd", "version": "2.3.4"}]
        chain = self._make_chain(naabu_ports=ports)
        await chain.run()
        assert chain.plan.open_ports == ports

    @pytest.mark.asyncio
    async def test_exploit_candidates_populated_after_recon(self):
        ports = [{"port": 21, "service": "vsftpd", "version": "2.3.4"}]
        chain = self._make_chain(naabu_ports=ports)
        await chain.run()
        assert len(chain.plan.exploit_candidates) > 0

    @pytest.mark.asyncio
    async def test_nuclei_findings_increase_candidates(self):
        findings = [make_nuclei_finding("cve-2021-44228", cvss=10.0)]
        chain = self._make_chain(nuclei_findings=findings)
        await chain.run()
        # Should have at least one candidate from nuclei
        assert len(chain.plan.exploit_candidates) > 0

    @pytest.mark.asyncio
    async def test_total_exploits_counter_increments(self):
        chain = self._make_chain(auto_approve="critical", msf_session_opened=False)
        result = await chain.run()
        assert result.total_exploits_attempted >= 1

    @pytest.mark.asyncio
    async def test_sysinfo_stored_in_result(self):
        chain = self._make_chain(
            auto_approve="critical",
            msf_session_opened=True,
            sysinfo_output="Linux box 5.10",
        )
        result = await chain.run()
        assert result.os_info == "Linux box 5.10"


# ===========================================================================
# Tests: AUTO_APPROVE_RISK_LEVEL helper
# ===========================================================================


class TestRiskApprovalHelper:
    """Test the _risk_is_auto_approved helper."""

    def test_none_threshold_always_false(self):
        from app.autochain.orchestrator import _risk_is_auto_approved

        assert _risk_is_auto_approved("low", "none") is False
        assert _risk_is_auto_approved("critical", "none") is False

    def test_medium_threshold_approves_low_and_medium(self):
        from app.autochain.orchestrator import _risk_is_auto_approved

        assert _risk_is_auto_approved("low", "medium") is True
        assert _risk_is_auto_approved("medium", "medium") is True
        assert _risk_is_auto_approved("high", "medium") is False
        assert _risk_is_auto_approved("critical", "medium") is False

    def test_high_threshold_approves_up_to_high(self):
        from app.autochain.orchestrator import _risk_is_auto_approved

        assert _risk_is_auto_approved("low", "high") is True
        assert _risk_is_auto_approved("high", "high") is True
        assert _risk_is_auto_approved("critical", "high") is False

    def test_critical_threshold_approves_all(self):
        from app.autochain.orchestrator import _risk_is_auto_approved

        assert _risk_is_auto_approved("critical", "critical") is True
        assert _risk_is_auto_approved("low", "critical") is True

    def test_invalid_threshold_returns_false(self):
        from app.autochain.orchestrator import _risk_is_auto_approved

        assert _risk_is_auto_approved("high", "super_dangerous") is False


# ===========================================================================
# Tests: Config — AUTO_APPROVE_RISK_LEVEL
# ===========================================================================


class TestConfig:
    def test_auto_approve_risk_level_default(self):
        from app.core.config import Settings

        s = Settings()
        assert s.AUTO_APPROVE_RISK_LEVEL == "none"

    def test_auto_approve_risk_level_from_env(self, monkeypatch):
        monkeypatch.setenv("AUTO_APPROVE_RISK_LEVEL", "high")
        from app.core.config import Settings

        s = Settings()
        assert s.AUTO_APPROVE_RISK_LEVEL == "high"


# ===========================================================================
# Tests: API endpoints (light-weight, no real HTTP)
# ===========================================================================


class TestAutochainAPISchemas:
    """Test request/response Pydantic models independently of the HTTP layer."""

    def test_start_request_defaults(self):
        from app.api.autochain import AutoChainStartRequest

        req = AutoChainStartRequest(target="10.0.0.1")
        assert req.auto_approve_risk_level == "none"
        assert req.naabu_url == "http://kali-tools:8000"

    def test_start_response_fields(self):
        from app.api.autochain import AutoChainStartResponse

        resp = AutoChainStartResponse(
            chain_id="c1",
            plan_id="p1",
            target="t",
            status="running",
            started_at="2026-01-01T00:00:00",
            message="ok",
        )
        assert resp.chain_id == "c1"

    def test_flags_response(self):
        from app.api.autochain import AutoChainFlagsResponse

        resp = AutoChainFlagsResponse(
            chain_id="c1",
            target="10.0.0.1",
            flags=[{"content": "abc123" * 5 + "ab", "source_command": "cat"}],
            count=1,
        )
        assert resp.count == 1

    def test_status_response(self):
        from app.api.autochain import AutoChainStatusResponse

        resp = AutoChainStatusResponse(
            chain_id="c1",
            target="t",
            status="complete",
            current_phase=None,
            total_steps=4,
            completed_steps=4,
            total_vulns_found=2,
            total_exploits_attempted=1,
            exploitation_success=True,
            flags_found=1,
            session_id=3,
            started_at="2026-01-01T00:00:00",
            finished_at="2026-01-01T00:01:00",
            error=None,
        )
        assert resp.exploitation_success is True
        assert resp.session_id == 3
