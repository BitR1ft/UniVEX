"""
Tests for Week 11-12 Betterment Plan — HTB Attack Templates & Session Upgrade

Coverage:
  - AutoChain.from_template() factory method
  - AutoChain.list_templates() class method
  - Template file validation (htb_easy.json, htb_medium.json)
  - Session upgrade phase (shell→meterpreter, TTY stabilisation)
  - Flag MD5 verification in _verify_flag_md5()
  - API endpoint schemas (AutoChainTemplateStartRequest)
  - FlagCaptureTool MD5 output
"""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.autochain.orchestrator import (
    AutoChain,
    FLAG_READ_COMMANDS_LINUX,
    FLAG_READ_COMMANDS_WINDOWS,
    _verify_flag_md5,
)
from app.autochain.schemas import (
    ChainPhase,
    ChainResult,
    ChainStatus,
    ChainStep,
    ExploitCandidate,
    ScanPlan,
)

# Path to templates directory (resolved relative to this test file)
_TEMPLATES_DIR = (
    Path(__file__).parent.parent.parent / "app" / "autochain" / "templates"
)


# ===========================================================================
# Tests: _verify_flag_md5 helper
# ===========================================================================


class TestVerifyFlagMd5:
    def test_known_md5(self):
        import hashlib

        flag = "d41d8cd98f00b204e9800998ecf8427e"
        expected = hashlib.md5(flag.encode()).hexdigest()
        assert _verify_flag_md5(flag) == expected

    def test_returns_32_char_string(self):
        result = _verify_flag_md5("a" * 32)
        assert len(result) == 32

    def test_different_flags_different_hashes(self):
        h1 = _verify_flag_md5("a" * 32)
        h2 = _verify_flag_md5("b" * 32)
        assert h1 != h2


# ===========================================================================
# Tests: Template file structure validation
# ===========================================================================


class TestTemplateFiles:
    """Validate the JSON template files ship with the required fields."""

    def _load(self, name: str) -> Dict[str, Any]:
        path = _TEMPLATES_DIR / f"{name}.json"
        assert path.exists(), f"Template file not found: {path}"
        with path.open() as fh:
            return json.load(fh)

    # ---- htb_easy.json ----

    def test_htb_easy_template_exists(self):
        assert (_TEMPLATES_DIR / "htb_easy.json").exists()

    def test_htb_easy_required_fields(self):
        tpl = self._load("htb_easy")
        for field in ("template_id", "name", "description", "phases", "version"):
            assert field in tpl, f"Missing field '{field}' in htb_easy.json"

    def test_htb_easy_template_id(self):
        assert self._load("htb_easy")["template_id"] == "htb_easy"

    def test_htb_easy_phases_non_empty(self):
        phases = self._load("htb_easy")["phases"]
        assert len(phases) >= 5, "htb_easy should have at least 5 phases"

    def test_htb_easy_has_flag_capture_phase(self):
        phases = self._load("htb_easy")["phases"]
        tools = [p["tool"] for p in phases]
        assert "flag_capture" in tools, "htb_easy must include a flag_capture phase"

    def test_htb_easy_has_ffuf_phase(self):
        phases = self._load("htb_easy")["phases"]
        tools = [p["tool"] for p in phases]
        assert "ffuf" in tools, "htb_easy must include an ffuf (web discovery) phase"

    def test_htb_easy_auto_approve_level(self):
        tpl = self._load("htb_easy")
        # Easy HTB should auto-approve high-risk actions for lab use
        assert tpl.get("auto_approve_risk_level") in ("high", "critical")

    def test_htb_easy_success_criteria(self):
        tpl = self._load("htb_easy")
        criteria = tpl["target_profile"]["success_criteria"]
        assert "root.txt" in criteria["target_flag_names"]
        assert "user.txt" in criteria["target_flag_names"]

    # ---- htb_medium.json ----

    def test_htb_medium_template_exists(self):
        assert (_TEMPLATES_DIR / "htb_medium.json").exists()

    def test_htb_medium_required_fields(self):
        tpl = self._load("htb_medium")
        for field in ("template_id", "name", "description", "phases", "version"):
            assert field in tpl, f"Missing field '{field}' in htb_medium.json"

    def test_htb_medium_template_id(self):
        assert self._load("htb_medium")["template_id"] == "htb_medium"

    def test_htb_medium_has_more_phases_than_easy(self):
        easy = self._load("htb_easy")["phases"]
        medium = self._load("htb_medium")["phases"]
        assert len(medium) > len(easy), (
            "htb_medium should have more phases than htb_easy"
        )

    def test_htb_medium_has_sqlmap_phase(self):
        phases = self._load("htb_medium")["phases"]
        tools = [p["tool"] for p in phases]
        assert "sqlmap" in tools, "htb_medium must include a sqlmap phase"

    def test_htb_medium_has_ldap_phase(self):
        phases = self._load("htb_medium")["phases"]
        names = [p["name"].lower() for p in phases]
        assert any("ldap" in n for n in names), (
            "htb_medium should include an LDAP enumeration phase"
        )

    def test_htb_medium_difficulty(self):
        tpl = self._load("htb_medium")
        assert tpl["target_profile"]["difficulty"] == "medium"

    def test_htb_medium_retry_logic_present(self):
        """At least one phase in htb_medium should define retry logic."""
        phases = self._load("htb_medium")["phases"]
        has_retry = any("retry" in p for p in phases)
        assert has_retry, "htb_medium should define retry logic on at least one phase"


# ===========================================================================
# Tests: AutoChain.from_template() factory
# ===========================================================================


class TestFromTemplate:
    def test_creates_autochain_instance(self):
        chain = AutoChain.from_template("htb_easy", target="10.10.10.3")
        assert isinstance(chain, AutoChain)

    def test_target_set_on_plan(self):
        chain = AutoChain.from_template("htb_easy", target="10.10.10.100")
        assert chain.plan.target == "10.10.10.100"

    def test_template_loaded_on_instance(self):
        chain = AutoChain.from_template("htb_easy", target="10.0.0.1")
        assert chain._template is not None
        assert chain._template["template_id"] == "htb_easy"

    def test_auto_approve_from_template(self):
        """Template's auto_approve_risk_level is used when no override supplied."""
        chain = AutoChain.from_template("htb_easy", target="10.0.0.1")
        assert chain.plan.auto_approve_risk_level == "high"

    def test_auto_approve_override(self):
        """Caller can override the template's auto_approve_risk_level."""
        chain = AutoChain.from_template(
            "htb_easy",
            target="10.0.0.1",
            auto_approve_risk_level="critical",
        )
        assert chain.plan.auto_approve_risk_level == "critical"

    def test_project_id_forwarded(self):
        chain = AutoChain.from_template(
            "htb_easy", target="10.0.0.1", project_id="proj-42"
        )
        assert chain.plan.project_id == "proj-42"

    def test_htb_medium_template(self):
        chain = AutoChain.from_template("htb_medium", target="10.10.10.50")
        assert chain._template["template_id"] == "htb_medium"

    def test_missing_template_raises_file_not_found(self):
        with pytest.raises(FileNotFoundError, match="nonexistent"):
            AutoChain.from_template("nonexistent", target="10.0.0.1")

    def test_error_message_lists_available_templates(self):
        with pytest.raises(FileNotFoundError, match="htb_easy"):
            AutoChain.from_template("nope", target="10.0.0.1")


# ===========================================================================
# Tests: AutoChain.list_templates()
# ===========================================================================


class TestListTemplates:
    def test_returns_list(self):
        result = AutoChain.list_templates()
        assert isinstance(result, list)

    def test_contains_htb_easy(self):
        ids = [t["id"] for t in AutoChain.list_templates()]
        assert "htb_easy" in ids

    def test_contains_htb_medium(self):
        ids = [t["id"] for t in AutoChain.list_templates()]
        assert "htb_medium" in ids

    def test_each_entry_has_required_keys(self):
        for tpl in AutoChain.list_templates():
            for key in ("id", "name", "description", "difficulty", "version"):
                assert key in tpl, f"Template entry missing key '{key}'"

    def test_difficulty_values_are_valid(self):
        valid = {"easy", "medium", "hard", "unknown"}
        for tpl in AutoChain.list_templates():
            assert tpl["difficulty"] in valid


# ===========================================================================
# Tests: Session Upgrade Phase
# ===========================================================================


def _make_plan(target: str = "10.0.0.1") -> ScanPlan:
    return ScanPlan(target=target, auto_approve_risk_level="high")


def _make_chain(plan: ScanPlan | None = None) -> AutoChain:
    plan = plan or _make_plan()
    chain = AutoChain(plan=plan)
    return chain


async def _collect_steps(gen: AsyncIterator[ChainStep]) -> List[ChainStep]:
    steps = []
    async for step in gen:
        steps.append(step)
    return steps


class TestSessionUpgradePhase:
    """Tests for _stream_session_upgrade() — Week 11."""

    @pytest.mark.asyncio
    async def test_no_session_yields_nothing(self):
        chain = _make_chain()
        # No session → generator must yield nothing (silently skip)
        steps = await _collect_steps(chain._stream_session_upgrade())
        assert steps == []

    @pytest.mark.asyncio
    async def test_meterpreter_session_no_upgrade_needed(self):
        chain = _make_chain()
        chain.result.session_id = 1
        chain.result.session_type = "meterpreter"

        steps = await _collect_steps(chain._stream_session_upgrade())
        assert len(steps) == 1
        assert steps[0].name == "session_upgrade"
        assert steps[0].status == "success"
        assert "already Meterpreter" in steps[0].output or "Meterpreter session active" in steps[0].output

    @pytest.mark.asyncio
    async def test_shell_session_attempts_meterpreter_upgrade(self):
        chain = _make_chain()
        chain.result.session_id = 2
        chain.result.session_type = "shell"

        # Mock successful shell_to_meterpreter upgrade
        async def _mock_call(tool, params):
            if tool == "execute_module":
                return {
                    "session_opened": True,
                    "session_info": {"session_id": 5, "type": "meterpreter"},
                }
            return {"output": ""}

        chain._msf.call_tool = AsyncMock(side_effect=_mock_call)

        steps = await _collect_steps(chain._stream_session_upgrade())
        assert len(steps) == 1
        assert steps[0].status == "success"
        assert chain.result.session_type == "meterpreter"
        assert chain.result.session_id == 5

    @pytest.mark.asyncio
    async def test_shell_fallback_to_tty_spawn_on_upgrade_failure(self):
        chain = _make_chain()
        chain.result.session_id = 3
        chain.result.session_type = "shell"

        # MSF upgrade fails, TTY spawn succeeds
        async def _mock_call(tool, params):
            if tool == "execute_module":
                return {"session_opened": False, "output": "exploit failed"}
            if tool == "session_command":
                return {"output": "bash-5.1$"}
            return {}

        chain._msf.call_tool = AsyncMock(side_effect=_mock_call)

        steps = await _collect_steps(chain._stream_session_upgrade())
        assert len(steps) == 1
        # Session retained as shell but TTY spawn output is reported
        assert "bash-5.1$" in steps[0].output or "Shell session retained" in steps[0].output

    @pytest.mark.asyncio
    async def test_session_upgrade_exception_is_handled(self):
        chain = _make_chain()
        chain.result.session_id = 4
        chain.result.session_type = "shell"

        async def _mock_call(tool, params):
            raise RuntimeError("MCP unreachable")

        chain._msf.call_tool = AsyncMock(side_effect=_mock_call)

        # Should not raise; should yield one step with some message
        steps = await _collect_steps(chain._stream_session_upgrade())
        assert len(steps) == 1


# ===========================================================================
# Tests: Flag MD5 in post-exploitation phase
# ===========================================================================


class TestFlagMd5InChainResult:
    """After flag capture, each flag dict should contain an 'md5' key."""

    @pytest.mark.asyncio
    async def test_captured_flags_include_md5(self):
        chain = _make_chain()
        chain.result.session_id = 1
        chain.result.session_type = "meterpreter"

        flag_value = "d41d8cd98f00b204e9800998ecf8427e"

        async def _mock_call(tool, params):
            cmd = params.get("command", "")
            if "sysinfo" in cmd:
                return {"output": "Linux ubuntu 5.4.0"}
            if "cat /root" in cmd or "find /home" in cmd:
                return {"output": flag_value}
            return {"output": ""}

        chain._msf.call_tool = AsyncMock(side_effect=_mock_call)

        steps = await _collect_steps(chain._stream_post_exploitation())
        flag_steps = [s for s in steps if s.name == "flag_capture"]
        assert flag_steps, "Expected a flag_capture step"

        captured = chain.result.flags
        assert len(captured) >= 1
        # Every captured flag must have an 'md5' field
        for f in captured:
            assert "md5" in f, f"Flag entry missing 'md5': {f}"
            assert len(f["md5"]) == 32


# ===========================================================================
# Tests: API schema for template-based chain start
# ===========================================================================


class TestTemplateAPISchemas:
    def test_template_start_request_required_fields(self):
        from app.api.autochain import AutoChainTemplateStartRequest

        req = AutoChainTemplateStartRequest(template="htb_easy", target="10.0.0.1")
        assert req.template == "htb_easy"
        assert req.target == "10.0.0.1"
        assert req.auto_approve_risk_level is None  # caller can leave as None

    def test_template_start_request_override(self):
        from app.api.autochain import AutoChainTemplateStartRequest

        req = AutoChainTemplateStartRequest(
            template="htb_medium",
            target="10.0.0.2",
            auto_approve_risk_level="critical",
        )
        assert req.auto_approve_risk_level == "critical"

    def test_template_start_default_urls(self):
        from app.api.autochain import AutoChainTemplateStartRequest

        req = AutoChainTemplateStartRequest(template="htb_easy", target="10.0.0.1")
        assert req.naabu_url == "http://kali-tools:8000"
        assert req.msf_url == "http://kali-tools:8003"
