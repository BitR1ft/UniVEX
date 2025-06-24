"""
Integration Test: Month 12 - Exploitation & Post-Exploitation Framework

Validates that Month 12 features work together:
- Attack path router → tool selection → approval workflow
- Agent state new fields
- Tool registry Month 12 tools
- Approval gate logic
- Phase-based access control for new tools
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, AsyncMock

from app.agent.attack_path_router import AttackPathRouter, AttackCategory
from app.agent.state.agent_state import AgentState, Phase
from app.agent.tools.tool_registry import ToolRegistry, create_default_registry
from app.agent.tools.exploitation_tools import (
    ExploitExecuteTool,
    BruteForceTool,
    SessionManagerTool,
)
from app.agent.tools.post_exploitation_tools import (
    FileOperationsTool,
    SystemEnumerationTool,
    PrivilegeEscalationTool,
)


class TestAttackRouterToToolSelection:
    """Test attack path router → tool selection → approval workflow."""

    def test_cve_workflow(self):
        """Test full workflow for CVE exploitation: classify → plan → approve."""
        router = AttackPathRouter()

        category = router.classify_intent("Exploit CVE-2021-44228 on 10.0.0.5")
        assert category == AttackCategory.CVE_EXPLOITATION

        plan = router.get_attack_plan(category, {"host": "10.0.0.5", "port": 443})
        assert plan["requires_approval"] is True
        assert plan["risk_level"] == "critical"
        assert "metasploit" in plan["tools"]
        assert len(plan["steps"]) > 0

    def test_brute_force_workflow(self):
        """Test full workflow for brute force attack."""
        router = AttackPathRouter()

        category = router.classify_intent("Brute force the SSH login on the server")
        assert category == AttackCategory.BRUTE_FORCE

        plan = router.get_attack_plan(category, {"host": "10.0.0.5", "port": 22})
        assert plan["requires_approval"] is True
        assert plan["risk_level"] == "high"
        assert "hydra" in plan["tools"]

    def test_web_app_workflow_no_approval(self):
        """Test that web app attack does not require approval."""
        router = AttackPathRouter()

        category = router.classify_intent("Test for sql injection on the login page")
        assert category == AttackCategory.WEB_APP_ATTACK

        plan = router.get_attack_plan(category, {"host": "example.com", "port": 80})
        assert plan["requires_approval"] is False

    def test_privesc_workflow(self):
        """Test that privilege escalation requires approval and has critical risk."""
        router = AttackPathRouter()

        category = router.classify_intent("Try privilege escalation to get root access")
        assert category == AttackCategory.PRIVILEGE_ESCALATION

        plan = router.get_attack_plan(category, {"host": "10.0.0.5"})
        assert plan["requires_approval"] is True
        assert plan["risk_level"] == "critical"


class TestAgentStateNewFields:
    """Test that AgentState includes new Month 12 fields."""

    def test_pending_approval_field(self):
        """Test AgentState has pending_approval field."""
        assert "pending_approval" in AgentState.__annotations__

    def test_guidance_field(self):
        """Test AgentState has guidance field."""
        assert "guidance" in AgentState.__annotations__

    def test_progress_field(self):
        """Test AgentState has progress field."""
        assert "progress" in AgentState.__annotations__

    def test_checkpoint_field(self):
        """Test AgentState has checkpoint field."""
        assert "checkpoint" in AgentState.__annotations__

    def test_phase_enum_has_post_exploitation(self):
        """Test Phase enum has POST_EXPLOITATION value."""
        assert hasattr(Phase, "POST_EXPLOITATION")
        assert Phase.POST_EXPLOITATION.value == "post_exploitation"


class TestToolRegistryMonth12:
    """Test that tool registry includes Month 12 tools."""

    def test_default_registry_has_exploit_execute(self):
        """Test default registry includes exploit_execute tool."""
        registry = create_default_registry()
        assert "exploit_execute" in registry.list_all_tools()

    def test_default_registry_has_brute_force(self):
        """Test default registry includes brute_force tool."""
        registry = create_default_registry()
        assert "brute_force" in registry.list_all_tools()

    def test_default_registry_has_session_manager(self):
        """Test default registry includes session_manager tool."""
        registry = create_default_registry()
        assert "session_manager" in registry.list_all_tools()

    def test_default_registry_has_file_operations(self):
        """Test default registry includes file_operations tool."""
        registry = create_default_registry()
        assert "file_operations" in registry.list_all_tools()

    def test_default_registry_has_system_enumerate(self):
        """Test default registry includes system_enumerate tool."""
        registry = create_default_registry()
        assert "system_enumerate" in registry.list_all_tools()

    def test_default_registry_has_privilege_escalation(self):
        """Test default registry includes privilege_escalation tool."""
        registry = create_default_registry()
        assert "privilege_escalation" in registry.list_all_tools()


class TestApprovalGateLogic:
    """Test the approval gate logic via AttackPathRouter."""

    def test_dangerous_categories_require_approval(self):
        """Test that all dangerous categories require approval."""
        router = AttackPathRouter()
        dangerous = [
            AttackCategory.CVE_EXPLOITATION,
            AttackCategory.BRUTE_FORCE,
            AttackCategory.PRIVILEGE_ESCALATION,
            AttackCategory.LATERAL_MOVEMENT,
        ]
        for cat in dangerous:
            assert router.requires_approval(cat) is True, f"{cat.value} should require approval"

    def test_safe_categories_no_approval(self):
        """Test that non-dangerous categories do not require approval."""
        router = AttackPathRouter()
        safe = [
            AttackCategory.WEB_APP_ATTACK,
            AttackCategory.PASSWORD_SPRAY,
            AttackCategory.SOCIAL_ENGINEERING,
            AttackCategory.NETWORK_PIVOT,
            AttackCategory.FILE_EXFILTRATION,
            AttackCategory.PERSISTENCE,
        ]
        for cat in safe:
            assert router.requires_approval(cat) is False, f"{cat.value} should not require approval"

    def test_plan_approval_flag_matches(self):
        """Test that plan's requires_approval flag matches router."""
        router = AttackPathRouter()
        target = {"host": "10.0.0.5"}

        for category in AttackCategory:
            plan = router.get_attack_plan(category, target)
            assert plan["requires_approval"] == router.requires_approval(category)


class TestPhaseBasedAccessControl:
    """Test phase-based access control for Month 12 tools."""

    def setup_method(self):
        self.registry = create_default_registry()

    def test_exploit_execute_only_in_exploitation(self):
        """Test exploit_execute is only allowed in EXPLOITATION phase."""
        assert self.registry.is_tool_allowed("exploit_execute", Phase.EXPLOITATION)
        assert not self.registry.is_tool_allowed("exploit_execute", Phase.INFORMATIONAL)
        assert not self.registry.is_tool_allowed("exploit_execute", Phase.POST_EXPLOITATION)

    def test_brute_force_only_in_exploitation(self):
        """Test brute_force is only allowed in EXPLOITATION phase."""
        assert self.registry.is_tool_allowed("brute_force", Phase.EXPLOITATION)
        assert not self.registry.is_tool_allowed("brute_force", Phase.INFORMATIONAL)
        assert not self.registry.is_tool_allowed("brute_force", Phase.POST_EXPLOITATION)

    def test_session_manager_in_exploitation_and_post(self):
        """Test session_manager is allowed in EXPLOITATION and POST_EXPLOITATION."""
        assert self.registry.is_tool_allowed("session_manager", Phase.EXPLOITATION)
        assert self.registry.is_tool_allowed("session_manager", Phase.POST_EXPLOITATION)
        assert not self.registry.is_tool_allowed("session_manager", Phase.INFORMATIONAL)

    def test_file_operations_only_in_post_exploitation(self):
        """Test file_operations is only allowed in POST_EXPLOITATION phase."""
        assert self.registry.is_tool_allowed("file_operations", Phase.POST_EXPLOITATION)
        assert not self.registry.is_tool_allowed("file_operations", Phase.INFORMATIONAL)
        assert not self.registry.is_tool_allowed("file_operations", Phase.EXPLOITATION)

    def test_system_enumerate_in_exploitation_and_post(self):
        """Test system_enumerate is allowed in EXPLOITATION and POST_EXPLOITATION."""
        assert self.registry.is_tool_allowed("system_enumerate", Phase.EXPLOITATION)
        assert self.registry.is_tool_allowed("system_enumerate", Phase.POST_EXPLOITATION)
        assert not self.registry.is_tool_allowed("system_enumerate", Phase.INFORMATIONAL)

    def test_privilege_escalation_only_in_post_exploitation(self):
        """Test privilege_escalation is only allowed in POST_EXPLOITATION phase."""
        assert self.registry.is_tool_allowed("privilege_escalation", Phase.POST_EXPLOITATION)
        assert not self.registry.is_tool_allowed("privilege_escalation", Phase.INFORMATIONAL)
        assert not self.registry.is_tool_allowed("privilege_escalation", Phase.EXPLOITATION)

    def test_informational_phase_excludes_month12_tools(self):
        """Test that INFORMATIONAL phase excludes all Month 12 exploitation tools."""
        info_tools = self.registry.get_tools_for_phase(Phase.INFORMATIONAL)
        month12_tools = [
            "exploit_execute", "brute_force", "file_operations",
            "privilege_escalation",
        ]
        for tool_name in month12_tools:
            assert tool_name not in info_tools, f"{tool_name} should not be in INFORMATIONAL phase"

    def test_exploitation_phase_tools(self):
        """Test that EXPLOITATION phase includes exploitation tools."""
        exploit_tools = self.registry.get_tools_for_phase(Phase.EXPLOITATION)
        assert "exploit_execute" in exploit_tools
        assert "brute_force" in exploit_tools
        assert "session_manager" in exploit_tools
        assert "system_enumerate" in exploit_tools

    def test_post_exploitation_phase_tools(self):
        """Test that POST_EXPLOITATION phase includes post-exploitation tools."""
        post_tools = self.registry.get_tools_for_phase(Phase.POST_EXPLOITATION)
        assert "file_operations" in post_tools
        assert "system_enumerate" in post_tools
        assert "privilege_escalation" in post_tools
        assert "session_manager" in post_tools


@pytest.mark.asyncio
class TestEndToEndToolExecution:
    """End-to-end test of tool selection and mocked execution."""

    async def test_classify_select_and_execute(self):
        """Test classify intent → select tool → execute with mock."""
        router = AttackPathRouter()
        registry = create_default_registry()

        # Step 1: Classify intent
        category = router.classify_intent("Brute force SSH on 10.0.0.5")
        assert category == AttackCategory.BRUTE_FORCE

        # Step 2: Check tool is available in exploitation phase
        assert registry.is_tool_allowed("brute_force", Phase.EXPLOITATION)

        # Step 3: Get tool and execute with mock
        tool = registry.get_tool("brute_force")
        assert tool is not None
        tool.client = Mock()
        tool.client.call_tool = AsyncMock(return_value={
            "success": True,
            "session_opened": True,
            "output": "Credentials found: admin:password",
        })

        result = await tool.execute(target="10.0.0.5", service="ssh", username="admin")
        assert "10.0.0.5" in result
        assert "Session Opened: True" in result
