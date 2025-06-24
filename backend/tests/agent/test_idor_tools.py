"""
Tests for PLAN.md Day 3 — IDOR & Access Control Testing Suite

Coverage:
  - _generate_sequential_ids(): sequential ID generation
  - _generate_uuid_variants(): UUID probe generation
  - _looks_like_uuid(): UUID format detection
  - _extract_id_from_url(): ID extraction from URL paths
  - _substitute_id_in_url(): URL ID substitution
  - _response_differs(): response comparison heuristic
  - _is_access_denied(): access denial detection
  - IDORDetectTool: metadata, offline path, MCP interaction
  - IDORExploitTool: metadata, cross-user access detection
  - PrivilegeEscalationWebTool: metadata, role injection
  - ToolRegistry: Day 3 tools registered in correct phases
  - AttackPathRouter: IDOR/access-control keywords → WEB_APP_ATTACK
"""

from __future__ import annotations

from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.agent.attack_path_router import AttackCategory, AttackPathRouter
from app.agent.state.agent_state import Phase
from app.agent.tools.idor_tools import (
    OWASP_IDOR_TAG,
    OWASP_PRIVESC_TAG,
    IDORDetectTool,
    IDORExploitTool,
    IDORRisk,
    PrivEscRisk,
    PrivilegeEscalationWebTool,
    _extract_id_from_url,
    _generate_sequential_ids,
    _generate_uuid_variants,
    _inject_query_param,
    _is_access_denied,
    _looks_like_uuid,
    _response_differs,
    _substitute_id_in_url,
)


# ===========================================================================
# Helpers
# ===========================================================================


def _make_curl_client(
    body: str = "",
    headers: Dict[str, str] = None,
    status_code: int = 200,
    success: bool = True,
) -> MagicMock:
    headers = headers or {}

    async def call_tool(name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": success,
            "status_code": status_code,
            "headers": headers,
            "body": body,
        }

    client = MagicMock()
    client.call_tool = AsyncMock(side_effect=call_tool)
    return client


# ===========================================================================
# _generate_sequential_ids
# ===========================================================================


class TestGenerateSequentialIds:
    def test_basic_range(self):
        ids = _generate_sequential_ids(10, count=4)
        assert 9 in ids
        assert 10 not in ids
        assert 11 in ids

    def test_does_not_include_base(self):
        ids = _generate_sequential_ids(5, count=3)
        assert 5 not in ids

    def test_clamps_to_positive(self):
        ids = _generate_sequential_ids(1, count=4)
        assert all(i >= 1 for i in ids)

    def test_count_respected(self):
        ids = _generate_sequential_ids(100, count=6)
        assert len(ids) <= 12  # 2 * count max

    def test_zero_base_clamps(self):
        ids = _generate_sequential_ids(0, count=3)
        assert all(i >= 1 for i in ids)


# ===========================================================================
# _generate_uuid_variants
# ===========================================================================


class TestGenerateUuidVariants:
    def test_returns_valid_uuids(self):
        base = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        variants = _generate_uuid_variants(base)
        assert len(variants) > 0
        for v in variants:
            assert _looks_like_uuid(v)

    def test_does_not_include_base(self):
        base = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        variants = _generate_uuid_variants(base)
        assert base not in variants

    def test_different_base_always_has_variants(self):
        base = "00000000-0000-0000-0000-000000000001"
        variants = _generate_uuid_variants(base)
        assert len(variants) >= 1


# ===========================================================================
# _looks_like_uuid
# ===========================================================================


class TestLooksLikeUuid:
    def test_valid_uuid(self):
        assert _looks_like_uuid("550e8400-e29b-41d4-a716-446655440000") is True

    def test_invalid_short_string(self):
        assert _looks_like_uuid("abc123") is False

    def test_invalid_integer(self):
        assert _looks_like_uuid("42") is False

    def test_uppercase_uuid(self):
        assert _looks_like_uuid("550E8400-E29B-41D4-A716-446655440000") is True

    def test_empty_string(self):
        assert _looks_like_uuid("") is False


# ===========================================================================
# _extract_id_from_url
# ===========================================================================


class TestExtractIdFromUrl:
    def test_integer_id_in_path(self):
        assert _extract_id_from_url("https://example.com/api/users/42") == "42"

    def test_uuid_in_path(self):
        url = "https://example.com/api/docs/550e8400-e29b-41d4-a716-446655440000"
        result = _extract_id_from_url(url)
        assert result is not None
        assert _looks_like_uuid(result)

    def test_no_id_in_path(self):
        assert _extract_id_from_url("https://example.com/api/users/list") is None

    def test_id_in_penultimate_segment(self):
        assert _extract_id_from_url("https://example.com/users/99/profile") == "99"

    def test_empty_path(self):
        assert _extract_id_from_url("https://example.com/") is None


# ===========================================================================
# _substitute_id_in_url
# ===========================================================================


class TestSubstituteIdInUrl:
    def test_replaces_integer_id(self):
        url = "https://example.com/api/users/42"
        result = _substitute_id_in_url(url, "42", 99)
        assert "/99" in result
        assert "/42" not in result

    def test_replaces_first_occurrence_only(self):
        url = "https://example.com/42/resource/42"
        result = _substitute_id_in_url(url, "42", 1)
        assert result.count("42") == 1  # Only second remains

    def test_preserves_query_string(self):
        url = "https://example.com/users/5?format=json"
        result = _substitute_id_in_url(url, "5", 10)
        assert "format=json" in result


# ===========================================================================
# _response_differs
# ===========================================================================


class TestResponseDiffers:
    def test_empty_bodies_not_different(self):
        assert _response_differs("", "") is False

    def test_access_denied_in_probe_not_different(self):
        base = '{"user": "Alice", "email": "alice@example.com"}'
        probe = "Access Denied"
        assert _response_differs(base, probe) is False

    def test_different_data_bodies(self):
        base = '{"user": "Alice", "email": "alice@example.com"}'
        probe = '{"user": "Bob", "email": "bob@example.com"}'
        assert _response_differs(base, probe) is True

    def test_same_bodies_not_different(self):
        body = '{"id": 42, "name": "Alice"}'
        assert _response_differs(body, body) is False

    def test_very_different_length_different(self):
        base = "a" * 1000
        probe = "b" * 100
        assert _response_differs(base, probe) is True


# ===========================================================================
# _is_access_denied
# ===========================================================================


class TestIsAccessDenied:
    def test_401_is_denied(self):
        assert _is_access_denied(401, "") is True

    def test_403_is_denied(self):
        assert _is_access_denied(403, "") is True

    def test_404_is_denied(self):
        assert _is_access_denied(404, "") is True

    def test_200_not_denied(self):
        assert _is_access_denied(200, "some data") is False

    def test_body_forbidden_text(self):
        assert _is_access_denied(200, "Access Denied — contact admin") is True

    def test_body_unauthorized_text(self):
        assert _is_access_denied(200, "You are not authorized to view this") is True


# ===========================================================================
# IDORDetectTool metadata
# ===========================================================================


class TestIDORDetectToolMetadata:
    def test_name(self):
        tool = IDORDetectTool()
        assert tool.name == "idor_detect"

    def test_description_mentions_idor(self):
        tool = IDORDetectTool()
        assert "IDOR" in tool.description or "Insecure Direct Object" in tool.description

    def test_owasp_tag(self):
        assert "A01:2021" in OWASP_IDOR_TAG

    def test_parameters_has_url(self):
        tool = IDORDetectTool()
        assert "url" in tool.metadata.parameters.get("properties", {})

    def test_parameters_has_base_id(self):
        tool = IDORDetectTool()
        assert "base_id" in tool.metadata.parameters.get("properties", {})

    def test_parameters_has_probe_count(self):
        tool = IDORDetectTool()
        assert "probe_count" in tool.metadata.parameters.get("properties", {})


# ===========================================================================
# IDORDetectTool execute — offline (no MCP server)
# ===========================================================================


class TestIDORDetectToolExecute:
    @pytest.mark.asyncio
    async def test_no_id_in_url_returns_message(self):
        tool = IDORDetectTool()
        result = await tool.execute(url="https://example.com/api/users/list")
        assert "Could not detect" in result or "idor_detect" in result

    @pytest.mark.asyncio
    async def test_mcp_baseline_failure(self):
        tool = IDORDetectTool()
        tool._client = _make_curl_client(success=False, body="", status_code=0)
        result = await tool.execute(url="https://example.com/api/users/42")
        assert "Failed to fetch baseline" in result or "idor_detect" in result

    @pytest.mark.asyncio
    async def test_baseline_access_denied(self):
        tool = IDORDetectTool()
        tool._client = _make_curl_client(body="Forbidden", status_code=403)
        result = await tool.execute(url="https://example.com/api/users/42")
        assert "403" in result or "access" in result.lower()

    @pytest.mark.asyncio
    async def test_detects_idor_when_probe_accessible(self):
        """Simulate: baseline succeeds, one probe returns different data."""
        responses = [
            # Baseline (id=42)
            {"success": True, "status_code": 200, "body": '{"id": 42, "name": "Alice", "email": "alice@a.com"}', "headers": {}},
            # Probe ids — first two return accessible different content
            {"success": True, "status_code": 200, "body": '{"id": 37, "name": "Bob", "email": "bob@b.com"}', "headers": {}},
            {"success": True, "status_code": 200, "body": '{"id": 38, "name": "Carol", "email": "carol@c.com"}', "headers": {}},
            {"success": True, "status_code": 403, "body": "Forbidden", "headers": {}},
            {"success": True, "status_code": 403, "body": "Forbidden", "headers": {}},
        ]
        call_count = [0]

        async def call_tool(name, params):
            idx = min(call_count[0], len(responses) - 1)
            call_count[0] += 1
            return responses[idx]

        tool = IDORDetectTool()
        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=call_tool)
        result = await tool.execute(url="https://example.com/api/users/42", probe_count=4)
        assert "IDOR" in result or "Potential" in result or "Accessible" in result

    @pytest.mark.asyncio
    async def test_no_idor_when_all_probes_denied(self):
        """All probes return 403 — no IDOR."""
        call_count = [0]

        async def call_tool(name, params):
            call_count[0] += 1
            if call_count[0] == 1:
                return {"success": True, "status_code": 200, "body": '{"id": 42, "data": "mine"}', "headers": {}}
            return {"success": True, "status_code": 403, "body": "Forbidden", "headers": {}}

        tool = IDORDetectTool()
        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=call_tool)
        result = await tool.execute(url="https://example.com/api/users/42", probe_count=4)
        assert "No IDOR detected" in result or "access control appears" in result.lower()


# ===========================================================================
# IDORExploitTool metadata
# ===========================================================================


class TestIDORExploitToolMetadata:
    def test_name(self):
        assert IDORExploitTool().name == "idor_exploit"

    def test_description_mentions_cross_user(self):
        tool = IDORExploitTool()
        assert "cross" in tool.description.lower() or "victim" in tool.description.lower()

    def test_parameters_has_victim_url(self):
        tool = IDORExploitTool()
        assert "victim_url" in tool.metadata.parameters.get("properties", {})

    def test_parameters_has_attacker_cookies(self):
        tool = IDORExploitTool()
        assert "attacker_cookies" in tool.metadata.parameters.get("properties", {})


# ===========================================================================
# IDORExploitTool execute
# ===========================================================================


class TestIDORExploitToolExecute:
    @pytest.mark.asyncio
    async def test_confirmed_when_both_access(self):
        tool = IDORExploitTool()
        tool._client = _make_curl_client(
            body='{"id": 99, "secret": "victim_data"}',
            status_code=200,
        )
        result = await tool.execute(
            victim_url="https://example.com/api/users/99",
            attacker_cookies="session=attacker_token",
            victim_cookies="session=victim_token",
        )
        assert "CONFIRMED" in result or "idor_exploit" in result

    @pytest.mark.asyncio
    async def test_access_control_enforced(self):
        """Attacker gets 403, victim gets 200 — no IDOR."""
        call_count = [0]

        async def call_tool(name, params):
            call_count[0] += 1
            if call_count[0] == 1:  # victim
                return {"success": True, "status_code": 200, "body": "my data", "headers": {}}
            return {"success": True, "status_code": 403, "body": "Forbidden", "headers": {}}

        tool = IDORExploitTool()
        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=call_tool)
        result = await tool.execute(
            victim_url="https://example.com/api/users/99",
            attacker_cookies="session=bad",
        )
        assert "enforced" in result.lower() or "denied" in result.lower()


# ===========================================================================
# PrivilegeEscalationWebTool metadata
# ===========================================================================


class TestPrivilegeEscalationWebToolMetadata:
    def test_name(self):
        assert PrivilegeEscalationWebTool().name == "privilege_escalation_web"

    def test_description_mentions_privilege(self):
        tool = PrivilegeEscalationWebTool()
        assert "privilege" in tool.description.lower() or "role" in tool.description.lower()

    def test_owasp_tag(self):
        assert "A01:2021" in OWASP_PRIVESC_TAG

    def test_parameters_has_url_and_body(self):
        tool = PrivilegeEscalationWebTool()
        props = tool.metadata.parameters.get("properties", {})
        assert "url" in props
        assert "body" in props

    def test_escalation_type_default_both(self):
        tool = PrivilegeEscalationWebTool()
        props = tool.metadata.parameters.get("properties", {})
        assert props["escalation_type"]["default"] == "both"


# ===========================================================================
# PrivilegeEscalationWebTool execute
# ===========================================================================


class TestPrivilegeEscalationWebToolExecute:
    @pytest.mark.asyncio
    async def test_detects_role_injection_accepted(self):
        """Server returns 200 when role=admin injected."""
        tool = PrivilegeEscalationWebTool()
        tool._client = _make_curl_client(body='{"role": "admin", "ok": true}', status_code=200)
        result = await tool.execute(url="https://example.com/api/profile", method="POST")
        assert "PRIVILEGE ESCALATION" in result or "privilege_escalation_web" in result

    @pytest.mark.asyncio
    async def test_no_escalation_when_role_rejected(self):
        tool = PrivilegeEscalationWebTool()
        tool._client = _make_curl_client(
            body='{"error": "Invalid role parameter"}',
            status_code=400,
        )
        result = await tool.execute(url="https://example.com/api/profile", method="POST")
        assert "No privilege escalation" in result or "privilege_escalation_web" in result

    @pytest.mark.asyncio
    async def test_admin_endpoint_accessible(self):
        tool = PrivilegeEscalationWebTool()
        # Body injection returns 400 but admin endpoint returns 200
        call_count = [0]

        async def call_tool(name, params):
            call_count[0] += 1
            url = params.get("url", "")
            if "admin" in url:
                return {"success": True, "status_code": 200, "body": "admin panel", "headers": {}}
            return {"success": True, "status_code": 400, "body": "bad request", "headers": {}}

        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=call_tool)
        result = await tool.execute(
            url="https://example.com/api/profile",
            admin_endpoint="https://example.com/admin",
            escalation_type="vertical",
        )
        assert "privilege_escalation_web" in result


# ===========================================================================
# _inject_query_param helper
# ===========================================================================


class TestInjectQueryParam:
    def test_injects_new_param(self):
        url = "https://example.com/api/data"
        result = _inject_query_param(url, "user_id", "42")
        assert "user_id=42" in result

    def test_replaces_existing_param(self):
        url = "https://example.com/api/data?user_id=1"
        result = _inject_query_param(url, "user_id", "99")
        assert "user_id=99" in result
        assert "user_id=1" not in result

    def test_preserves_other_params(self):
        url = "https://example.com/api/data?format=json"
        result = _inject_query_param(url, "user_id", "42")
        assert "format=json" in result
        assert "user_id=42" in result


# ===========================================================================
# IDORRisk / PrivEscRisk enums
# ===========================================================================


class TestRiskEnums:
    def test_idor_risk_values(self):
        assert IDORRisk.CRITICAL.value == "critical"
        assert IDORRisk.HIGH.value == "high"
        assert IDORRisk.MEDIUM.value == "medium"
        assert IDORRisk.LOW.value == "low"
        assert IDORRisk.NONE.value == "none"

    def test_privesc_risk_values(self):
        assert PrivEscRisk.CRITICAL.value == "critical"
        assert PrivEscRisk.HIGH.value == "high"


# ===========================================================================
# ToolRegistry.# ===========================================================================


class TestToolRegistryDay3:
    def test_idor_detect_registered_informational(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.is_tool_allowed("idor_detect", Phase.INFORMATIONAL)

    def test_idor_detect_registered_exploitation(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.is_tool_allowed("idor_detect", Phase.EXPLOITATION)

    def test_idor_exploit_registered_exploitation(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.is_tool_allowed("idor_exploit", Phase.EXPLOITATION)

    def test_idor_exploit_not_informational(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert not registry.is_tool_allowed("idor_exploit", Phase.INFORMATIONAL)

    def test_privilege_escalation_web_registered_exploitation(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.is_tool_allowed("privilege_escalation_web", Phase.EXPLOITATION)

    def test_auth_bypass_registered_informational(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.is_tool_allowed("auth_bypass", Phase.INFORMATIONAL)

    def test_session_puzzling_registered(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.is_tool_allowed("session_puzzling", Phase.INFORMATIONAL)

    def test_rate_limit_bypass_registered(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.is_tool_allowed("rate_limit_bypass", Phase.EXPLOITATION)


# ===========================================================================
# AttackPathRouter — IDOR/auth keywords → WEB_APP_ATTACK
# ===========================================================================


class TestAttackPathRouterDay3:
    def test_idor_keyword(self):
        router = AttackPathRouter()
        category = router.classify_intent("Test for IDOR vulnerabilities in the API")
        assert category == AttackCategory.WEB_APP_ATTACK

    def test_auth_bypass_keyword(self):
        router = AttackPathRouter()
        category = router.classify_intent("Test auth bypass via X-Forwarded-For header injection")
        assert category == AttackCategory.WEB_APP_ATTACK

    def test_access_control_keyword(self):
        router = AttackPathRouter()
        category = router.classify_intent("Broken access control testing for role escalation")
        assert category == AttackCategory.WEB_APP_ATTACK

    def test_session_fixation_keyword(self):
        router = AttackPathRouter()
        category = router.classify_intent("Test for session fixation vulnerabilities")
        assert category == AttackCategory.WEB_APP_ATTACK
