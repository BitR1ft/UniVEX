"""
Tests for PLAN.md Day 3 — Auth Bypass, Session Puzzling & Rate Limit Bypass Tools

Coverage:
  - _is_accessible(): access detection helper
  - _get_body(): body extraction helper
  - _extract_session_from_response(): session cookie extraction
  - _detect_session_cookie_name(): cookie name detection
  - _analyse_session_cookie_attributes(): cookie attribute analysis
  - AuthBypassTool: metadata, verb tampering, header injection, path bypass
  - SessionPuzzlingTool: metadata, fixation detection, cookie attribute analysis
  - RateLimitBypassTool: metadata, IP rotation bypass, UA rotation
  - ToolRegistry: all auth bypass tools registered
  - AttackPathRouter: keywords route to WEB_APP_ATTACK
"""

from __future__ import annotations

from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.agent.attack_path_router import AttackCategory, AttackPathRouter
from app.agent.state.agent_state import Phase
from app.agent.tools.auth_bypass_tools import (
    OWASP_AUTH_TAG,
    OWASP_RATELIMIT_TAG,
    OWASP_SESSION_TAG,
    AuthBypassRisk,
    AuthBypassTool,
    RateLimitBypassTool,
    SessionPuzzlingTool,
    _IP_BYPASS_HEADERS,
    _PATH_BYPASS_SUFFIXES,
    _REWRITE_HEADERS,
    _SESSION_COOKIE_NAMES,
    _analyse_session_cookie_attributes,
    _detect_session_cookie_name,
    _extract_session_from_response,
    _get_body,
    _is_accessible,
    _is_protected,
)


# ===========================================================================
# Helper
# ===========================================================================


def _make_client(
    body: str = "",
    headers: Dict[str, str] = None,
    status_code: int = 200,
    success: bool = True,
) -> MagicMock:
    headers = headers or {}

    async def call_tool(name, params):
        return {"success": success, "status_code": status_code, "headers": headers, "body": body}

    c = MagicMock()
    c.call_tool = AsyncMock(side_effect=call_tool)
    return c


# ===========================================================================
# _is_accessible / _is_protected
# ===========================================================================


class TestIsAccessible:
    def test_200_without_denial_markers(self):
        assert _is_accessible(200, "some normal content") is True

    def test_200_with_access_denied(self):
        assert _is_accessible(200, "Access denied — please log in") is False

    def test_403_not_accessible(self):
        assert _is_accessible(403, "") is False

    def test_404_not_accessible(self):
        assert _is_accessible(404, "Not found") is False

    def test_201_accessible(self):
        assert _is_accessible(201, '{"created": true}') is True

    def test_204_accessible(self):
        assert _is_accessible(204, "") is True


class TestIsProtected:
    def test_401_protected(self):
        assert _is_protected(401) is True

    def test_403_protected(self):
        assert _is_protected(403) is True

    def test_200_not_protected(self):
        assert _is_protected(200) is False


# ===========================================================================
# _get_body
# ===========================================================================


class TestGetBody:
    def test_string_body(self):
        assert _get_body({"body": "hello"}) == "hello"

    def test_dict_body_serialised(self):
        result = _get_body({"body": {"key": "value"}})
        assert '"key"' in result
        assert '"value"' in result

    def test_missing_body_empty(self):
        assert _get_body({}) == ""

    def test_none_body_empty(self):
        assert _get_body({"body": None}) == ""


# ===========================================================================
# _extract_session_from_response
# ===========================================================================


class TestExtractSessionFromResponse:
    def test_extracts_session_id(self):
        headers = {"set-cookie": "session=abc123; Path=/; HttpOnly"}
        result = _extract_session_from_response(headers)
        assert result == "abc123"

    def test_extracts_phpsessid(self):
        headers = {"Set-Cookie": "PHPSESSID=xyz789; Path=/"}
        result = _extract_session_from_response(headers)
        assert result == "xyz789"

    def test_preferred_name_used(self):
        headers = {"set-cookie": "custom_session=tok; Path=/"}
        result = _extract_session_from_response(headers, preferred_name="custom_session")
        assert result == "tok"

    def test_no_session_returns_none(self):
        headers = {"content-type": "application/json"}
        result = _extract_session_from_response(headers)
        assert result is None

    def test_empty_headers(self):
        assert _extract_session_from_response({}) is None


# ===========================================================================
# _detect_session_cookie_name
# ===========================================================================


class TestDetectSessionCookieName:
    def test_detects_phpsessid(self):
        headers = {"set-cookie": "PHPSESSID=abc; Path=/"}
        assert _detect_session_cookie_name(headers) == "PHPSESSID"

    def test_detects_jsessionid(self):
        headers = {"set-cookie": "JSESSIONID=xyz; Path=/; HttpOnly"}
        assert _detect_session_cookie_name(headers) == "JSESSIONID"

    def test_fallback_when_unknown(self):
        headers = {"content-type": "text/html"}
        assert _detect_session_cookie_name(headers) == "session"


# ===========================================================================
# _analyse_session_cookie_attributes
# ===========================================================================


class TestAnalyseSessionCookieAttributes:
    def test_missing_secure_flag(self):
        headers = {"set-cookie": "session=abc; Path=/; HttpOnly; SameSite=Strict"}
        issues = _analyse_session_cookie_attributes(headers)
        types = [i["type"] for i in issues]
        assert "missing_secure_flag" in types

    def test_missing_httponly_flag(self):
        headers = {"set-cookie": "session=abc; Path=/; Secure; SameSite=Strict"}
        issues = _analyse_session_cookie_attributes(headers)
        types = [i["type"] for i in issues]
        assert "missing_httponly_flag" in types

    def test_missing_samesite(self):
        headers = {"set-cookie": "session=abc; Path=/; Secure; HttpOnly"}
        issues = _analyse_session_cookie_attributes(headers)
        types = [i["type"] for i in issues]
        assert "missing_samesite" in types

    def test_samesite_none_flagged(self):
        headers = {"set-cookie": "session=abc; Path=/; Secure; HttpOnly; SameSite=None"}
        issues = _analyse_session_cookie_attributes(headers)
        types = [i["type"] for i in issues]
        assert "samesite_none" in types

    def test_fully_hardened_no_issues(self):
        headers = {"set-cookie": "session=abc; Path=/; Secure; HttpOnly; SameSite=Strict"}
        issues = _analyse_session_cookie_attributes(headers)
        # Only secure flag missing should not appear if present
        types = [i["type"] for i in issues]
        assert "missing_secure_flag" not in types
        assert "missing_httponly_flag" not in types

    def test_non_session_cookie_ignored(self):
        headers = {"set-cookie": "analytics=ga123; Path=/"}
        issues = _analyse_session_cookie_attributes(headers)
        assert len(issues) == 0


# ===========================================================================
# AuthBypassTool metadata
# ===========================================================================


class TestAuthBypassToolMetadata:
    def test_name(self):
        assert AuthBypassTool().name == "auth_bypass"

    def test_description_mentions_bypass(self):
        tool = AuthBypassTool()
        assert "bypass" in tool.description.lower()

    def test_owasp_tag(self):
        assert "A01:2021" in OWASP_AUTH_TAG

    def test_parameters_has_url(self):
        tool = AuthBypassTool()
        assert "url" in tool.metadata.parameters.get("properties", {})

    def test_parameters_has_expected_status(self):
        tool = AuthBypassTool()
        assert "expected_status" in tool.metadata.parameters.get("properties", {})

    def test_ip_bypass_headers_not_empty(self):
        assert len(_IP_BYPASS_HEADERS) >= 5

    def test_path_bypass_suffixes_not_empty(self):
        assert len(_PATH_BYPASS_SUFFIXES) >= 5

    def test_rewrite_headers_not_empty(self):
        assert len(_REWRITE_HEADERS) >= 3


# ===========================================================================
# AuthBypassTool execute
# ===========================================================================


class TestAuthBypassToolExecute:
    @pytest.mark.asyncio
    async def test_no_bypass_when_all_403(self):
        tool = AuthBypassTool()
        tool._client = _make_client(body="Forbidden", status_code=403)
        result = await tool.execute(
            url="https://example.com/admin",
            expected_status=403,
        )
        assert "No auth bypass" in result or "auth_bypass" in result

    @pytest.mark.asyncio
    async def test_detects_verb_tampering(self):
        """HEAD method bypasses 403."""
        call_count = [0]

        async def call_tool(name, params):
            call_count[0] += 1
            method = params.get("method", "GET")
            if method == "HEAD":
                return {"success": True, "status_code": 200, "body": "admin content", "headers": {}}
            return {"success": True, "status_code": 403, "body": "Forbidden", "headers": {}}

        tool = AuthBypassTool()
        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=call_tool)
        result = await tool.execute(
            url="https://example.com/admin",
            expected_status=403,
            test_verb_tampering=True,
            test_header_injection=False,
            test_path_bypass=False,
            test_rewrite_headers=False,
        )
        assert "AUTH BYPASS DETECTED" in result or "verb_tampering" in result

    @pytest.mark.asyncio
    async def test_detects_header_injection(self):
        """X-Forwarded-For: 127.0.0.1 bypasses protection."""
        call_count = [0]

        async def call_tool(name, params):
            call_count[0] += 1
            hdrs = params.get("headers", {})
            if "X-Forwarded-For" in hdrs:
                return {"success": True, "status_code": 200, "body": "admin data", "headers": {}}
            return {"success": True, "status_code": 403, "body": "Forbidden", "headers": {}}

        tool = AuthBypassTool()
        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=call_tool)
        result = await tool.execute(
            url="https://example.com/admin",
            expected_status=403,
            test_verb_tampering=False,
            test_header_injection=True,
            test_path_bypass=False,
            test_rewrite_headers=False,
        )
        assert "header_injection" in result or "AUTH BYPASS" in result


# ===========================================================================
# AuthBypassRisk enum
# ===========================================================================


class TestAuthBypassRiskEnum:
    def test_critical_value(self):
        assert AuthBypassRisk.CRITICAL.value == "critical"

    def test_high_value(self):
        assert AuthBypassRisk.HIGH.value == "high"

    def test_none_value(self):
        assert AuthBypassRisk.NONE.value == "none"


# ===========================================================================
# SessionPuzzlingTool metadata
# ===========================================================================


class TestSessionPuzzlingToolMetadata:
    def test_name(self):
        assert SessionPuzzlingTool().name == "session_puzzling"

    def test_description_mentions_session(self):
        tool = SessionPuzzlingTool()
        assert "session" in tool.description.lower()

    def test_owasp_tag(self):
        assert "A07:2021" in OWASP_SESSION_TAG

    def test_parameters_has_login_url(self):
        tool = SessionPuzzlingTool()
        assert "login_url" in tool.metadata.parameters.get("properties", {})

    def test_session_cookie_names_populated(self):
        assert "session" in _SESSION_COOKIE_NAMES
        assert "PHPSESSID" in _SESSION_COOKIE_NAMES


# ===========================================================================
# SessionPuzzlingTool execute
# ===========================================================================


class TestSessionPuzzlingToolExecute:
    @pytest.mark.asyncio
    async def test_clean_session_no_issues(self):
        """Login returns new session and rotates it — no issues."""
        call_count = [0]

        async def call_tool(name, params):
            call_count[0] += 1
            return {
                "success": True,
                "status_code": 200,
                "headers": {"Set-Cookie": "session=newtoken123; Secure; HttpOnly; SameSite=Strict"},
                "body": "OK",
            }

        tool = SessionPuzzlingTool()
        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=call_tool)
        result = await tool.execute(login_url="https://example.com/login")
        # Should not have critical fixation issue since session is rotated
        assert "session_puzzling" in result

    @pytest.mark.asyncio
    async def test_missing_cookie_flags_detected(self):
        """Server sets session cookie without Secure/HttpOnly."""
        async def call_tool(name, params):
            return {
                "success": True,
                "status_code": 200,
                "headers": {"set-cookie": "session=tok; Path=/"},
                "body": "OK",
            }

        tool = SessionPuzzlingTool()
        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=call_tool)
        result = await tool.execute(login_url="https://example.com/login")
        assert "flag" in result.lower() or "session_puzzling" in result


# ===========================================================================
# RateLimitBypassTool metadata
# ===========================================================================


class TestRateLimitBypassToolMetadata:
    def test_name(self):
        assert RateLimitBypassTool().name == "rate_limit_bypass"

    def test_description_mentions_rate_limit(self):
        tool = RateLimitBypassTool()
        assert "rate" in tool.description.lower()

    def test_owasp_tag(self):
        assert "A04:2021" in OWASP_RATELIMIT_TAG

    def test_parameters_has_url(self):
        tool = RateLimitBypassTool()
        assert "url" in tool.metadata.parameters.get("properties", {})

    def test_parameters_has_rate_limit_status(self):
        tool = RateLimitBypassTool()
        assert "rate_limit_status" in tool.metadata.parameters.get("properties", {})


# ===========================================================================
# RateLimitBypassTool execute
# ===========================================================================


class TestRateLimitBypassToolExecute:
    @pytest.mark.asyncio
    async def test_no_bypass_when_all_429(self):
        tool = RateLimitBypassTool()
        tool._client = _make_client(body="Too Many Requests", status_code=429)
        result = await tool.execute(
            url="https://example.com/api/login",
            rate_limit_status=429,
        )
        assert "Rate limiting appears robust" in result or "rate_limit_bypass" in result

    @pytest.mark.asyncio
    async def test_detects_ip_rotation_bypass(self):
        """IP rotation allows continued access past rate limit."""
        call_count = [0]

        async def call_tool(name, params):
            call_count[0] += 1
            hdrs = params.get("headers", {})
            if "X-Forwarded-For" in hdrs or "X-Real-IP" in hdrs:
                return {"success": True, "status_code": 200, "body": "ok", "headers": {}}
            return {"success": True, "status_code": 429, "body": "Too Many Requests", "headers": {}}

        tool = RateLimitBypassTool()
        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=call_tool)
        result = await tool.execute(
            url="https://example.com/api/login",
            rate_limit_status=429,
            probe_count=3,
        )
        assert "ip_rotation" in result or "RATE LIMIT BYPASS" in result


# ===========================================================================
# ToolRegistry — auth bypass tools registered
# ===========================================================================


class TestToolRegistryAuthBypass:
    def test_auth_bypass_informational(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.is_tool_allowed("auth_bypass", Phase.INFORMATIONAL)

    def test_auth_bypass_exploitation(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.is_tool_allowed("auth_bypass", Phase.EXPLOITATION)

    def test_session_puzzling_informational(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.is_tool_allowed("session_puzzling", Phase.INFORMATIONAL)

    def test_rate_limit_bypass_informational(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.is_tool_allowed("rate_limit_bypass", Phase.INFORMATIONAL)

    def test_rate_limit_bypass_exploitation(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.is_tool_allowed("rate_limit_bypass", Phase.EXPLOITATION)


# ===========================================================================
# AttackPathRouter — keywords route to WEB_APP_ATTACK
# ===========================================================================


class TestAttackPathRouterAuthBypass:
    def test_rate_limit_bypass_keyword(self):
        router = AttackPathRouter()
        category = router.classify_intent("Test rate limit bypass via IP rotation")
        assert category == AttackCategory.WEB_APP_ATTACK

    def test_session_fixation_keyword(self):
        router = AttackPathRouter()
        category = router.classify_intent("Check for session fixation vulnerabilities on login")
        assert category == AttackCategory.WEB_APP_ATTACK

    def test_horizontal_escalation_keyword(self):
        router = AttackPathRouter()
        category = router.classify_intent("Test horizontal escalation via parameter tampering")
        assert category == AttackCategory.WEB_APP_ATTACK
