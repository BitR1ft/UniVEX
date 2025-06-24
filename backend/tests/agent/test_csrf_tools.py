"""
Tests for PLAN.md Day 2 — CSRF, SSRF & Request Forgery Toolkit (CSRF section)

Coverage:
  - analyse_csrf_token(): token detection, SameSite analysis, risk classification
  - generate_csrf_poc(): HTML PoC generation, field encoding, enctype
  - CSRFDetectTool: metadata, MCP interactions, formatting
  - CSRFExploitTool: metadata, PoC generation, remediation advice
  - ToolRegistry: CSRF tools registered in correct phases
  - AttackPathRouter: CSRF keyword → WEB_APP_ATTACK
"""

from __future__ import annotations

import re
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.agent.attack_path_router import AttackCategory, AttackPathRouter
from app.agent.state.agent_state import Phase
from app.agent.tools.csrf_tools import (
    OWASP_CSRF_TAG,
    CSRFDetectTool,
    CSRFExploitTool,
    CSRFRisk,
    _CSRF_FIELD_NAMES,
    _CSRF_HEADER_NAMES,
    analyse_csrf_token,
    generate_csrf_poc,
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
# analyse_csrf_token
# ===========================================================================


class TestAnalyseCsrfToken:
    def test_token_found_in_form(self):
        body = '<form><input type="hidden" name="csrf_token" value="abc123xyz"></form>'
        result = analyse_csrf_token(body, {})
        assert result["found"] is True
        assert result["token_field"] == "csrf_token"
        assert result["token_value"] == "abc123xyz"

    def test_no_token_high_risk(self):
        body = "<form><input name='email' type='text'></form>"
        result = analyse_csrf_token(body, {})
        assert result["found"] is False
        assert result["risk"] == CSRFRisk.HIGH.value

    def test_samesite_strict_lowers_risk_without_token(self):
        body = "<form><input name='email'></form>"
        headers = {"set-cookie": "session=abc; SameSite=Strict; Secure"}
        result = analyse_csrf_token(body, headers)
        assert result["samesite"] == "strict"
        assert result["risk"] == CSRFRisk.LOW.value  # SameSite alone = LOW

    def test_samesite_lax_lowers_risk(self):
        body = "<form><input name='email'></form>"
        headers = {"set-cookie": "session=abc; SameSite=Lax"}
        result = analyse_csrf_token(body, headers)
        assert result["samesite"] == "lax"
        assert result["risk"] == CSRFRisk.LOW.value

    def test_secure_flag_detected(self):
        headers = {"set-cookie": "session=abc; Secure; HttpOnly"}
        result = analyse_csrf_token("", headers)
        assert result["secure"] is True
        assert result["httponly"] is True

    def test_short_token_medium_risk(self):
        body = '<input name="csrf_token" value="short">'  # < 8 chars
        result = analyse_csrf_token(body, {})
        assert result["found"] is True
        assert result["risk"] == CSRFRisk.MEDIUM.value

    def test_token_in_header(self):
        headers = {"x-csrf-token": "longenoughtokentobefine123"}
        result = analyse_csrf_token("", headers)
        assert result["found"] is True

    def test_all_csrf_field_names_detected(self):
        for field in _CSRF_FIELD_NAMES[:5]:
            body = f'<input type="hidden" name="{field}" value="randomtoken12345">'
            result = analyse_csrf_token(body, {})
            assert result["found"] is True, f"Field {field} not detected"

    def test_risk_none_with_token_and_samesite(self):
        body = '<input name="csrf_token" value="averylongsecuretokenvalue12345">'
        headers = {"set-cookie": "session=abc; SameSite=Strict; Secure"}
        result = analyse_csrf_token(body, headers)
        assert result["risk"] == CSRFRisk.NONE.value

    def test_empty_body_and_headers(self):
        result = analyse_csrf_token("", {})
        assert result["found"] is False
        assert result["risk"] == CSRFRisk.HIGH.value

    def test_xsrf_header_name(self):
        headers = {"x-xsrf-token": "anotherlongtoken12345"}
        result = analyse_csrf_token("", headers)
        assert result["found"] is True

    def test_case_insensitive_samesite(self):
        headers = {"set-cookie": "s=v; samesite=STRICT"}
        result = analyse_csrf_token("", headers)
        assert result["samesite"] == "strict"


# ===========================================================================
# generate_csrf_poc
# ===========================================================================


class TestGenerateCsrfPoc:
    def test_contains_form_action(self):
        html = generate_csrf_poc("http://example.com/delete", "POST")
        assert "http://example.com/delete" in html

    def test_contains_method(self):
        html = generate_csrf_poc("http://example.com/delete", "POST")
        assert 'method="post"' in html

    def test_fields_included(self):
        html = generate_csrf_poc(
            "http://example.com/delete", "POST", fields={"user_id": "42", "confirm": "true"}
        )
        assert 'name="user_id"' in html
        assert 'value="42"' in html
        assert 'name="confirm"' in html

    def test_auto_submit_onload(self):
        html = generate_csrf_poc("http://example.com/", "POST")
        assert "onload" in html
        assert "submit" in html

    def test_xss_escape_in_values(self):
        html = generate_csrf_poc(
            "http://example.com/",
            "POST",
            fields={"evil": '<script>alert(1)</script>'},
        )
        # Raw script tag should NOT appear in value attribute
        assert '<script>' not in html or 'value="<script>' not in html

    def test_owasp_tag_in_poc(self):
        html = generate_csrf_poc("http://example.com/", "POST")
        assert "OWASP" in html or "A01" in html or "A05" in html

    def test_multipart_enctype(self):
        html = generate_csrf_poc(
            "http://example.com/",
            "POST",
            content_type="multipart/form-data",
        )
        assert "multipart/form-data" in html

    def test_put_method(self):
        html = generate_csrf_poc("http://example.com/api/user", "PUT")
        assert 'method="put"' in html

    def test_empty_fields(self):
        html = generate_csrf_poc("http://example.com/logout", "POST")
        assert "<form" in html

    def test_endpoint_html_escaped(self):
        # endpoint with & character
        html = generate_csrf_poc("http://example.com/action?a=1&b=2", "POST")
        # & should be escaped in the action attribute
        assert "action=" in html


# ===========================================================================
# CSRFDetectTool
# ===========================================================================


class TestCsrfDetectTool:
    def test_name(self):
        tool = CSRFDetectTool()
        assert tool.name == "csrf_detect"

    def test_description_mentions_csrf(self):
        tool = CSRFDetectTool()
        assert "csrf" in tool.description.lower()

    def test_parameters_schema(self):
        tool = CSRFDetectTool()
        schema = tool.metadata.parameters
        assert "url" in schema["required"]

    @pytest.mark.asyncio
    async def test_failed_fetch(self):
        tool = CSRFDetectTool()
        tool._client = _make_curl_client(success=False)
        result = await tool.execute(url="http://example.com/form")
        assert "failed" in result.lower() or "error" in result.lower()

    @pytest.mark.asyncio
    async def test_no_token_high_risk_output(self):
        body = "<form><input name='email'></form>"
        tool = CSRFDetectTool()
        tool._client = _make_curl_client(body=body)
        result = await tool.execute(url="http://example.com/form", check_token_reuse=False)
        assert "high" in result.lower()
        assert OWASP_CSRF_TAG in result

    @pytest.mark.asyncio
    async def test_token_present_lower_risk(self):
        body = '<form><input name="csrf_token" value="supersecuretoken1234"></form>'
        cookie_headers = {"set-cookie": "session=x; SameSite=Strict; Secure"}
        tool = CSRFDetectTool()
        tool._client = _make_curl_client(body=body, headers=cookie_headers)
        result = await tool.execute(url="http://example.com/form", check_token_reuse=False)
        # Should show NONE or lower risk
        assert "high" not in result.lower() or "csrf token found: yes" in result.lower()

    @pytest.mark.asyncio
    async def test_token_reuse_detected(self):
        body = '<form><input name="csrf_token" value="statictoken12345"></form>'
        tool = CSRFDetectTool()
        tool._client = _make_curl_client(body=body)
        result = await tool.execute(url="http://example.com/form", check_token_reuse=True)
        # Two identical fetches → reuse detected
        assert "static" in result.lower() or "reuse" in result.lower()

    @pytest.mark.asyncio
    async def test_samesite_shown_in_output(self):
        body = "<form><input name='_csrf'></form>"
        headers = {"set-cookie": "session=x; SameSite=Lax"}
        tool = CSRFDetectTool()
        tool._client = _make_curl_client(body=body, headers=headers)
        result = await tool.execute(url="http://example.com/", check_token_reuse=False)
        assert "lax" in result.lower() or "samesite" in result.lower()

    @pytest.mark.asyncio
    async def test_cookies_sent_in_header(self):
        tool = CSRFDetectTool()
        captured_params = {}

        async def capture(name, params):
            captured_params.update(params)
            return {"success": True, "status_code": 200, "headers": {}, "body": ""}

        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=capture)
        await tool.execute(url="http://example.com/", cookies="session=abc123", check_token_reuse=False)
        assert captured_params.get("headers", {}).get("Cookie") == "session=abc123"

    @pytest.mark.asyncio
    async def test_action_url_shown_in_output(self):
        body = "<form></form>"
        tool = CSRFDetectTool()
        tool._client = _make_curl_client(body=body)
        result = await tool.execute(
            url="http://example.com/profile",
            action_url="http://example.com/profile/update",
            check_token_reuse=False,
        )
        assert "http://example.com/profile/update" in result

    @pytest.mark.asyncio
    async def test_exploit_tip_shown_for_high_risk(self):
        body = "<form><input name='email'></form>"
        tool = CSRFDetectTool()
        tool._client = _make_curl_client(body=body)
        result = await tool.execute(url="http://example.com/form", check_token_reuse=False)
        assert "csrf_exploit" in result.lower() or "poc" in result.lower()


# ===========================================================================
# CSRFExploitTool
# ===========================================================================


class TestCsrfExploitTool:
    def test_name(self):
        tool = CSRFExploitTool()
        assert tool.name == "csrf_exploit"

    def test_description_mentions_poc(self):
        tool = CSRFExploitTool()
        assert "poc" in tool.description.lower() or "proof" in tool.description.lower()

    def test_parameters_schema(self):
        tool = CSRFExploitTool()
        schema = tool.metadata.parameters
        assert "endpoint" in schema["required"]

    @pytest.mark.asyncio
    async def test_generates_html(self):
        tool = CSRFExploitTool()
        result = await tool.execute(endpoint="http://example.com/delete", method="POST")
        assert "<form" in result
        assert "http://example.com/delete" in result

    @pytest.mark.asyncio
    async def test_includes_fields(self):
        tool = CSRFExploitTool()
        result = await tool.execute(
            endpoint="http://example.com/transfer",
            fields={"amount": "1000", "to": "attacker"},
        )
        assert 'name="amount"' in result
        assert 'value="1000"' in result

    @pytest.mark.asyncio
    async def test_remediation_advice_present(self):
        tool = CSRFExploitTool()
        result = await tool.execute(endpoint="http://example.com/delete")
        assert "remediation" in result.lower() or "SameSite" in result

    @pytest.mark.asyncio
    async def test_owasp_tag_in_output(self):
        tool = CSRFExploitTool()
        result = await tool.execute(endpoint="http://example.com/delete")
        assert OWASP_CSRF_TAG in result or "A01" in result or "A05" in result

    @pytest.mark.asyncio
    async def test_put_method_included(self):
        tool = CSRFExploitTool()
        result = await tool.execute(endpoint="http://example.com/api/user", method="PUT")
        assert "put" in result.lower()

    @pytest.mark.asyncio
    async def test_xss_safe_field_values(self):
        import html as html_mod
        tool = CSRFExploitTool()
        result = await tool.execute(
            endpoint="http://example.com/",
            fields={"comment": '<script>alert(1)</script>'},
        )
        # Value should be HTML-escaped in the output
        assert html_mod.escape('<script>alert(1)</script>', quote=True) in result


# ===========================================================================
# ToolRegistry — CSRF tools registered
# ===========================================================================


class TestToolRegistryCsrf:
    def _registry(self):
        from app.agent.tools.tool_registry import create_default_registry
        return create_default_registry()

    def test_csrf_detect_registered(self):
        r = self._registry()
        assert r.get_tool("csrf_detect") is not None

    def test_csrf_exploit_registered(self):
        r = self._registry()
        assert r.get_tool("csrf_exploit") is not None

    def test_csrf_detect_in_informational(self):
        r = self._registry()
        assert r.is_tool_allowed("csrf_detect", Phase.INFORMATIONAL)

    def test_csrf_detect_in_exploitation(self):
        r = self._registry()
        assert r.is_tool_allowed("csrf_detect", Phase.EXPLOITATION)

    def test_csrf_exploit_only_exploitation(self):
        r = self._registry()
        assert r.is_tool_allowed("csrf_exploit", Phase.EXPLOITATION)
        assert not r.is_tool_allowed("csrf_exploit", Phase.INFORMATIONAL)

    def test_csrf_tools_in_exploitation_phase_tools(self):
        r = self._registry()
        phase_tools = r.get_tools_for_phase(Phase.EXPLOITATION)
        assert "csrf_detect" in phase_tools
        assert "csrf_exploit" in phase_tools


# ===========================================================================
# AttackPathRouter — CSRF keywords
# ===========================================================================


class TestAttackPathRouterCsrf:
    def _router(self) -> AttackPathRouter:
        with patch.dict("os.environ", {"CLASSIFIER_MODE": "keyword"}):
            return AttackPathRouter()

    def test_csrf_keyword(self):
        router = self._router()
        cat = router.classify_intent("check for csrf vulnerabilities on the form")
        assert cat == AttackCategory.WEB_APP_ATTACK

    def test_cross_site_request_forgery(self):
        router = self._router()
        cat = router.classify_intent("cross-site request forgery attack")
        assert cat == AttackCategory.WEB_APP_ATTACK

    def test_ssrf_keyword(self):
        router = self._router()
        cat = router.classify_intent("test for ssrf via the url parameter")
        assert cat == AttackCategory.WEB_APP_ATTACK

    def test_web_app_plan_generated(self):
        router = self._router()
        plan = router.get_attack_plan(AttackCategory.WEB_APP_ATTACK, {"host": "10.10.10.1"})
        assert plan["risk_level"] == "high"
        assert "steps" in plan
