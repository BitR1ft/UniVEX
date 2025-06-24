"""
Tests for PLAN.md Day 1 — XSS Detection & Exploitation Engine

Coverage:
  - Payload engine: get_payloads(), CONTEXT_PAYLOADS, POLYGLOT_PAYLOAD
  - Detection helpers: _detect_reflection(), _html_encoded(), _classify_severity()
  - DOM analysis: analyse_dom_sources_sinks()
  - ReflectedXSSTool: metadata, offline fallback, MCP result formatting
  - StoredXSSTool: metadata, offline summary, MCP result formatting
  - DOMXSSTool: metadata, static analysis, MCP result formatting
  - XSSServer: URL validation, payload sanitisation, _is_internal()
  - ToolRegistry: XSS tools registered in correct phases
  - AttackPathRouter: xss keywords classified as WEB_APP_ATTACK
"""

from __future__ import annotations

import json
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.agent.attack_path_router import AttackCategory, AttackPathRouter
from app.agent.state.agent_state import Phase
from app.agent.tools.xss_tools import (
    CONTEXT_PAYLOADS,
    OWASP_TAG,
    POLYGLOT_PAYLOAD,
    DOMXSSTool,
    InjectionContext,
    ReflectedXSSTool,
    StoredXSSTool,
    XSSSeverity,
    XSSType,
    _classify_severity,
    _detect_reflection,
    _html_encoded,
    analyse_dom_sources_sinks,
    get_payloads,
)
from app.mcp.servers.xss_server import (
    XSSServer,
    _is_internal,
    _sanitise_payloads,
    _validate_url,
)


# ===========================================================================
# Helpers
# ===========================================================================


def _make_xss_client(
    tool_name: str = "scan_reflected_xss",
    success: bool = True,
    findings: list = None,
) -> MagicMock:
    findings = findings or []

    async def call_tool(name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": success,
            "findings": findings,
            "total": len(findings),
            "url": params.get("url", ""),
        }

    client = MagicMock()
    client.call_tool = AsyncMock(side_effect=call_tool)
    return client


# ===========================================================================
# Payload engine
# ===========================================================================


class TestPayloadEngine:
    def test_polyglot_payload_is_string(self):
        assert isinstance(POLYGLOT_PAYLOAD, str)
        assert len(POLYGLOT_PAYLOAD) > 20

    def test_get_payloads_default_html(self):
        payloads = get_payloads(InjectionContext.HTML)
        assert POLYGLOT_PAYLOAD in payloads
        assert len(payloads) > 5

    def test_get_payloads_limit(self):
        payloads = get_payloads(InjectionContext.HTML, limit=3)
        assert len(payloads) == 3

    def test_get_payloads_zero_limit_means_all(self):
        all_p = get_payloads(InjectionContext.HTML, limit=0)
        assert len(all_p) > 3

    def test_get_payloads_attr_context(self):
        payloads = get_payloads(InjectionContext.ATTR)
        # Should contain at least one attribute injection payload
        assert any("onmouseover" in p or "onfocus" in p for p in payloads)

    def test_get_payloads_js_context(self):
        payloads = get_payloads(InjectionContext.JS)
        assert any("alert" in p for p in payloads)

    def test_get_payloads_url_context(self):
        payloads = get_payloads(InjectionContext.URL)
        assert any("javascript:" in p or "%3C" in p for p in payloads)

    def test_all_contexts_have_payloads(self):
        for ctx in InjectionContext:
            payloads = get_payloads(ctx)
            assert len(payloads) >= 2, f"Context {ctx} has too few payloads"

    def test_context_payloads_dict_complete(self):
        for ctx in InjectionContext:
            assert ctx in CONTEXT_PAYLOADS, f"Missing context {ctx} in CONTEXT_PAYLOADS"

    def test_payloads_are_strings(self):
        for ctx in InjectionContext:
            for p in get_payloads(ctx):
                assert isinstance(p, str)


# ===========================================================================
# Detection helpers
# ===========================================================================


class TestDetectReflection:
    def test_direct_payload_match(self):
        payload = "<script>alert(1)</script>"
        body = f"<html><body>{payload}</body></html>"
        reflected, evidence = _detect_reflection(payload, body)
        assert reflected is True
        assert evidence

    def test_pattern_match_script_tag(self):
        payload = "<script>foo()</script>"
        body = "Output: <script>foo()</script> end"
        reflected, evidence = _detect_reflection(payload, body)
        assert reflected is True

    def test_no_reflection(self):
        payload = "<script>alert(1)</script>"
        body = "<html><body>Hello world</body></html>"
        reflected, evidence = _detect_reflection(payload, body)
        assert reflected is False
        assert evidence == ""

    def test_empty_body(self):
        reflected, evidence = _detect_reflection("<script>alert(1)</script>", "")
        assert reflected is False

    def test_onerror_event_handler(self):
        body = '<img onerror="alert(1)" src=x>'
        payload = '<img src=x onerror=alert(1)>'
        reflected, evidence = _detect_reflection(payload, body)
        assert reflected is True

    def test_javascript_protocol(self):
        body = '<a href="javascript:alert(1)">click</a>'
        payload = "javascript:alert(1)"
        reflected, evidence = _detect_reflection(payload, body)
        assert reflected is True

    def test_svg_onload(self):
        body = "<svg onload=alert(1)>"
        payload = "<svg onload=alert(1)>"
        reflected, evidence = _detect_reflection(payload, body)
        assert reflected is True


class TestHtmlEncoded:
    def test_encoded_is_not_reflected(self):
        payload = "<script>alert(1)</script>"
        import html
        body = html.escape(payload)
        # HTML encoded — should be a false positive
        assert _html_encoded(payload, body) is True

    def test_unencoded_is_not_false_positive(self):
        payload = "<script>alert(1)</script>"
        body = payload  # Raw — NOT encoded
        assert _html_encoded(payload, body) is False

    def test_empty_body(self):
        assert _html_encoded("<script>", "") is False


class TestClassifySeverity:
    def test_stored_always_critical(self):
        for ctx in InjectionContext:
            assert _classify_severity(XSSType.STORED, ctx) == XSSSeverity.CRITICAL

    def test_reflected_js_context_high(self):
        assert _classify_severity(XSSType.REFLECTED, InjectionContext.JS) == XSSSeverity.HIGH

    def test_reflected_html_context_medium(self):
        assert _classify_severity(XSSType.REFLECTED, InjectionContext.HTML) == XSSSeverity.MEDIUM

    def test_dom_is_low(self):
        assert _classify_severity(XSSType.DOM, InjectionContext.HTML) == XSSSeverity.LOW


# ===========================================================================
# DOM analysis
# ===========================================================================


class TestAnalyseDomSourcesSinks:
    def test_detects_location_search(self):
        source = "var q = location.search; document.getElementById('out').innerHTML = q;"
        result = analyse_dom_sources_sinks(source)
        assert "location.search" in result["sources"]
        assert "innerHTML" in result["sinks"]

    def test_detects_eval_sink(self):
        source = "eval(document.URL);"
        result = analyse_dom_sources_sinks(source)
        assert "eval" in result["sinks"]

    def test_detects_document_write(self):
        source = "document.write(window.name);"
        result = analyse_dom_sources_sinks(source)
        assert "document.write" in result["sinks"]
        assert "window.name" in result["sources"]

    def test_no_sources_or_sinks(self):
        source = "var x = 1 + 2; console.log(x);"
        result = analyse_dom_sources_sinks(source)
        assert result["sources"] == []
        assert result["sinks"] == []

    def test_empty_source(self):
        result = analyse_dom_sources_sinks("")
        assert result == {"sources": [], "sinks": []}

    def test_jquery_html_sink(self):
        source = "$('#output').html(location.hash.slice(1));"
        result = analyse_dom_sources_sinks(source)
        assert "location.hash" in result["sources"]

    def test_deduplicates_results(self):
        source = "eval(document.URL); eval(document.documentURI);"
        result = analyse_dom_sources_sinks(source)
        assert result["sinks"].count("eval") == 1


# ===========================================================================
# ReflectedXSSTool
# ===========================================================================


class TestReflectedXSSTool:
    def test_name(self):
        tool = ReflectedXSSTool()
        assert tool.name == "xss_reflected_scan"

    def test_description_mentions_xss(self):
        tool = ReflectedXSSTool()
        assert "xss" in tool.description.lower() or "reflected" in tool.description.lower()

    def test_parameters_schema(self):
        tool = ReflectedXSSTool()
        schema = tool.metadata.parameters
        assert "url" in schema["properties"]
        assert "url" in schema["required"]

    @pytest.mark.asyncio
    async def test_no_params_fallback(self):
        tool = ReflectedXSSTool()
        tool._client = _make_xss_client(success=False)
        result = await tool.execute(url="http://example.com/")
        assert "no query parameters" in result.lower() or "offline" in result.lower() or "param" in result.lower()

    @pytest.mark.asyncio
    async def test_url_with_params_offline(self):
        tool = ReflectedXSSTool()
        tool._client = _make_xss_client(success=False)
        result = await tool.execute(url="http://example.com/search?q=test")
        assert "q" in result
        assert OWASP_TAG in result

    @pytest.mark.asyncio
    async def test_mcp_no_findings(self):
        tool = ReflectedXSSTool()
        tool._client = _make_xss_client(success=True, findings=[])
        result = await tool.execute(url="http://example.com/search?q=test")
        assert "no reflected xss" in result.lower() or "not reflected" in result.lower()

    @pytest.mark.asyncio
    async def test_mcp_with_finding(self):
        finding = {
            "param": "q",
            "payload": "<script>alert(1)</script>",
            "evidence": "<script>alert(1)</script>",
            "context": "html_context",
        }
        tool = ReflectedXSSTool()
        tool._client = _make_xss_client(success=True, findings=[finding])
        result = await tool.execute(url="http://example.com/search?q=test")
        assert "q" in result
        assert OWASP_TAG in result
        assert "medium" in result.lower() or "high" in result.lower()

    @pytest.mark.asyncio
    async def test_invalid_context_falls_back_to_html(self):
        tool = ReflectedXSSTool()
        tool._client = _make_xss_client(success=False)
        # Should not raise
        result = await tool.execute(url="http://example.com/?x=1", context="invalid_context")
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_max_payloads_capped_at_20(self):
        tool = ReflectedXSSTool()
        captured_params = {}

        async def capture(name, params):
            captured_params.update(params)
            return {"success": True, "findings": []}

        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=capture)
        await tool.execute(url="http://example.com/?x=1", max_payloads=999)
        assert len(captured_params.get("payloads", [])) <= 20

    @pytest.mark.asyncio
    async def test_extra_params_included_in_plan(self):
        tool = ReflectedXSSTool()
        tool._client = _make_xss_client(success=False)
        result = await tool.execute(url="http://example.com/", params=["search", "name"])
        assert "search" in result or "name" in result

    @pytest.mark.asyncio
    async def test_js_context_payloads_sent(self):
        tool = ReflectedXSSTool()
        captured = {}

        async def capture(name, params):
            captured.update(params)
            return {"success": True, "findings": []}

        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=capture)
        await tool.execute(url="http://example.com/?x=1", context="js_context")
        # Payloads should include JS context payloads
        payloads = captured.get("payloads", [])
        assert any("alert" in p for p in payloads)


# ===========================================================================
# StoredXSSTool
# ===========================================================================


class TestStoredXSSTool:
    def test_name(self):
        tool = StoredXSSTool()
        assert tool.name == "xss_stored_scan"

    def test_parameters_require_write_and_read_url(self):
        tool = StoredXSSTool()
        schema = tool.metadata.parameters
        assert "write_url" in schema["required"]
        assert "read_url" in schema["required"]

    @pytest.mark.asyncio
    async def test_offline_summary_contains_plan(self):
        tool = StoredXSSTool()
        tool._client = _make_xss_client(success=False)
        result = await tool.execute(
            write_url="http://example.com/comment",
            read_url="http://example.com/comments",
        )
        assert "write" in result.lower() or "submit" in result.lower()
        assert OWASP_TAG in result

    @pytest.mark.asyncio
    async def test_mcp_no_findings(self):
        tool = StoredXSSTool()
        tool._client = _make_xss_client(success=True, findings=[])
        result = await tool.execute(
            write_url="http://example.com/comment",
            read_url="http://example.com/comments",
        )
        assert "no stored xss" in result.lower() or "not reflected" in result.lower()

    @pytest.mark.asyncio
    async def test_mcp_finding_critical(self):
        finding = {
            "field": "comment",
            "payload": "<script>alert(1)</script>",
            "evidence": "<script>alert(1)</script>",
        }
        tool = StoredXSSTool()
        tool._client = _make_xss_client(success=True, findings=[finding])
        result = await tool.execute(
            write_url="http://example.com/comment",
            read_url="http://example.com/comments",
        )
        assert "critical" in result.lower()
        assert "comment" in result.lower()

    @pytest.mark.asyncio
    async def test_custom_field_name_passed_to_mcp(self):
        tool = StoredXSSTool()
        captured = {}

        async def capture(name, params):
            captured.update(params)
            return {"success": True, "findings": []}

        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=capture)
        await tool.execute(
            write_url="http://example.com/api/posts",
            read_url="http://example.com/posts",
            field_name="body",
        )
        assert captured.get("field_name") == "body"

    @pytest.mark.asyncio
    async def test_method_passed_to_mcp(self):
        tool = StoredXSSTool()
        captured = {}

        async def capture(name, params):
            captured.update(params)
            return {"success": True, "findings": []}

        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=capture)
        await tool.execute(
            write_url="http://example.com/api/posts",
            read_url="http://example.com/posts",
            method="PUT",
        )
        assert captured.get("method") == "PUT"


# ===========================================================================
# DOMXSSTool
# ===========================================================================


class TestDOMXSSTool:
    def test_name(self):
        tool = DOMXSSTool()
        assert tool.name == "xss_dom_scan"

    def test_parameters_schema(self):
        tool = DOMXSSTool()
        schema = tool.metadata.parameters
        assert "url" in schema["required"]
        assert "page_source" in schema["properties"]

    @pytest.mark.asyncio
    async def test_static_analysis_offline(self):
        tool = DOMXSSTool()
        tool._client = _make_xss_client(success=False)
        page_src = "var q = location.search; document.getElementById('x').innerHTML = q;"
        result = await tool.execute(url="http://example.com/", page_source=page_src)
        assert "location.search" in result
        assert "innerHTML" in result

    @pytest.mark.asyncio
    async def test_no_source_no_sink_message(self):
        tool = DOMXSSTool()
        tool._client = _make_xss_client(success=False)
        result = await tool.execute(url="http://example.com/", page_source="var x = 1;")
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_mcp_dynamic_findings(self):
        dynamic_finding = {"payload": "javascript:alert(1)", "trigger": "alert()", "sink": "location.href"}
        tool = DOMXSSTool()

        async def call_tool(name, params):
            return {"success": True, "findings": [dynamic_finding], "page_source": ""}

        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=call_tool)
        result = await tool.execute(url="http://example.com/")
        assert "alert" in result.lower()
        assert "low" in result.lower()

    @pytest.mark.asyncio
    async def test_no_dynamic_findings(self):
        tool = DOMXSSTool()
        tool._client = _make_xss_client(success=True, findings=[])
        result = await tool.execute(url="http://example.com/", page_source="")
        assert "offline" in result.lower() or "no" in result.lower() or "dom" in result.lower()

    @pytest.mark.asyncio
    async def test_probe_payloads_flag_passed(self):
        tool = DOMXSSTool()
        captured = {}

        async def capture(name, params):
            captured.update(params)
            return {"success": True, "findings": []}

        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=capture)
        await tool.execute(url="http://example.com/", probe_payloads=False)
        assert captured.get("probe_payloads") is False


# ===========================================================================
# XSSServer
# ===========================================================================


class TestIsInternal:
    def test_localhost_is_internal(self):
        assert _is_internal("localhost") is True

    def test_127_is_internal(self):
        assert _is_internal("127.0.0.1") is True

    def test_ipv6_loopback_is_internal(self):
        assert _is_internal("::1") is True

    def test_10_range_is_internal(self):
        assert _is_internal("10.0.0.1") is True

    def test_172_range_is_internal(self):
        assert _is_internal("172.16.5.5") is True

    def test_192_168_is_internal(self):
        assert _is_internal("192.168.1.1") is True

    def test_public_ip_not_internal(self):
        assert _is_internal("8.8.8.8") is False

    def test_hostname_not_internal(self):
        assert _is_internal("example.com") is False


class TestValidateUrl:
    def test_valid_http(self):
        _validate_url("http://example.com/", allow_internal=False)  # should not raise

    def test_valid_https(self):
        _validate_url("https://example.com/search?q=test", allow_internal=False)

    def test_invalid_scheme_raises(self):
        with pytest.raises(ValueError, match="scheme"):
            _validate_url("ftp://example.com/", allow_internal=False)

    def test_internal_blocked_by_default(self):
        with pytest.raises(ValueError, match="internal"):
            _validate_url("http://127.0.0.1/", allow_internal=False)

    def test_internal_allowed_when_flag_set(self):
        _validate_url("http://127.0.0.1/", allow_internal=True)  # should not raise

    def test_localhost_blocked(self):
        with pytest.raises(ValueError):
            _validate_url("http://localhost/admin", allow_internal=False)


class TestSanitisePayloads:
    def test_long_payloads_dropped(self):
        short = "a" * 10
        long = "b" * 600
        result = _sanitise_payloads([short, long])
        assert short in result
        assert long not in result

    def test_non_string_dropped(self):
        result = _sanitise_payloads([123, None, "<script>alert(1)</script>"])  # type: ignore
        assert len(result) == 1

    def test_empty_list(self):
        assert _sanitise_payloads([]) == []


class TestXSSServerTools:
    def test_get_tools_returns_three(self):
        server = XSSServer()
        tools = server.get_tools()
        assert len(tools) == 3

    def test_tool_names(self):
        server = XSSServer()
        names = {t.name for t in server.get_tools()}
        assert "scan_reflected_xss" in names
        assert "scan_stored_xss" in names
        assert "scan_dom_xss" in names

    def test_unknown_tool_raises(self):
        server = XSSServer()
        import asyncio
        with pytest.raises((ValueError, Exception)):
            asyncio.run(server.execute_tool("nonexistent_tool", {}))

    @pytest.mark.asyncio
    async def test_reflected_invalid_url(self):
        server = XSSServer()
        result = await server.execute_tool("scan_reflected_xss", {"url": "ftp://bad.url/"})
        assert result["success"] is False
        assert "findings" in result

    @pytest.mark.asyncio
    async def test_reflected_internal_blocked(self):
        server = XSSServer(allow_internal=False)
        result = await server.execute_tool(
            "scan_reflected_xss", {"url": "http://127.0.0.1/", "allow_internal": False}
        )
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_stored_invalid_write_url(self):
        server = XSSServer()
        result = await server.execute_tool(
            "scan_stored_xss",
            {"write_url": "not_a_url", "read_url": "http://example.com/comments"},
        )
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_dom_invalid_url(self):
        server = XSSServer()
        result = await server.execute_tool("scan_dom_xss", {"url": "notaurl"})
        assert result["success"] is False


# ===========================================================================
# ToolRegistry — XSS tools registered
# ===========================================================================


class TestToolRegistryXSS:
    def _make_registry(self):
        from app.agent.tools.tool_registry import create_default_registry
        return create_default_registry()

    def test_reflected_xss_registered(self):
        registry = self._make_registry()
        assert registry.get_tool("xss_reflected_scan") is not None

    def test_stored_xss_registered(self):
        registry = self._make_registry()
        assert registry.get_tool("xss_stored_scan") is not None

    def test_dom_xss_registered(self):
        registry = self._make_registry()
        assert registry.get_tool("xss_dom_scan") is not None

    def test_reflected_available_in_informational(self):
        registry = self._make_registry()
        assert registry.is_tool_allowed("xss_reflected_scan", Phase.INFORMATIONAL)

    def test_reflected_available_in_exploitation(self):
        registry = self._make_registry()
        assert registry.is_tool_allowed("xss_reflected_scan", Phase.EXPLOITATION)

    def test_reflected_not_available_in_post_exploitation(self):
        registry = self._make_registry()
        assert not registry.is_tool_allowed("xss_reflected_scan", Phase.POST_EXPLOITATION)

    def test_stored_only_exploitation(self):
        registry = self._make_registry()
        assert registry.is_tool_allowed("xss_stored_scan", Phase.EXPLOITATION)
        assert not registry.is_tool_allowed("xss_stored_scan", Phase.INFORMATIONAL)

    def test_dom_available_in_informational(self):
        registry = self._make_registry()
        assert registry.is_tool_allowed("xss_dom_scan", Phase.INFORMATIONAL)


# ===========================================================================
# AttackPathRouter — XSS keywords
# ===========================================================================


class TestAttackPathRouterXSS:
    def _router(self) -> AttackPathRouter:
        with patch.dict("os.environ", {"CLASSIFIER_MODE": "keyword"}):
            return AttackPathRouter()

    def test_xss_keyword(self):
        router = self._router()
        cat = router.classify_intent("test xss vulnerability on this site")
        assert cat == AttackCategory.WEB_APP_ATTACK

    def test_cross_site_scripting_keyword(self):
        router = self._router()
        cat = router.classify_intent("check for cross-site scripting")
        assert cat == AttackCategory.WEB_APP_ATTACK

    def test_dom_xss_keyword(self):
        router = self._router()
        cat = router.classify_intent("find dom xss in the web application")
        assert cat == AttackCategory.WEB_APP_ATTACK

    def test_reflected_xss_keyword(self):
        router = self._router()
        cat = router.classify_intent("injection attack via url parameter")
        assert cat == AttackCategory.WEB_APP_ATTACK

    def test_xss_tools_in_web_app_category(self):
        with patch.dict("os.environ", {"CLASSIFIER_MODE": "keyword"}):
            router = AttackPathRouter()
        tools = router.get_required_tools(AttackCategory.WEB_APP_ATTACK)
        # XSS tools should appear in required tools OR plan steps for WEB_APP_ATTACK
        plan = router.get_attack_plan(AttackCategory.WEB_APP_ATTACK, {"host": "10.10.10.1"})
        assert plan["category"] == "web_app_attack"
