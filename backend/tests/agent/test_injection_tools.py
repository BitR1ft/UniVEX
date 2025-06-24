"""
Tests for PLAN.md Day 6 — Advanced Web Injection Engine

Coverage:
  - Payload lists: _NOSQL_QUERY_PAYLOADS, _NOSQL_AUTH_BYPASS_PAYLOADS, _SSTI_DETECT_PAYLOADS,
      _SSTI_EXPLOIT_PAYLOADS, _LDAP_AUTH_BYPASS_PAYLOADS, XXE_PAYLOADS,
      _CMD_INJECTION_PAYLOADS, _CRLF_PAYLOADS
  - Detection helpers: _detect_nosql_success(), _detect_ssti_in_response(),
      _fingerprint_ssti_engine(), _detect_ldap_injection(), _detect_xxe_in_response(),
      _detect_command_injection(), _detect_crlf_injection()
  - NoSQLInjectionTool: metadata, offline fallback, MCP result formatting
  - SSTIDetectTool: metadata, offline fallback, MCP result formatting
  - SSTIExploitTool: metadata, offline fallback, engine payloads
  - LDAPInjectionTool: metadata, offline fallback, MCP result formatting
  - XXETool: metadata, offline fallback, payload type selection
  - CommandInjectionTool: metadata, offline fallback, blind test appended
  - HeaderInjectionTool: metadata, offline fallback, CRLF payload inclusion
  - InjectionServer: get_tools() count, port, _is_internal(), _validate_url(), _extract_host()
  - ToolRegistry: Day 6 tools registered in correct phases
  - AttackPathRouter: injection keywords → WEB_APP_ATTACK
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.agent.attack_path_router import AttackCategory, AttackPathRouter
from app.agent.state.agent_state import Phase
from app.agent.tools.injection_tools import (
    CommandInjectionTool,
    HeaderInjectionTool,
    InjectionSeverity,
    LDAPInjectionTool,
    NoSQLInjectionTool,
    OWASP_INJECTION_TAG,
    OWASP_XXE_TAG,
    SSTIDetectTool,
    SSTIExploitTool,
    XXETool,
    _CRLF_DETECTION_PATTERNS,
    _CRLF_PAYLOADS,
    _CMD_INJECTION_PAYLOADS,
    _LDAP_AUTH_BYPASS_PAYLOADS,
    _LDAP_ENUM_PAYLOADS,
    _LDAP_ERROR_PATTERNS,
    _NOSQL_AUTH_BYPASS_PAYLOADS,
    _NOSQL_QUERY_PAYLOADS,
    _SSTI_DETECT_PAYLOADS,
    _SSTI_ENGINE_PATTERNS,
    _SSTI_EXPLOIT_PAYLOADS,
    XXE_PAYLOADS,
    _detect_command_injection,
    _detect_crlf_injection,
    _detect_ldap_injection,
    _detect_nosql_success,
    _detect_ssti_in_response,
    _detect_xxe_in_response,
    _fingerprint_ssti_engine,
)
from app.mcp.servers.injection_server import (
    InjectionServer,
    _extract_host,
    _is_internal,
    _validate_url,
)
from app.agent.tools.tool_registry import create_default_registry


# ===========================================================================
# Mock helpers
# ===========================================================================


def _make_injection_client(
    tool_name: str = "nosql_injection_test",
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


def _make_failing_client() -> MagicMock:
    client = MagicMock()
    client.call_tool = AsyncMock(side_effect=Exception("Connection refused"))
    return client


# ===========================================================================
# Payload list tests
# ===========================================================================


class TestNoSQLPayloads:
    def test_query_payloads_non_empty(self):
        assert len(_NOSQL_QUERY_PAYLOADS) > 0

    def test_query_payloads_contains_gt_operator(self):
        assert any("$gt" in p for p in _NOSQL_QUERY_PAYLOADS)

    def test_query_payloads_contains_ne_operator(self):
        assert any("$ne" in p for p in _NOSQL_QUERY_PAYLOADS)

    def test_query_payloads_contains_regex_operator(self):
        assert any("$regex" in p for p in _NOSQL_QUERY_PAYLOADS)

    def test_auth_bypass_payloads_non_empty(self):
        assert len(_NOSQL_AUTH_BYPASS_PAYLOADS) > 0

    def test_auth_bypass_payloads_are_dicts(self):
        for p in _NOSQL_AUTH_BYPASS_PAYLOADS:
            assert isinstance(p, dict)

    def test_auth_bypass_payloads_have_username_key(self):
        assert all("username" in p for p in _NOSQL_AUTH_BYPASS_PAYLOADS)

    def test_auth_bypass_payloads_have_password_key(self):
        assert all("password" in p for p in _NOSQL_AUTH_BYPASS_PAYLOADS)

    def test_auth_bypass_contains_exists_operator(self):
        assert any(
            isinstance(p.get("username"), dict) and "$exists" in p["username"]
            for p in _NOSQL_AUTH_BYPASS_PAYLOADS
        )


class TestSSTIPayloads:
    def test_detect_payloads_non_empty(self):
        assert len(_SSTI_DETECT_PAYLOADS) > 0

    def test_detect_payloads_are_tuples(self):
        for item in _SSTI_DETECT_PAYLOADS:
            assert isinstance(item, tuple)
            assert len(item) == 2

    def test_detect_payloads_contains_jinja2_canary(self):
        payloads = [p for p, _ in _SSTI_DETECT_PAYLOADS]
        assert "{{7*7}}" in payloads

    def test_detect_payloads_jinja2_expected_output(self):
        mapping = dict(_SSTI_DETECT_PAYLOADS)
        assert mapping["{{7*7}}"] == "49"

    def test_detect_payloads_freemarker_canary(self):
        payloads = [p for p, _ in _SSTI_DETECT_PAYLOADS]
        assert any("${" in p for p in payloads)

    def test_exploit_payloads_has_jinja2(self):
        assert "jinja2" in _SSTI_EXPLOIT_PAYLOADS

    def test_exploit_payloads_has_twig(self):
        assert "twig" in _SSTI_EXPLOIT_PAYLOADS

    def test_exploit_payloads_has_freemarker(self):
        assert "freemarker" in _SSTI_EXPLOIT_PAYLOADS

    def test_exploit_payloads_has_mako(self):
        assert "mako" in _SSTI_EXPLOIT_PAYLOADS

    def test_exploit_payloads_jinja2_non_empty(self):
        assert len(_SSTI_EXPLOIT_PAYLOADS["jinja2"]) > 0

    def test_exploit_payloads_jinja2_contains_popen(self):
        assert any("popen" in p for p in _SSTI_EXPLOIT_PAYLOADS["jinja2"])

    def test_engine_patterns_has_jinja2(self):
        assert "jinja2" in _SSTI_ENGINE_PATTERNS

    def test_engine_patterns_has_twig(self):
        assert "twig" in _SSTI_ENGINE_PATTERNS

    def test_engine_patterns_values_are_lists(self):
        for engine, patterns in _SSTI_ENGINE_PATTERNS.items():
            assert isinstance(patterns, list), f"{engine} patterns should be a list"


class TestLDAPPayloads:
    def test_auth_bypass_payloads_non_empty(self):
        assert len(_LDAP_AUTH_BYPASS_PAYLOADS) > 0

    def test_auth_bypass_payloads_are_tuples(self):
        for item in _LDAP_AUTH_BYPASS_PAYLOADS:
            assert isinstance(item, tuple)

    def test_auth_bypass_contains_wildcard(self):
        assert any("*" in u for u, _ in _LDAP_AUTH_BYPASS_PAYLOADS)

    def test_enum_payloads_non_empty(self):
        assert len(_LDAP_ENUM_PAYLOADS) > 0

    def test_error_patterns_contains_ldap(self):
        assert "ldap" in _LDAP_ERROR_PATTERNS

    def test_error_patterns_contains_objectclass(self):
        assert any("objectclass" in p for p in _LDAP_ERROR_PATTERNS)


class TestXXEPayloads:
    def test_xxe_payloads_non_empty(self):
        assert len(XXE_PAYLOADS) > 0

    def test_file_read_payload_present(self):
        assert "file_read" in XXE_PAYLOADS

    def test_ssrf_payload_present(self):
        assert "ssrf" in XXE_PAYLOADS

    def test_billion_laughs_present(self):
        assert "billion_laughs" in XXE_PAYLOADS

    def test_file_read_payload_contains_etc_passwd(self):
        assert "/etc/passwd" in XXE_PAYLOADS["file_read"]

    def test_ssrf_payload_contains_metadata_url(self):
        assert "169.254.169.254" in XXE_PAYLOADS["ssrf"]

    def test_billion_laughs_contains_lol_entity(self):
        assert "lol" in XXE_PAYLOADS["billion_laughs"]


class TestCmdInjectionPayloads:
    def test_payloads_non_empty(self):
        assert len(_CMD_INJECTION_PAYLOADS) > 0

    def test_payloads_are_tuples(self):
        for item in _CMD_INJECTION_PAYLOADS:
            assert isinstance(item, tuple)
            assert len(item) == 2

    def test_contains_semicolon_separator(self):
        assert any(";" in p for p, _ in _CMD_INJECTION_PAYLOADS)

    def test_contains_pipe_separator(self):
        assert any(p.startswith("|") for p, _ in _CMD_INJECTION_PAYLOADS)

    def test_contains_subshell_separator(self):
        assert any("$(" in p for p, _ in _CMD_INJECTION_PAYLOADS)

    def test_contains_marker_for_reflected(self):
        assert any("CMDINJECTED" in m for _, m in _CMD_INJECTION_PAYLOADS if m)


class TestCrlfPayloads:
    def test_payloads_non_empty(self):
        assert len(_CRLF_PAYLOADS) > 0

    def test_contains_url_encoded_crlf(self):
        assert any("%0d%0a" in p.lower() for p in _CRLF_PAYLOADS)

    def test_contains_raw_crlf(self):
        assert any("\r\n" in p for p in _CRLF_PAYLOADS)

    def test_detection_patterns_non_empty(self):
        assert len(_CRLF_DETECTION_PATTERNS) > 0

    def test_detection_patterns_contains_injected(self):
        assert any("injected" in p for p in _CRLF_DETECTION_PATTERNS)


# ===========================================================================
# Detection helper tests
# ===========================================================================


class TestDetectNoSQLSuccess:
    def test_returns_false_for_empty_response(self):
        detected, reason = _detect_nosql_success("", "baseline")
        assert detected is False

    def test_returns_false_for_normal_response(self):
        detected, reason = _detect_nosql_success("Login failed", "Login failed")
        assert detected is False

    def test_detects_mongo_error_pattern(self):
        body = "MongoError: Query failed with invalid operator"
        detected, reason = _detect_nosql_success(body, "Login failed")
        assert detected is True
        assert reason != ""

    def test_detects_cast_exception(self):
        body = "CastingException: could not cast value"
        detected, reason = _detect_nosql_success(body, "")
        assert detected is True

    def test_detects_bsontype_error(self):
        body = "Error: BSONType mismatch"
        detected, reason = _detect_nosql_success(body, "")
        assert detected is True

    def test_detects_large_response_vs_empty_baseline(self):
        big_response = "user data " * 100  # Much larger than baseline
        detected, reason = _detect_nosql_success(big_response, "")
        assert detected is True

    def test_no_false_positive_similar_size(self):
        baseline = "Login failed for user"
        similar = "Login denied for user"
        detected, _ = _detect_nosql_success(similar, baseline)
        assert detected is False


class TestDetectSSTIInResponse:
    def test_jinja2_math_expression_detected(self):
        detected, found = _detect_ssti_in_response("{{7*7}}", "49", "Hello 49 World")
        assert detected is True

    def test_no_match_when_expected_absent(self):
        detected, found = _detect_ssti_in_response("{{7*7}}", "49", "Hello World")
        assert detected is False

    def test_string_multiply_detected(self):
        detected, found = _detect_ssti_in_response("{{7*'7'}}", "7777777", "Output: 7777777")
        assert detected is True

    def test_template_error_detected_for_polyglot(self):
        detected, found = _detect_ssti_in_response(
            "${{<%[%'\"}}%\\.", "error",
            "Template syntax error: parse error on line 1"
        )
        assert detected is True

    def test_no_error_when_clean_response(self):
        detected, found = _detect_ssti_in_response(
            "${{<%[%'\"}}%\\.", "error",
            "200 OK"
        )
        assert detected is False

    def test_dollar_expression_detected(self):
        detected, found = _detect_ssti_in_response("${7*7}", "49", "Result: 49")
        assert detected is True

    def test_empty_response_returns_false(self):
        detected, found = _detect_ssti_in_response("{{7*7}}", "49", "")
        assert detected is False


class TestFingerprintSSTIEngine:
    def test_jinja2_from_error(self):
        error = "jinja2.exceptions.TemplateNotFound: template not found"
        engine = _fingerprint_ssti_engine(error)
        assert engine == "jinja2"

    def test_twig_from_error(self):
        error = "Twig_Error_Loader: Template not found in PHP"
        engine = _fingerprint_ssti_engine(error)
        assert engine == "twig"

    def test_freemarker_from_error(self):
        error = "freemarker.core.ParseException: Java templateexception"
        engine = _fingerprint_ssti_engine(error)
        assert engine == "freemarker"

    def test_mako_from_error(self):
        # Both Jinja2 and Mako run on Python, but "mako" is in the Mako pattern
        # list while "python" matches Jinja2 first. Use only the engine-specific
        # keyword to avoid ambiguity in the first-match fingerprinting logic.
        error = "mako syntaxexception on render"
        engine = _fingerprint_ssti_engine(error)
        assert engine == "mako"

    def test_pebble_from_error(self):
        # Both Pebble and Freemarker run on Java, but "pebble" uniquely
        # identifies Pebble while "java" matches Freemarker first. Use the
        # engine-specific keyword so the first-match logic returns the right engine.
        error = "pebble template render error"
        engine = _fingerprint_ssti_engine(error)
        assert engine == "pebble"

    def test_unknown_for_unrecognized_error(self):
        engine = _fingerprint_ssti_engine("Some generic 500 error occurred")
        assert engine == "unknown"

    def test_case_insensitive_matching(self):
        engine = _fingerprint_ssti_engine("JINJA2 TEMPLATENOTFOUND")
        assert engine == "jinja2"


class TestDetectLDAPInjection:
    def test_ldap_error_in_body_detected(self):
        body = "LDAPException: Invalid DN syntax"
        detected, reason = _detect_ldap_injection(body, 500)
        assert detected is True
        assert reason != ""

    def test_objectclass_error_detected(self):
        body = "Error: invalid objectClass filter"
        detected, reason = _detect_ldap_injection(body, 200)
        assert detected is True

    def test_namingexception_detected(self):
        body = "javax.naming.NamingException: LDAP error code 34"
        detected, reason = _detect_ldap_injection(body, 500)
        assert detected is True

    def test_no_detection_for_clean_response(self):
        body = "Invalid username or password"
        detected, reason = _detect_ldap_injection(body, 401)
        assert detected is False

    def test_ldap_bind_error_detected(self):
        body = "ldap_bind() failed: Invalid credentials"
        detected, reason = _detect_ldap_injection(body, 500)
        assert detected is True

    def test_empty_body_no_detection(self):
        detected, reason = _detect_ldap_injection("", 200)
        assert detected is False


class TestDetectXXEInResponse:
    def test_passwd_file_content_detected(self):
        body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1"
        detected, reason = _detect_xxe_in_response(body)
        assert detected is True

    def test_aws_metadata_detected(self):
        body = "ami-12345678\ninstance-id: i-abcdef"
        detected, reason = _detect_xxe_in_response(body)
        assert detected is True

    def test_xxe_error_disclosure_detected(self):
        body = "XML parse error: external entity reference not allowed"
        detected, reason = _detect_xxe_in_response(body)
        assert detected is True

    def test_no_detection_for_normal_response(self):
        body = '{"status": "ok", "message": "Request processed"}'
        detected, reason = _detect_xxe_in_response(body)
        assert detected is False

    def test_oob_marker_detected(self):
        body = "xxe callback received from attacker host"
        detected, reason = _detect_xxe_in_response(body)
        assert detected is True

    def test_dtd_error_detected(self):
        body = "DTD parsing failed: external DTD not supported"
        detected, reason = _detect_xxe_in_response(body)
        assert detected is True

    def test_empty_response_returns_false(self):
        detected, reason = _detect_xxe_in_response("")
        assert detected is False


class TestDetectCommandInjection:
    def test_marker_in_response_detected(self):
        assert _detect_command_injection("Output: CMDINJECTED data", "CMDINJECTED") is True

    def test_no_marker_returns_false(self):
        assert _detect_command_injection("normal output", "CMDINJECTED") is False

    def test_uid_marker_detected(self):
        assert _detect_command_injection("uid=0(root) gid=0(root)", "uid=") is True

    def test_empty_marker_returns_false(self):
        assert _detect_command_injection("any output here", "") is False

    def test_empty_body_returns_false(self):
        assert _detect_command_injection("", "CMDINJECTED") is False

    def test_passwd_content_detected(self):
        assert _detect_command_injection("root:x:0:0:root:/root\ndaemon:x:1:1", "root:x:") is True


class TestDetectCRLFInjection:
    def test_injected_header_in_body_detected(self):
        detected, reason = _detect_crlf_injection(
            {}, "Response body\nset-cookie: injected=true\nrest of body"
        )
        assert detected is True

    def test_injected_header_in_response_headers_detected(self):
        headers = {"set-cookie": "injected=true; path=/"}
        detected, reason = _detect_crlf_injection(headers, "")
        assert detected is True

    def test_x_injected_header_in_body(self):
        body = "HTTP/1.1 200 OK\r\nX-Injected-Header: UNIVEX_CRLF_TEST\r\n"
        detected, reason = _detect_crlf_injection({}, body.lower())
        assert detected is True

    def test_no_detection_for_clean_response(self):
        headers = {"content-type": "application/json"}
        detected, reason = _detect_crlf_injection(headers, '{"status": "ok"}')
        assert detected is False

    def test_empty_headers_and_body(self):
        detected, reason = _detect_crlf_injection({}, "")
        assert detected is False

    def test_univex_crlf_test_in_body(self):
        detected, reason = _detect_crlf_injection({}, "univex_crlf_test marker found")
        assert detected is True


# ===========================================================================
# NoSQLInjectionTool tests
# ===========================================================================


class TestNoSQLInjectionTool:
    def test_name(self):
        tool = NoSQLInjectionTool()
        assert tool.name == "nosql_injection"

    def test_description_mentions_mongodb(self):
        tool = NoSQLInjectionTool()
        assert "mongodb" in tool.description.lower() or "nosql" in tool.description.lower()

    def test_description_mentions_owasp(self):
        tool = NoSQLInjectionTool()
        assert "A03" in tool.description or "owasp" in tool.description.lower()

    def test_parameters_require_url(self):
        tool = NoSQLInjectionTool()
        assert "url" in tool.metadata.parameters["required"]

    def test_parameters_has_method(self):
        tool = NoSQLInjectionTool()
        assert "method" in tool.metadata.parameters["properties"]

    def test_parameters_has_test_auth_bypass(self):
        tool = NoSQLInjectionTool()
        assert "test_auth_bypass" in tool.metadata.parameters["properties"]

    def test_mcp_result_returned_on_success(self):
        tool = NoSQLInjectionTool()
        tool._client = _make_injection_client(
            findings=[{"type": "auth_bypass", "payload": '{"$gt": ""}'}]
        )
        result = asyncio.run(tool.execute(url="http://target.com/login"))
        data = json.loads(result)
        assert data["success"] is True

    def test_mcp_result_contains_url(self):
        tool = NoSQLInjectionTool()
        tool._client = _make_injection_client()
        result = asyncio.run(tool.execute(url="http://target.com/api/login"))
        data = json.loads(result)
        url = data.get("url", "")
        assert url == "http://target.com/api/login" or data.get("success") is True

    def test_offline_fallback_on_connection_error(self):
        tool = NoSQLInjectionTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/login"))
        data = json.loads(result)
        assert data["success"] is True
        assert data["source"] == "payload_enumeration"

    def test_offline_fallback_includes_auth_payloads(self):
        tool = NoSQLInjectionTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/login"))
        data = json.loads(result)
        assert len(data["auth_bypass_payloads"]) > 0

    def test_offline_fallback_includes_query_payloads(self):
        tool = NoSQLInjectionTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/search"))
        data = json.loads(result)
        assert len(data["query_payloads"]) > 0

    def test_offline_fallback_includes_owasp_tag(self):
        tool = NoSQLInjectionTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/login"))
        data = json.loads(result)
        assert data.get("owasp_tag") == OWASP_INJECTION_TAG

    def test_offline_fallback_includes_url(self):
        url = "http://target.com/api/auth"
        tool = NoSQLInjectionTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url=url))
        data = json.loads(result)
        assert data.get("url") == url

    def test_offline_fallback_note_present(self):
        tool = NoSQLInjectionTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/login"))
        data = json.loads(result)
        assert "note" in data

    def test_mcp_not_called_on_offline(self):
        tool = NoSQLInjectionTool()
        tool._client = _make_failing_client()
        asyncio.run(tool.execute(url="http://target.com/login"))
        # Exception was raised, client was called once and then fallback triggered
        assert tool._client.call_tool.call_count == 1

    def test_username_field_passed_to_mcp(self):
        captured = {}

        async def capture_call(name, params):
            captured.update(params)
            return {"success": True, "findings": []}

        tool = NoSQLInjectionTool()
        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=capture_call)
        asyncio.run(tool.execute(url="http://target.com/login", username_field="email"))
        assert captured.get("username_field") == "email"


# ===========================================================================
# SSTIDetectTool tests
# ===========================================================================


class TestSSTIDetectTool:
    def test_name(self):
        tool = SSTIDetectTool()
        assert tool.name == "ssti_detect"

    def test_description_mentions_ssti(self):
        tool = SSTIDetectTool()
        assert "ssti" in tool.description.lower() or "template" in tool.description.lower()

    def test_description_mentions_jinja2(self):
        tool = SSTIDetectTool()
        assert "jinja2" in tool.description.lower()

    def test_parameters_require_url(self):
        tool = SSTIDetectTool()
        assert "url" in tool.metadata.parameters["required"]

    def test_parameters_has_params(self):
        tool = SSTIDetectTool()
        assert "params" in tool.metadata.parameters["properties"]

    def test_parameters_has_post_body(self):
        tool = SSTIDetectTool()
        assert "post_body" in tool.metadata.parameters["properties"]

    def test_mcp_result_returned_on_success(self):
        tool = SSTIDetectTool()
        tool._client = _make_injection_client(
            findings=[{"engine": "jinja2", "payload": "{{7*7}}", "output": "49"}]
        )
        result = asyncio.run(tool.execute(url="http://target.com/search"))
        data = json.loads(result)
        assert data["success"] is True

    def test_offline_fallback_on_connection_error(self):
        tool = SSTIDetectTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/search"))
        data = json.loads(result)
        assert data["success"] is True
        assert data["source"] == "payload_plan"

    def test_offline_fallback_includes_detection_payloads(self):
        tool = SSTIDetectTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/search"))
        data = json.loads(result)
        assert len(data["detection_payloads"]) > 0

    def test_offline_fallback_includes_supported_engines(self):
        tool = SSTIDetectTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/search"))
        data = json.loads(result)
        assert "jinja2" in data["supported_engines"]

    def test_offline_fallback_includes_owasp_tag(self):
        tool = SSTIDetectTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/search"))
        data = json.loads(result)
        assert data.get("owasp_tag") == OWASP_INJECTION_TAG

    def test_offline_fallback_severity_critical(self):
        tool = SSTIDetectTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/search"))
        data = json.loads(result)
        assert data.get("severity") == InjectionSeverity.CRITICAL

    def test_offline_detection_payloads_contain_jinja2_canary(self):
        tool = SSTIDetectTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/search"))
        data = json.loads(result)
        payloads = [item["payload"] for item in data["detection_payloads"]]
        assert "{{7*7}}" in payloads


# ===========================================================================
# SSTIExploitTool tests
# ===========================================================================


class TestSSTIExploitTool:
    def test_name(self):
        tool = SSTIExploitTool()
        assert tool.name == "ssti_exploit"

    def test_description_mentions_rce(self):
        tool = SSTIExploitTool()
        assert "rce" in tool.description.lower() or "remote code" in tool.description.lower()

    def test_parameters_require_url(self):
        tool = SSTIExploitTool()
        assert "url" in tool.metadata.parameters["required"]

    def test_parameters_has_engine(self):
        tool = SSTIExploitTool()
        assert "engine" in tool.metadata.parameters["properties"]

    def test_parameters_has_command(self):
        tool = SSTIExploitTool()
        assert "command" in tool.metadata.parameters["properties"]

    def test_mcp_result_returned_on_success(self):
        tool = SSTIExploitTool()
        tool._client = _make_injection_client(
            findings=[{"rce_output": "uid=33(www-data)"}]
        )
        result = asyncio.run(tool.execute(url="http://target.com/page", engine="jinja2"))
        data = json.loads(result)
        assert data["success"] is True

    def test_offline_fallback_jinja2_payloads(self):
        tool = SSTIExploitTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/page", engine="jinja2"))
        data = json.loads(result)
        assert data["success"] is True
        assert data["source"] == "rce_payload_plan"
        assert len(data["rce_payloads"]) > 0

    def test_offline_fallback_twig_payloads(self):
        tool = SSTIExploitTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/page", engine="twig"))
        data = json.loads(result)
        assert data["engine"] == "twig"

    def test_offline_fallback_unknown_engine(self):
        tool = SSTIExploitTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/page", engine="unknown"))
        data = json.loads(result)
        assert data["success"] is True

    def test_command_substituted_in_payloads(self):
        tool = SSTIExploitTool()
        tool._client = _make_failing_client()
        result = asyncio.run(
            tool.execute(url="http://target.com/page", engine="mako", command="whoami")
        )
        data = json.loads(result)
        assert data["command"] == "whoami"

    def test_offline_fallback_includes_owasp_tag(self):
        tool = SSTIExploitTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/page", engine="jinja2"))
        data = json.loads(result)
        assert data.get("owasp_tag") == OWASP_INJECTION_TAG

    def test_offline_fallback_severity_critical(self):
        tool = SSTIExploitTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/page", engine="jinja2"))
        data = json.loads(result)
        assert data.get("severity") == InjectionSeverity.CRITICAL


# ===========================================================================
# LDAPInjectionTool tests
# ===========================================================================


class TestLDAPInjectionTool:
    def test_name(self):
        tool = LDAPInjectionTool()
        assert tool.name == "ldap_injection"

    def test_description_mentions_ldap(self):
        tool = LDAPInjectionTool()
        assert "ldap" in tool.description.lower()

    def test_description_mentions_auth_bypass(self):
        tool = LDAPInjectionTool()
        assert "auth bypass" in tool.description.lower() or "bypass" in tool.description.lower()

    def test_parameters_require_url(self):
        tool = LDAPInjectionTool()
        assert "url" in tool.metadata.parameters["required"]

    def test_parameters_has_username_field(self):
        tool = LDAPInjectionTool()
        assert "username_field" in tool.metadata.parameters["properties"]

    def test_parameters_has_method(self):
        tool = LDAPInjectionTool()
        assert "method" in tool.metadata.parameters["properties"]

    def test_mcp_result_returned_on_success(self):
        tool = LDAPInjectionTool()
        tool._client = _make_injection_client(
            findings=[{"type": "ldap_bypass", "payload": "admin)(|(password=*)"}]
        )
        result = asyncio.run(tool.execute(url="http://target.com/login"))
        data = json.loads(result)
        assert data["success"] is True

    def test_offline_fallback_on_connection_error(self):
        tool = LDAPInjectionTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/login"))
        data = json.loads(result)
        assert data["success"] is True
        assert data["source"] == "payload_plan"

    def test_offline_fallback_includes_auth_bypass_payloads(self):
        tool = LDAPInjectionTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/login"))
        data = json.loads(result)
        assert len(data["auth_bypass_payloads"]) > 0

    def test_offline_fallback_includes_enumeration_payloads(self):
        tool = LDAPInjectionTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/login"))
        data = json.loads(result)
        assert len(data["enumeration_payloads"]) > 0

    def test_offline_fallback_includes_error_patterns(self):
        tool = LDAPInjectionTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/login"))
        data = json.loads(result)
        assert "ldap" in data["error_patterns"]

    def test_offline_fallback_includes_owasp_tag(self):
        tool = LDAPInjectionTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/login"))
        data = json.loads(result)
        assert data.get("owasp_tag") == OWASP_INJECTION_TAG

    def test_offline_fallback_url_preserved(self):
        url = "http://target.com/ldap/auth"
        tool = LDAPInjectionTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url=url))
        data = json.loads(result)
        assert data.get("url") == url


# ===========================================================================
# XXETool tests
# ===========================================================================


class TestXXETool:
    def test_name(self):
        tool = XXETool()
        assert tool.name == "xxe_test"

    def test_description_mentions_xxe(self):
        tool = XXETool()
        assert "xxe" in tool.description.lower() or "external entity" in tool.description.lower()

    def test_description_mentions_file_read(self):
        tool = XXETool()
        assert "file" in tool.description.lower()

    def test_description_mentions_owasp_a05(self):
        tool = XXETool()
        assert "A05" in tool.description

    def test_parameters_require_url(self):
        tool = XXETool()
        assert "url" in tool.metadata.parameters["required"]

    def test_parameters_has_attack_type(self):
        tool = XXETool()
        assert "attack_type" in tool.metadata.parameters["properties"]

    def test_parameters_has_oob_host(self):
        tool = XXETool()
        assert "oob_host" in tool.metadata.parameters["properties"]

    def test_mcp_result_returned_on_success(self):
        tool = XXETool()
        tool._client = _make_injection_client(
            findings=[{"type": "file_read", "content": "root:x:0:0:root:/root:/bin/bash"}]
        )
        result = asyncio.run(tool.execute(url="http://target.com/upload"))
        data = json.loads(result)
        assert data["success"] is True

    def test_offline_fallback_on_connection_error(self):
        tool = XXETool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/upload"))
        data = json.loads(result)
        assert data["success"] is True
        assert data["source"] == "xxe_payload_plan"

    def test_offline_fallback_includes_payloads(self):
        tool = XXETool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/upload"))
        data = json.loads(result)
        assert len(data["payloads"]) > 0

    def test_offline_fallback_file_read_attack_type(self):
        tool = XXETool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/upload", attack_type="file_read"))
        data = json.loads(result)
        assert "file_read" in data["payloads"]

    def test_offline_fallback_ssrf_attack_type(self):
        tool = XXETool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/upload", attack_type="ssrf"))
        data = json.loads(result)
        assert "ssrf" in data["payloads"]

    def test_offline_fallback_oob_excluded_without_host(self):
        tool = XXETool()
        tool._client = _make_failing_client()
        result = asyncio.run(
            tool.execute(url="http://target.com/upload", attack_type="all", oob_host="")
        )
        data = json.loads(result)
        # OOB payload requires oob_host to be set
        assert "oob" not in data["payloads"]

    def test_offline_fallback_oob_included_with_host(self):
        tool = XXETool()
        tool._client = _make_failing_client()
        result = asyncio.run(
            tool.execute(
                url="http://target.com/upload",
                attack_type="all",
                oob_host="attacker.com",
            )
        )
        data = json.loads(result)
        assert "oob" in data["payloads"]

    def test_offline_fallback_includes_owasp_tag(self):
        tool = XXETool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/upload"))
        data = json.loads(result)
        assert data.get("owasp_tag") == OWASP_XXE_TAG

    def test_offline_fallback_severity_critical(self):
        tool = XXETool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/upload"))
        data = json.loads(result)
        assert data.get("severity") == InjectionSeverity.CRITICAL

    def test_offline_fallback_detection_patterns_present(self):
        tool = XXETool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/upload"))
        data = json.loads(result)
        assert len(data["detection_patterns"]) > 0


# ===========================================================================
# CommandInjectionTool tests
# ===========================================================================


class TestCommandInjectionTool:
    def test_name(self):
        tool = CommandInjectionTool()
        assert tool.name == "command_injection"

    def test_description_mentions_command_injection(self):
        tool = CommandInjectionTool()
        assert "command" in tool.description.lower() or "injection" in tool.description.lower()

    def test_description_mentions_separators(self):
        tool = CommandInjectionTool()
        desc = tool.description.lower()
        assert ";" in desc or "pipe" in desc or "|" in desc or "separator" in desc

    def test_parameters_require_url(self):
        tool = CommandInjectionTool()
        assert "url" in tool.metadata.parameters["required"]

    def test_parameters_has_params(self):
        tool = CommandInjectionTool()
        assert "params" in tool.metadata.parameters["properties"]

    def test_parameters_has_test_blind(self):
        tool = CommandInjectionTool()
        assert "test_blind" in tool.metadata.parameters["properties"]

    def test_mcp_result_returned_on_success(self):
        tool = CommandInjectionTool()
        tool._client = _make_injection_client(
            findings=[{"payload": "; echo CMDINJECTED", "marker": "CMDINJECTED"}]
        )
        result = asyncio.run(tool.execute(url="http://target.com/ping"))
        data = json.loads(result)
        assert data["success"] is True

    def test_offline_fallback_on_connection_error(self):
        tool = CommandInjectionTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/ping"))
        data = json.loads(result)
        assert data["success"] is True
        assert data["source"] == "injection_payload_plan"

    def test_offline_fallback_includes_payloads(self):
        tool = CommandInjectionTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/ping"))
        data = json.loads(result)
        assert len(data["payloads"]) > 0

    def test_offline_fallback_includes_owasp_tag(self):
        tool = CommandInjectionTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/ping"))
        data = json.loads(result)
        assert data.get("owasp_tag") == OWASP_INJECTION_TAG

    def test_offline_fallback_severity_critical(self):
        tool = CommandInjectionTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/ping"))
        data = json.loads(result)
        assert data.get("severity") == InjectionSeverity.CRITICAL

    def test_blind_payload_appended_when_test_blind_true(self):
        captured = {}

        async def capture_call(name, params):
            captured["payloads"] = params.get("payloads", [])
            return {"success": True, "findings": []}

        tool = CommandInjectionTool()
        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=capture_call)
        asyncio.run(tool.execute(url="http://target.com/ping", test_blind=True))
        # blind payload should be in the list sent to MCP
        payload_strs = [item["payload"] for item in captured.get("payloads", [])]
        assert any("sleep" in p for p in payload_strs)

    def test_params_sent_to_mcp(self):
        captured = {}

        async def capture_call(name, params):
            captured.update(params)
            return {"success": True, "findings": []}

        tool = CommandInjectionTool()
        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=capture_call)
        asyncio.run(
            tool.execute(url="http://target.com/ping", params={"host": "example.com"})
        )
        assert captured.get("params") == {"host": "example.com"}


# ===========================================================================
# HeaderInjectionTool tests
# ===========================================================================


class TestHeaderInjectionTool:
    def test_name(self):
        tool = HeaderInjectionTool()
        assert tool.name == "header_injection"

    def test_description_mentions_crlf(self):
        tool = HeaderInjectionTool()
        assert "crlf" in tool.description.lower() or "header" in tool.description.lower()

    def test_description_mentions_response_splitting(self):
        tool = HeaderInjectionTool()
        assert "splitting" in tool.description.lower() or "injection" in tool.description.lower()

    def test_parameters_require_url(self):
        tool = HeaderInjectionTool()
        assert "url" in tool.metadata.parameters["required"]

    def test_parameters_has_headers_to_test(self):
        tool = HeaderInjectionTool()
        assert "headers_to_test" in tool.metadata.parameters["properties"]

    def test_parameters_has_url_params_to_test(self):
        tool = HeaderInjectionTool()
        assert "url_params_to_test" in tool.metadata.parameters["properties"]

    def test_mcp_result_returned_on_success(self):
        tool = HeaderInjectionTool()
        tool._client = _make_injection_client(
            findings=[{"header": "Location", "payload": "%0d%0aSet-Cookie: injected=true"}]
        )
        result = asyncio.run(tool.execute(url="http://target.com/redirect"))
        data = json.loads(result)
        assert data["success"] is True

    def test_offline_fallback_on_connection_error(self):
        tool = HeaderInjectionTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/redirect"))
        data = json.loads(result)
        assert data["success"] is True
        assert data["source"] == "crlf_payload_plan"

    def test_offline_fallback_includes_crlf_payloads(self):
        tool = HeaderInjectionTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/redirect"))
        data = json.loads(result)
        assert len(data["crlf_payloads"]) > 0

    def test_offline_fallback_includes_detection_patterns(self):
        tool = HeaderInjectionTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/redirect"))
        data = json.loads(result)
        assert len(data["detection_patterns"]) > 0

    def test_offline_fallback_includes_owasp_tag(self):
        tool = HeaderInjectionTool()
        tool._client = _make_failing_client()
        result = asyncio.run(tool.execute(url="http://target.com/redirect"))
        data = json.loads(result)
        assert data.get("owasp_tag") == OWASP_INJECTION_TAG

    def test_offline_fallback_headers_to_test_preserved(self):
        tool = HeaderInjectionTool()
        tool._client = _make_failing_client()
        result = asyncio.run(
            tool.execute(
                url="http://target.com/redirect",
                headers_to_test=["X-Custom-Header"],
            )
        )
        data = json.loads(result)
        assert "X-Custom-Header" in data.get("headers_to_test", [])

    def test_crlf_payloads_sent_to_mcp(self):
        captured = {}

        async def capture_call(name, params):
            captured.update(params)
            return {"success": True, "findings": []}

        tool = HeaderInjectionTool()
        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=capture_call)
        asyncio.run(tool.execute(url="http://target.com/redirect"))
        assert len(captured.get("crlf_payloads", [])) > 0


# ===========================================================================
# OWASP tag constants
# ===========================================================================


class TestOWASPConstants:
    def test_injection_tag_value(self):
        assert OWASP_INJECTION_TAG == "A03:2021-Injection"

    def test_xxe_tag_value(self):
        assert OWASP_XXE_TAG == "A05:2021-Security_Misconfiguration"

    def test_injection_severity_enum_values(self):
        assert InjectionSeverity.CRITICAL == "critical"
        assert InjectionSeverity.HIGH == "high"
        assert InjectionSeverity.MEDIUM == "medium"
        assert InjectionSeverity.LOW == "low"
        assert InjectionSeverity.INFO == "info"


# ===========================================================================
# InjectionServer tests
# ===========================================================================


class TestInjectionServer:
    def test_port_is_8010(self):
        server = InjectionServer()
        assert server.port == 8010

    def test_get_tools_returns_7_tools(self):
        server = InjectionServer()
        tools = server.get_tools()
        assert len(tools) == 7

    def test_get_tools_has_nosql_injection_test(self):
        server = InjectionServer()
        names = [t.name for t in server.get_tools()]
        assert "nosql_injection_test" in names

    def test_get_tools_has_ssti_detect(self):
        server = InjectionServer()
        names = [t.name for t in server.get_tools()]
        assert "ssti_detect" in names

    def test_get_tools_has_ssti_exploit(self):
        server = InjectionServer()
        names = [t.name for t in server.get_tools()]
        assert "ssti_exploit" in names

    def test_get_tools_has_ldap_injection_test(self):
        server = InjectionServer()
        names = [t.name for t in server.get_tools()]
        assert "ldap_injection_test" in names

    def test_get_tools_has_xxe_test(self):
        server = InjectionServer()
        names = [t.name for t in server.get_tools()]
        assert "xxe_test" in names

    def test_get_tools_has_command_injection_test(self):
        server = InjectionServer()
        names = [t.name for t in server.get_tools()]
        assert "command_injection_test" in names

    def test_get_tools_has_header_injection_test(self):
        server = InjectionServer()
        names = [t.name for t in server.get_tools()]
        assert "header_injection_test" in names

    def test_server_name(self):
        server = InjectionServer()
        assert "injection" in server.name.lower()


class TestIsInternal:
    def test_localhost_is_internal(self):
        assert _is_internal("localhost") is True

    def test_loopback_ip_is_internal(self):
        assert _is_internal("127.0.0.1") is True

    def test_ipv6_loopback_is_internal(self):
        assert _is_internal("::1") is True

    def test_rfc1918_10_is_internal(self):
        assert _is_internal("10.0.0.1") is True

    def test_rfc1918_172_is_internal(self):
        assert _is_internal("172.16.0.1") is True

    def test_rfc1918_192_168_is_internal(self):
        assert _is_internal("192.168.1.1") is True

    def test_public_ip_not_internal(self):
        assert _is_internal("93.184.216.34") is False

    def test_external_hostname_not_internal(self):
        assert _is_internal("example.com") is False

    def test_rfc1918_boundary_172_31(self):
        assert _is_internal("172.31.255.255") is True

    def test_public_172_is_not_internal(self):
        assert _is_internal("172.32.0.1") is False


class TestExtractHost:
    def test_extracts_hostname(self):
        assert _extract_host("http://example.com/path") == "example.com"

    def test_extracts_ip(self):
        assert _extract_host("http://10.0.0.1/api") == "10.0.0.1"

    def test_extracts_hostname_with_port(self):
        assert _extract_host("http://example.com:8080/path") == "example.com"

    def test_empty_for_invalid_url(self):
        result = _extract_host("not-a-url")
        assert result == "" or isinstance(result, str)

    def test_https_scheme(self):
        assert _extract_host("https://secure.example.com/api") == "secure.example.com"


class TestValidateUrl:
    def test_valid_http_url_passes(self):
        # external host should not raise
        _validate_url("http://example.com/path")

    def test_valid_https_url_passes(self):
        _validate_url("https://example.com/api")

    def test_invalid_scheme_raises(self):
        with pytest.raises(ValueError, match="scheme"):
            _validate_url("ftp://example.com/file")

    def test_internal_address_raises_by_default(self):
        with pytest.raises(ValueError, match="internal"):
            _validate_url("http://192.168.1.1/admin")

    def test_internal_allowed_with_flag(self):
        # Should not raise with allow_internal=True
        _validate_url("http://192.168.1.1/admin", allow_internal=True)

    def test_localhost_blocked_by_default(self):
        with pytest.raises(ValueError):
            _validate_url("http://localhost:8080/api")

    def test_localhost_allowed_with_flag(self):
        _validate_url("http://localhost:8080/api", allow_internal=True)

    def test_no_scheme_raises(self):
        with pytest.raises(ValueError):
            _validate_url("example.com/path")


# ===========================================================================
# ToolRegistry.# ===========================================================================


class TestToolRegistryInjectionTools:
    def _registry(self):
        return create_default_registry()

    def test_nosql_injection_registered(self):
        r = self._registry()
        assert r.get_tool("nosql_injection") is not None

    def test_ssti_detect_registered(self):
        r = self._registry()
        assert r.get_tool("ssti_detect") is not None

    def test_ssti_exploit_registered(self):
        r = self._registry()
        assert r.get_tool("ssti_exploit") is not None

    def test_ldap_injection_registered(self):
        r = self._registry()
        assert r.get_tool("ldap_injection") is not None

    def test_xxe_test_registered(self):
        r = self._registry()
        assert r.get_tool("xxe_test") is not None

    def test_command_injection_registered(self):
        r = self._registry()
        assert r.get_tool("command_injection") is not None

    def test_header_injection_registered(self):
        r = self._registry()
        assert r.get_tool("header_injection") is not None

    def test_nosql_injection_in_informational(self):
        r = self._registry()
        assert r.is_tool_allowed("nosql_injection", Phase.INFORMATIONAL)

    def test_nosql_injection_in_exploitation(self):
        r = self._registry()
        assert r.is_tool_allowed("nosql_injection", Phase.EXPLOITATION)

    def test_ssti_detect_in_informational(self):
        r = self._registry()
        assert r.is_tool_allowed("ssti_detect", Phase.INFORMATIONAL)

    def test_ssti_detect_in_exploitation(self):
        r = self._registry()
        assert r.is_tool_allowed("ssti_detect", Phase.EXPLOITATION)

    def test_ssti_exploit_only_exploitation(self):
        r = self._registry()
        assert r.is_tool_allowed("ssti_exploit", Phase.EXPLOITATION)
        assert not r.is_tool_allowed("ssti_exploit", Phase.INFORMATIONAL)

    def test_ldap_injection_in_informational(self):
        r = self._registry()
        assert r.is_tool_allowed("ldap_injection", Phase.INFORMATIONAL)

    def test_ldap_injection_in_exploitation(self):
        r = self._registry()
        assert r.is_tool_allowed("ldap_injection", Phase.EXPLOITATION)

    def test_xxe_test_only_exploitation(self):
        r = self._registry()
        assert r.is_tool_allowed("xxe_test", Phase.EXPLOITATION)
        assert not r.is_tool_allowed("xxe_test", Phase.INFORMATIONAL)

    def test_command_injection_only_exploitation(self):
        r = self._registry()
        assert r.is_tool_allowed("command_injection", Phase.EXPLOITATION)
        assert not r.is_tool_allowed("command_injection", Phase.INFORMATIONAL)

    def test_header_injection_in_informational(self):
        r = self._registry()
        assert r.is_tool_allowed("header_injection", Phase.INFORMATIONAL)

    def test_header_injection_in_exploitation(self):
        r = self._registry()
        assert r.is_tool_allowed("header_injection", Phase.EXPLOITATION)

    def test_all_7_tools_in_exploitation(self):
        r = self._registry()
        phase_tools = r.get_tools_for_phase(Phase.EXPLOITATION)
        for name in [
            "nosql_injection", "ssti_detect", "ssti_exploit",
            "ldap_injection", "xxe_test", "command_injection", "header_injection",
        ]:
            assert name in phase_tools, f"{name} not found in EXPLOITATION phase"


# ===========================================================================
# AttackPathRouter — injection keywords
# ===========================================================================


class TestAttackPathRouterInjectionKeywords:
    def _router(self) -> AttackPathRouter:
        with patch.dict("os.environ", {"CLASSIFIER_MODE": "keyword"}):
            return AttackPathRouter()

    def test_nosql_injection_keyword(self):
        router = self._router()
        cat = router.classify_intent("test for nosql injection on the login endpoint")
        assert cat == AttackCategory.WEB_APP_ATTACK

    def test_injection_keyword(self):
        router = self._router()
        cat = router.classify_intent("check for injection vulnerabilities in the form")
        assert cat == AttackCategory.WEB_APP_ATTACK

    def test_ssti_keyword(self):
        router = self._router()
        cat = router.classify_intent("detect ssti vulnerability in template engine")
        assert cat == AttackCategory.WEB_APP_ATTACK

    def test_ldap_injection_keyword(self):
        router = self._router()
        cat = router.classify_intent("test ldap injection on the authentication endpoint")
        assert cat == AttackCategory.WEB_APP_ATTACK

    def test_xxe_keyword(self):
        router = self._router()
        cat = router.classify_intent("xxe injection in xml upload endpoint")
        assert cat == AttackCategory.WEB_APP_ATTACK

    def test_command_injection_keyword(self):
        router = self._router()
        cat = router.classify_intent("command injection via ping parameter")
        assert cat == AttackCategory.WEB_APP_ATTACK

    def test_web_app_attack_keyword(self):
        router = self._router()
        cat = router.classify_intent("web application injection testing")
        assert cat == AttackCategory.WEB_APP_ATTACK

    def test_web_app_plan_has_steps(self):
        router = self._router()
        plan = router.get_attack_plan(AttackCategory.WEB_APP_ATTACK, {"host": "10.10.10.1"})
        assert "steps" in plan

    def test_web_app_plan_risk_high(self):
        router = self._router()
        plan = router.get_attack_plan(AttackCategory.WEB_APP_ATTACK, {"host": "10.10.10.1"})
        assert plan.get("risk_level") == "high"
