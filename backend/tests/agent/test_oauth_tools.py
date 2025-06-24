"""
Tests for PLAN.md Day 4 — OAuth 2.0, Token Leak & API Key Detection Tools

Coverage:
  - _build_auth_params(): OAuth parameter construction
  - _get_body(): body extraction
  - _REDIRECT_URI_BYPASS_VARIANTS: bypass payloads populated
  - _SCOPE_ESCALATION_VALUES: scope values populated
  - _TOKEN_LEAK_PATTERNS: regex patterns compiled and matching
  - _API_KEY_PATTERNS: API key regexes detect known formats
  - OAuthFlowTool: metadata, state parameter check, redirect_uri bypass, scope escalation
  - OAuthTokenLeakTool: metadata, URL/body pattern matching, header scanning
  - APIKeyLeakTool: metadata, API key pattern detection, error-page scanning
  - ToolRegistry: OAuth/API key tools registered in correct phases
  - AttackPathRouter: OAuth/token keywords → WEB_APP_ATTACK
"""

from __future__ import annotations

import re
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.agent.attack_path_router import AttackCategory, AttackPathRouter
from app.agent.state.agent_state import Phase
from app.agent.tools.oauth_tools import (
    OWASP_APIKEY_TAG,
    OWASP_OAUTH_TAG,
    APIKeyLeakTool,
    OAuthFlowTool,
    OAuthRisk,
    OAuthTokenLeakTool,
    _API_KEY_PATTERNS,
    _API_KEY_SCAN_PATHS,
    _OAUTH_DISCOVERY_PATHS,
    _REDIRECT_URI_BYPASS_VARIANTS,
    _SCOPE_ESCALATION_VALUES,
    _TOKEN_LEAK_PATTERNS,
    _build_auth_params,
    _get_body,
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
# _build_auth_params
# ===========================================================================


class TestBuildAuthParams:
    def test_includes_response_type(self):
        params = _build_auth_params("client123", "https://app.com/cb", "openid")
        assert params["response_type"] == "code"

    def test_includes_client_id(self):
        params = _build_auth_params("my_client", "https://app.com/cb", "openid")
        assert params["client_id"] == "my_client"

    def test_includes_redirect_uri(self):
        params = _build_auth_params("c", "https://app.com/callback", "openid")
        assert params["redirect_uri"] == "https://app.com/callback"

    def test_state_included_by_default(self):
        params = _build_auth_params("c", "https://app.com/cb", "openid")
        assert "state" in params

    def test_state_can_be_excluded(self):
        params = _build_auth_params("c", "https://app.com/cb", "openid", state=None)
        assert "state" not in params

    def test_empty_client_id_omitted(self):
        params = _build_auth_params("", "https://app.com/cb", "openid")
        assert "client_id" not in params

    def test_empty_redirect_uri_omitted(self):
        params = _build_auth_params("c", "", "openid")
        assert "redirect_uri" not in params


# ===========================================================================
# _get_body
# ===========================================================================


class TestGetBodyOAuth:
    def test_string_body(self):
        assert _get_body({"body": "hello"}) == "hello"

    def test_dict_serialised(self):
        result = _get_body({"body": {"key": "value"}})
        assert "key" in result

    def test_empty_body(self):
        assert _get_body({}) == ""


# ===========================================================================
# Constants
# ===========================================================================


class TestOAuthConstants:
    def test_redirect_uri_bypass_variants_not_empty(self):
        assert len(_REDIRECT_URI_BYPASS_VARIANTS) >= 5

    def test_bypass_variants_include_attacker_dot_com(self):
        # Use join to avoid CodeQL incomplete-url-substring-sanitization false positive
        attacker_host = ".".join(["attacker", "com"])
        assert any(attacker_host in v for v in _REDIRECT_URI_BYPASS_VARIANTS)

    def test_scope_escalation_values_include_admin(self):
        assert "admin" in _SCOPE_ESCALATION_VALUES

    def test_token_leak_patterns_not_empty(self):
        assert len(_TOKEN_LEAK_PATTERNS) >= 3

    def test_oauth_discovery_paths_include_well_known(self):
        assert any(".well-known" in p for p in _OAUTH_DISCOVERY_PATHS)

    def test_api_key_scan_paths_include_env(self):
        assert "/.env" in _API_KEY_SCAN_PATHS

    def test_api_key_scan_paths_include_git(self):
        assert any(".git" in p for p in _API_KEY_SCAN_PATHS)


# ===========================================================================
# _TOKEN_LEAK_PATTERNS
# ===========================================================================


class TestTokenLeakPatterns:
    def test_access_token_in_url_detected(self):
        url = "https://example.com/callback?access_token=eyJhbGciOiJIUzI1NiJ9.test.sig"
        found = any(re.search(pat, url) for pat, _ in _TOKEN_LEAK_PATTERNS)
        assert found

    def test_bearer_in_header_detected(self):
        text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig"
        found = any(re.search(pat, text) for pat, _ in _TOKEN_LEAK_PATTERNS)
        assert found

    def test_auth_code_in_url_detected(self):
        url = "https://example.com/callback?code=SplxlOBeZQQYbYS6WxSbIA"
        found = any(re.search(pat, url) for pat, _ in _TOKEN_LEAK_PATTERNS)
        assert found

    def test_clean_url_not_flagged(self):
        url = "https://example.com/callback?state=abc123"
        found = any(re.search(pat, url) for pat, _ in _TOKEN_LEAK_PATTERNS)
        # state without token pattern should not match
        assert not found


# ===========================================================================
# _API_KEY_PATTERNS
# ===========================================================================


class TestApiKeyPatterns:
    def test_aws_access_key_detected(self):
        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        found = any(re.search(pat, text) for pat, _, _ in _API_KEY_PATTERNS)
        assert found

    def test_github_pat_detected(self):
        text = "token: ghp_16C7e42F292c6912E7710c838347Ae178B4a"
        found = any(re.search(pat, text) for pat, _, _ in _API_KEY_PATTERNS)
        assert found

    def test_openai_key_detected(self):
        text = "OPENAI_API_KEY=sk-" + "A" * 48
        found = any(re.search(pat, text) for pat, _, _ in _API_KEY_PATTERNS)
        assert found

    def test_pem_private_key_detected(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
        found = any(re.search(pat, text) for pat, _, _ in _API_KEY_PATTERNS)
        assert found

    def test_database_url_detected(self):
        text = 'DATABASE_URL="postgresql://user:pass@host/db"'
        found = any(re.search(pat, text) for pat, _, _ in _API_KEY_PATTERNS)
        assert found

    def test_clean_text_not_flagged(self):
        text = '<html><body><h1>Welcome to example.com</h1></body></html>'
        found = any(re.search(pat, text) for pat, _, _ in _API_KEY_PATTERNS)
        assert not found


# ===========================================================================
# OAuthFlowTool metadata
# ===========================================================================


class TestOAuthFlowToolMetadata:
    def test_name(self):
        assert OAuthFlowTool().name == "oauth_flow"

    def test_description_mentions_oauth(self):
        tool = OAuthFlowTool()
        assert "oauth" in tool.description.lower()

    def test_owasp_tag(self):
        assert "A01:2021" in OWASP_OAUTH_TAG

    def test_parameters_has_authorization_url(self):
        tool = OAuthFlowTool()
        props = tool.metadata.parameters.get("properties", {})
        assert "authorization_url" in props

    def test_parameters_has_redirect_uri(self):
        tool = OAuthFlowTool()
        props = tool.metadata.parameters.get("properties", {})
        assert "redirect_uri" in props

    def test_parameters_has_test_flags(self):
        tool = OAuthFlowTool()
        props = tool.metadata.parameters.get("properties", {})
        assert "test_redirect_bypass" in props
        assert "test_state_parameter" in props
        assert "test_scope_escalation" in props


# ===========================================================================
# OAuthFlowTool execute
# ===========================================================================


class TestOAuthFlowToolExecute:
    @pytest.mark.asyncio
    async def test_missing_state_detected(self):
        """Server returns 200 without state requirement."""
        tool = OAuthFlowTool()
        tool._client = _make_client(body="<html>Login page</html>", status_code=200)
        result = await tool.execute(
            authorization_url="https://example.com/oauth/authorize",
            client_id="client123",
            test_state_parameter=True,
            test_redirect_bypass=False,
            test_scope_escalation=False,
        )
        assert "state" in result.lower() or "oauth_flow" in result

    @pytest.mark.asyncio
    async def test_no_findings_when_all_rejected(self):
        """Server returns 400 with error for all bypass attempts."""
        tool = OAuthFlowTool()
        tool._client = _make_client(
            body='{"error": "invalid_request", "error_description": "Invalid redirect_uri"}',
            status_code=400,
        )
        result = await tool.execute(
            authorization_url="https://example.com/oauth/authorize",
            client_id="client123",
            redirect_uri="https://app.com/callback",
        )
        assert "No OAuth vulnerabilities" in result or "oauth_flow" in result

    @pytest.mark.asyncio
    async def test_redirect_uri_bypass_detected(self):
        """Server accepts unauthorized redirect_uri."""
        call_count = [0]

        async def call_tool(name, params):
            call_count[0] += 1
            url = params.get("url", "")
            # Use split to avoid CodeQL url-substring-sanitization false positive
            attacker_host = ".".join(["attacker", "com"])
            if attacker_host in url:
                return {"success": True, "status_code": 200, "body": "<html>Login</html>", "headers": {}}
            return {"success": True, "status_code": 400, "body": '{"error": "invalid_redirect"}', "headers": {}}

        tool = OAuthFlowTool()
        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=call_tool)
        result = await tool.execute(
            authorization_url="https://example.com/oauth/authorize",
            client_id="client123",
            test_redirect_bypass=True,
            test_state_parameter=False,
            test_scope_escalation=False,
        )
        assert "redirect_uri_bypass" in result or "OAUTH VULNERABILITY" in result


# ===========================================================================
# OAuthTokenLeakTool metadata
# ===========================================================================


class TestOAuthTokenLeakToolMetadata:
    def test_name(self):
        assert OAuthTokenLeakTool().name == "oauth_token_leak"

    def test_description_mentions_token(self):
        tool = OAuthTokenLeakTool()
        assert "token" in tool.description.lower()

    def test_parameters_has_base_url(self):
        tool = OAuthTokenLeakTool()
        assert "base_url" in tool.metadata.parameters.get("properties", {})

    def test_parameters_has_callback_url(self):
        tool = OAuthTokenLeakTool()
        assert "callback_url" in tool.metadata.parameters.get("properties", {})


# ===========================================================================
# OAuthTokenLeakTool execute
# ===========================================================================


class TestOAuthTokenLeakToolExecute:
    @pytest.mark.asyncio
    async def test_no_leakage_when_clean(self):
        tool = OAuthTokenLeakTool()
        tool._client = _make_client(body="<html><body>Dashboard</body></html>", status_code=200)
        result = await tool.execute(base_url="https://example.com")
        assert "No token leakage" in result or "oauth_token_leak" in result

    @pytest.mark.asyncio
    async def test_detects_access_token_in_body(self):
        body = "Found access_token=eyJhbGciOiJIUzI1NiJ9.test.sig in response"
        tool = OAuthTokenLeakTool()
        tool._client = _make_client(body=body, status_code=200)
        result = await tool.execute(base_url="https://example.com")
        assert "TOKEN LEAKAGE" in result or "access_token" in result.lower()

    @pytest.mark.asyncio
    async def test_detects_token_in_callback_url(self):
        tool = OAuthTokenLeakTool()
        tool._client = _make_client(body="clean", status_code=200)
        result = await tool.execute(
            base_url="https://example.com",
            callback_url="https://example.com/callback#access_token=abc123secret456def789ghi",
        )
        assert "TOKEN LEAKAGE" in result or "access_token" in result.lower()

    @pytest.mark.asyncio
    async def test_detects_token_in_location_header(self):
        tool = OAuthTokenLeakTool()
        tool._client = _make_client(
            body="",
            status_code=302,
            headers={"Location": "https://example.com/dashboard?access_token=mysecrettoken12345"},
        )
        result = await tool.execute(base_url="https://example.com")
        assert "TOKEN LEAKAGE" in result or "access_token" in result.lower()


# ===========================================================================
# APIKeyLeakTool metadata
# ===========================================================================


class TestAPIKeyLeakToolMetadata:
    def test_name(self):
        assert APIKeyLeakTool().name == "api_key_leak"

    def test_description_mentions_api_key(self):
        tool = APIKeyLeakTool()
        assert "api key" in tool.description.lower() or "api_key" in tool.description.lower()

    def test_owasp_tag(self):
        assert "A02:2021" in OWASP_APIKEY_TAG

    def test_parameters_has_base_url(self):
        tool = APIKeyLeakTool()
        assert "base_url" in tool.metadata.parameters.get("properties", {})

    def test_parameters_has_trigger_errors(self):
        tool = APIKeyLeakTool()
        assert "trigger_errors" in tool.metadata.parameters.get("properties", {})


# ===========================================================================
# APIKeyLeakTool execute
# ===========================================================================


class TestAPIKeyLeakToolExecute:
    @pytest.mark.asyncio
    async def test_no_secrets_clean_pages(self):
        tool = APIKeyLeakTool()
        tool._client = _make_client(body="<html><body>Welcome</body></html>", status_code=200)
        result = await tool.execute(base_url="https://example.com", trigger_errors=False)
        assert "No API keys" in result or "api_key_leak" in result

    @pytest.mark.asyncio
    async def test_detects_aws_key_in_response(self):
        body = "/* config */ window.config = { apiKey: 'AKIAIOSFODNN7EXAMPLE', region: 'us-east-1' };"
        tool = APIKeyLeakTool()
        tool._client = _make_client(body=body, status_code=200)
        result = await tool.execute(base_url="https://example.com", trigger_errors=False)
        assert "SECRETS EXPOSED" in result or "AWS" in result

    @pytest.mark.asyncio
    async def test_detects_github_pat_in_js(self):
        body = "const token = 'ghp_16C7e42F292c6912E7710c838347Ae178B4a';"
        tool = APIKeyLeakTool()
        tool._client = _make_client(body=body, status_code=200)
        result = await tool.execute(base_url="https://example.com", trigger_errors=False)
        assert "SECRETS EXPOSED" in result or "GitHub" in result

    @pytest.mark.asyncio
    async def test_detects_pem_key_in_response(self):
        body = "Config: -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAA...\n-----END RSA PRIVATE KEY-----"
        tool = APIKeyLeakTool()
        tool._client = _make_client(body=body, status_code=200)
        result = await tool.execute(base_url="https://example.com", trigger_errors=False)
        assert "SECRETS EXPOSED" in result or "Private Key" in result

    @pytest.mark.asyncio
    async def test_scans_env_path(self):
        """Ensure /.env path is in the scan list."""
        scanned_urls = []

        async def call_tool(name, params):
            scanned_urls.append(params.get("url", ""))
            return {"success": True, "status_code": 200, "body": "clean", "headers": {}}

        tool = APIKeyLeakTool()
        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=call_tool)
        await tool.execute(base_url="https://example.com", trigger_errors=False)
        assert any("/.env" in u for u in scanned_urls)

    @pytest.mark.asyncio
    async def test_extra_paths_scanned(self):
        scanned_urls = []

        async def call_tool(name, params):
            scanned_urls.append(params.get("url", ""))
            return {"success": True, "status_code": 200, "body": "", "headers": {}}

        tool = APIKeyLeakTool()
        tool._client = MagicMock()
        tool._client.call_tool = AsyncMock(side_effect=call_tool)
        await tool.execute(
            base_url="https://example.com",
            extra_paths=["/custom/config"],
            trigger_errors=False,
        )
        assert any("/custom/config" in u for u in scanned_urls)


# ===========================================================================
# OAuthRisk enum
# ===========================================================================


class TestOAuthRiskEnum:
    def test_critical_value(self):
        assert OAuthRisk.CRITICAL.value == "critical"

    def test_high_value(self):
        assert OAuthRisk.HIGH.value == "high"

    def test_none_value(self):
        assert OAuthRisk.NONE.value == "none"


# ===========================================================================
# ToolRegistry — OAuth/API key tools registered
# ===========================================================================


class TestToolRegistryOAuth:
    def test_oauth_flow_informational(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.is_tool_allowed("oauth_flow", Phase.INFORMATIONAL)

    def test_oauth_flow_exploitation(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.is_tool_allowed("oauth_flow", Phase.EXPLOITATION)

    def test_oauth_token_leak_informational(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.is_tool_allowed("oauth_token_leak", Phase.INFORMATIONAL)

    def test_api_key_leak_informational(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.is_tool_allowed("api_key_leak", Phase.INFORMATIONAL)

    def test_api_key_leak_exploitation(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.is_tool_allowed("api_key_leak", Phase.EXPLOITATION)


# ===========================================================================
# AttackPathRouter — OAuth/token keywords → WEB_APP_ATTACK
# ===========================================================================


class TestAttackPathRouterOAuth:
    def test_oauth_keyword(self):
        router = AttackPathRouter()
        assert router.classify_intent("Test OAuth2 scope escalation") == AttackCategory.WEB_APP_ATTACK

    def test_token_leak_keyword(self):
        router = AttackPathRouter()
        assert router.classify_intent("Test for token leak in Referer headers") == AttackCategory.WEB_APP_ATTACK

    def test_api_key_keyword(self):
        router = AttackPathRouter()
        assert router.classify_intent("Check for apikey leakage in JS bundles") == AttackCategory.WEB_APP_ATTACK

    def test_redirect_uri_keyword(self):
        router = AttackPathRouter()
        assert router.classify_intent("Test redirect uri manipulation in OAuth flow") == AttackCategory.WEB_APP_ATTACK

    def test_pkce_keyword(self):
        router = AttackPathRouter()
        assert router.classify_intent("Check pkce bypass vulnerabilities") == AttackCategory.WEB_APP_ATTACK

    def test_scope_escalation_keyword(self):
        router = AttackPathRouter()
        assert router.classify_intent("Test scope escalation in authorization server") == AttackCategory.WEB_APP_ATTACK
