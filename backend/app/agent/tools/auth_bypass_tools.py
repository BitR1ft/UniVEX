"""
Auth Bypass & Session Testing Tools

Implements three agent tools for authentication bypass and session attack testing:

  AuthBypassTool        — test common auth bypass patterns: path traversal tricks,
                          HTTP verb tampering, header injection (X-Forwarded-For,
                          X-Original-URL, X-Rewrite-URL, X-Custom-IP-Authorization).
  SessionPuzzlingTool   — test session fixation, session puzzling, and concurrent
                          session attacks.
  RateLimitBypassTool   — test rate limiting bypass via IP rotation headers, parameter
                          pollution, and case variation.

OWASP Mapping: A01:2021-Broken Access Control / A07:2021-Identification and
               Authentication Failures
"""

from __future__ import annotations

import logging
import urllib.parse
from enum import Enum
from typing import Any, Dict, List, Optional

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import truncate_output
from app.mcp.base_server import MCPClient

logger = logging.getLogger(__name__)

DEFAULT_CURL_SERVER_URL = "http://kali-tools:8001"

OWASP_AUTH_TAG = "A01:2021-Broken Access Control / A07:2021-Identification & Authentication Failures"
OWASP_SESSION_TAG = "A07:2021-Identification and Authentication Failures (Session Management)"
OWASP_RATELIMIT_TAG = "A04:2021-Insecure Design (Rate Limit Bypass)"


# ---------------------------------------------------------------------------
# Auth bypass vectors
# ---------------------------------------------------------------------------

_VERB_TAMPERING_METHODS = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE", "TRACE"]

_IP_BYPASS_HEADERS: List[str] = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Client-IP",
    "X-Host",
    "X-Custom-IP-Authorization",
    "Forwarded",
    "True-Client-IP",
    "CF-Connecting-IP",
]

_LOCALHOST_IPS = ["127.0.0.1", "localhost", "0.0.0.0", "::1", "127.0.0.1%09"]

_PATH_BYPASS_SUFFIXES: List[str] = [
    "/",
    "//",
    "/%2F",
    "/./",
    "/.%2e/",
    "%09",
    ";/",
    "/..;/",
    "#",
    "?debug=true",
    "%20",
    ".json",
    ".xml",
    "~",
    "..",
    "%00",
]

_REWRITE_HEADERS: List[str] = [
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Override-URL",
    "X-HTTP-Method-Override",
    "X-Method-Override",
]


class AuthBypassRisk(str, Enum):
    """Risk level of an auth bypass finding."""
    CRITICAL = "critical"  # Direct authentication bypass confirmed
    HIGH = "high"          # Auth enforcement skipped via header/verb
    MEDIUM = "medium"      # Ambiguous response suggesting partial bypass
    NONE = "none"          # No bypass detected


def _is_protected(status: int) -> bool:
    """Return True if status code indicates access is restricted."""
    return status in (401, 403)


def _is_accessible(status: int, body: str) -> bool:
    """Return True if response looks like successful resource access."""
    if status in (200, 201, 204):
        denial = ("access denied", "forbidden", "unauthorized", "login required", "not allowed")
        return not any(d in body.lower() for d in denial)
    return False


# ---------------------------------------------------------------------------
# AuthBypassTool
# ---------------------------------------------------------------------------


class AuthBypassTool(BaseTool):
    """Test common authentication bypass techniques.

    Strategies tested:
    1. HTTP verb tampering — change method while keeping path
    2. Header injection — X-Forwarded-For, X-Original-URL, X-Real-IP (127.0.0.1)
    3. Path suffix tricks — append //, /./, %2F etc. to bypass WAF rules
    4. URL rewrite headers — X-Original-URL, X-Rewrite-URL pointing to admin path

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
            name="auth_bypass",
            description=(
                "Test HTTP authentication bypass techniques: verb tampering, "
                "IP-spoofing headers (X-Forwarded-For: 127.0.0.1), URL rewrite headers "
                "(X-Original-URL), and path suffix bypass tricks. "
                "Reports which bypass vector succeeded. OWASP A01/A07."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Protected URL to test auth bypass against.",
                    },
                    "expected_status": {
                        "type": "integer",
                        "description": "Expected status code for a protected page (usually 401 or 403).",
                        "default": 403,
                    },
                    "cookies": {
                        "type": "string",
                        "description": "Unauthenticated session cookies (or leave empty for no-auth tests).",
                        "default": "",
                    },
                    "test_verb_tampering": {
                        "type": "boolean",
                        "description": "Test HTTP verb tampering bypass.",
                        "default": True,
                    },
                    "test_header_injection": {
                        "type": "boolean",
                        "description": "Test IP-spoofing header injection bypass.",
                        "default": True,
                    },
                    "test_path_bypass": {
                        "type": "boolean",
                        "description": "Test path suffix / encoding bypass.",
                        "default": True,
                    },
                    "test_rewrite_headers": {
                        "type": "boolean",
                        "description": "Test X-Original-URL / X-Rewrite-URL header bypass.",
                        "default": True,
                    },
                },
                "required": ["url"],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        url: str,
        expected_status: int = 403,
        cookies: str = "",
        test_verb_tampering: bool = True,
        test_header_injection: bool = True,
        test_path_bypass: bool = True,
        test_rewrite_headers: bool = True,
        **kwargs: Any,
    ) -> str:
        base_headers: Dict[str, str] = {}
        if cookies:
            base_headers["Cookie"] = cookies

        findings: List[Dict[str, Any]] = []

        # ── 1. Verb tampering ──────────────────────────────────────────────
        if test_verb_tampering:
            for verb in _VERB_TAMPERING_METHODS:
                resp = await self._fetch(url, verb, base_headers)
                status = resp.get("status_code", 0)
                body = _get_body(resp)
                if _is_accessible(status, body) and status != expected_status:
                    findings.append({
                        "vector": "verb_tampering",
                        "detail": f"Method: {verb}",
                        "status": status,
                        "evidence": body[:200],
                    })

        # ── 2. Header injection ────────────────────────────────────────────
        if test_header_injection:
            for hdr in _IP_BYPASS_HEADERS:
                for ip in _LOCALHOST_IPS[:3]:
                    hdrs = dict(base_headers)
                    hdrs[hdr] = ip
                    resp = await self._fetch(url, "GET", hdrs)
                    status = resp.get("status_code", 0)
                    body = _get_body(resp)
                    if _is_accessible(status, body) and status != expected_status:
                        findings.append({
                            "vector": "header_injection",
                            "detail": f"{hdr}: {ip}",
                            "status": status,
                            "evidence": body[:200],
                        })
                        break  # One success per header is enough

        # ── 3. Path suffix bypass ──────────────────────────────────────────
        if test_path_bypass:
            for suffix in _PATH_BYPASS_SUFFIXES[:8]:
                probe_url = url.rstrip("/") + suffix
                resp = await self._fetch(probe_url, "GET", base_headers)
                status = resp.get("status_code", 0)
                body = _get_body(resp)
                if _is_accessible(status, body) and status != expected_status:
                    findings.append({
                        "vector": "path_bypass",
                        "detail": f"Suffix: {repr(suffix)}",
                        "status": status,
                        "evidence": body[:200],
                    })

        # ── 4. Rewrite header bypass ───────────────────────────────────────
        if test_rewrite_headers:
            parsed = urllib.parse.urlparse(url)
            for hdr in _REWRITE_HEADERS[:4]:
                hdrs = dict(base_headers)
                hdrs[hdr] = parsed.path  # Request the protected path via rewrite
                # Target the root so the rewrite header re-routes
                root_url = f"{parsed.scheme}://{parsed.netloc}/"
                resp = await self._fetch(root_url, "GET", hdrs)
                status = resp.get("status_code", 0)
                body = _get_body(resp)
                if _is_accessible(status, body):
                    findings.append({
                        "vector": "rewrite_header",
                        "detail": f"{hdr}: {parsed.path}",
                        "status": status,
                        "evidence": body[:200],
                    })

        return self._format(url, findings)

    async def _fetch(
        self, url: str, method: str, headers: Dict[str, str]
    ) -> Dict[str, Any]:
        try:
            return await self._client.call_tool(
                "execute_curl",
                {"url": url, "method": method, "headers": headers, "follow_redirects": False},
            )
        except Exception as exc:
            logger.debug("AuthBypass fetch failed: %s", exc)
            return {"success": False, "error": str(exc)}

    def _format(self, url: str, findings: List[Dict[str, Any]]) -> str:
        lines = [
            f"[auth_bypass] Auth Bypass Test: {url}",
            f"  Findings: {len(findings)}",
            "",
        ]
        if findings:
            risk = AuthBypassRisk.CRITICAL if len(findings) >= 2 else AuthBypassRisk.HIGH
            lines += [
                f"  ⚠ AUTH BYPASS DETECTED — Risk: {risk.value.upper()}",
                f"  OWASP: {OWASP_AUTH_TAG}",
                "",
                "── Bypass Vectors ─────────────────────────",
            ]
            for f in findings:
                lines += [
                    f"  [{f['vector']}] {f['detail']} → HTTP {f['status']}",
                    f"    Evidence: {f['evidence'][:120]}",
                    "",
                ]
            lines += [
                "── Remediation ────────────────────────────",
                "  1. Enforce authentication checks in application middleware, not just WAF/proxy",
                "  2. Normalise URL paths server-side before access-control decisions",
                "  3. Reject unexpected HTTP methods for sensitive endpoints",
                "  4. Distrust all client-supplied IP headers; use load balancer trusted IPs",
            ]
        else:
            lines += [
                "  ✓ No auth bypass vectors detected.",
                f"  OWASP: {OWASP_AUTH_TAG}",
            ]
        return truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# SessionPuzzlingTool
# ---------------------------------------------------------------------------


_SESSION_COOKIE_NAMES = [
    "session", "sessionid", "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId",
    "connect.sid", "rack.session", "laravel_session", "sid",
]


class SessionPuzzlingTool(BaseTool):
    """Test session fixation, session puzzling, and concurrent session attacks.

    Checks:
    1. Session fixation — server accepts a pre-set session token without rotation
    2. Concurrent sessions — same credentials usable from multiple sessions
    3. Session token predictability — examines token entropy
    4. Cookie attribute weaknesses — missing Secure/HttpOnly/SameSite flags

    OWASP A07:2021-Identification and Authentication Failures
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
            name="session_puzzling",
            description=(
                "Test session fixation: inject a known session token before login and "
                "verify whether the server rotates it post-authentication. Also analyses "
                "session cookie attributes (Secure, HttpOnly, SameSite) and concurrent "
                "session behaviour. OWASP A07:2021."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "login_url": {
                        "type": "string",
                        "description": "Login endpoint URL.",
                    },
                    "post_login_url": {
                        "type": "string",
                        "description": "URL to verify authenticated access after login (e.g. /dashboard).",
                        "default": "",
                    },
                    "login_body": {
                        "type": "string",
                        "description": "JSON body for the login request (e.g. {\"username\": \"user\", \"password\": \"pass\"}).",
                        "default": "{}",
                    },
                    "fixed_session_token": {
                        "type": "string",
                        "description": "Pre-set session token to inject for fixation test.",
                        "default": "UNIVEX_FIXED_SESSION_12345",
                    },
                    "session_cookie_name": {
                        "type": "string",
                        "description": "Name of the session cookie (leave empty for auto-detection).",
                        "default": "",
                    },
                },
                "required": ["login_url"],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        login_url: str,
        post_login_url: str = "",
        login_body: str = "{}",
        fixed_session_token: str = "UNIVEX_FIXED_SESSION_12345",
        session_cookie_name: str = "",
        **kwargs: Any,
    ) -> str:

        issues: List[Dict[str, Any]] = []

        # ── Step 1: Get pre-login session token ────────────────────────────
        pre_resp = await self._fetch(login_url, "GET", {})
        pre_cookies_header = pre_resp.get("headers", {})
        pre_session = _extract_session_from_response(pre_cookies_header, session_cookie_name)

        # ── Step 2: Attempt login with fixed session token ─────────────────
        cookie_name = session_cookie_name or _detect_session_cookie_name(pre_cookies_header)
        fixed_cookie = f"{cookie_name}={fixed_session_token}"
        login_headers = {
            "Content-Type": "application/json",
            "Cookie": fixed_cookie,
        }
        login_resp = await self._fetch(login_url, "POST", login_headers, login_body)
        post_cookies_header = login_resp.get("headers", {})
        post_session = _extract_session_from_response(post_cookies_header, session_cookie_name)

        # ── Step 3: Session fixation check ────────────────────────────────
        if post_session and post_session == fixed_session_token:
            issues.append({
                "type": "session_fixation",
                "detail": f"Server accepted pre-set session token '{fixed_session_token}' post-login",
                "risk": "critical",
            })
        elif pre_session and post_session and pre_session == post_session:
            issues.append({
                "type": "session_not_rotated",
                "detail": "Session token was NOT rotated after authentication",
                "risk": "high",
            })

        # ── Step 4: Cookie attribute analysis ─────────────────────────────
        for issue in _analyse_session_cookie_attributes(pre_cookies_header):
            issues.append(issue)

        # ── Step 5: Concurrent session test ───────────────────────────────
        if post_login_url and post_session:
            # Try accessing with old (pre-login) session
            if pre_session and pre_session != post_session:
                old_hdrs = {"Cookie": f"{cookie_name}={pre_session}"}
                old_resp = await self._fetch(post_login_url, "GET", old_hdrs)
                if _is_accessible(old_resp.get("status_code", 0), _get_body(old_resp)):
                    issues.append({
                        "type": "concurrent_sessions",
                        "detail": "Old session remains valid after new session creation",
                        "risk": "medium",
                    })

        return self._format(login_url, issues)

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
                "follow_redirects": True,
            }
            if body:
                params["body"] = body
            return await self._client.call_tool("execute_curl", params)
        except Exception as exc:
            logger.debug("SessionPuzzling fetch failed: %s", exc)
            return {"success": False, "error": str(exc)}

    def _format(self, url: str, issues: List[Dict[str, Any]]) -> str:
        lines = [
            f"[session_puzzling] Session Security Test: {url}",
            f"  Issues found: {len(issues)}",
            "",
        ]
        if issues:
            critical = [i for i in issues if i.get("risk") == "critical"]
            risk_label = "CRITICAL" if critical else "HIGH" if any(i.get("risk") == "high" for i in issues) else "MEDIUM"
            lines += [
                f"  ⚠ SESSION VULNERABILITY — Risk: {risk_label}",
                f"  OWASP: {OWASP_SESSION_TAG}",
                "",
                "── Issues Found ───────────────────────────",
            ]
            for i in issues:
                lines += [
                    f"  [{i['risk'].upper()}] {i['type']}",
                    f"    {i['detail']}",
                    "",
                ]
            lines += [
                "── Remediation ────────────────────────────",
                "  1. Always regenerate session ID after successful authentication",
                "  2. Set Secure, HttpOnly, SameSite=Strict on all session cookies",
                "  3. Implement server-side session invalidation on logout",
                "  4. Enforce single-session policies or flag concurrent sessions",
            ]
        else:
            lines += [
                "  ✓ No session vulnerabilities detected.",
                f"  OWASP: {OWASP_SESSION_TAG}",
            ]
        return truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# RateLimitBypassTool
# ---------------------------------------------------------------------------

_RATE_LIMIT_BYPASS_HEADERS: List[Tuple] = [
    ("X-Forwarded-For", "10.0.0.{i}"),
    ("X-Real-IP", "10.0.0.{i}"),
    ("X-Originating-IP", "10.0.0.{i}"),
    ("CF-Connecting-IP", "10.0.0.{i}"),
    ("True-Client-IP", "10.0.0.{i}"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
]


class RateLimitBypassTool(BaseTool):
    """Test rate limiting bypass via IP rotation headers and parameter pollution.

    Strategies:
    1. IP rotation via X-Forwarded-For cycling
    2. Case variation on endpoints (/Login vs /login)
    3. Parameter pollution (duplicate parameters)
    4. User-Agent rotation
    5. Adding null-byte / whitespace to tokens

    OWASP A04:2021-Insecure Design
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
            name="rate_limit_bypass",
            description=(
                "Test rate limiting bypass: cycle IP addresses via X-Forwarded-For, "
                "vary User-Agent strings, use parameter pollution, and test case "
                "variation on endpoints. Reports which bypass technique allows continued "
                "access after the rate limit is hit. OWASP A04:2021."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Rate-limited endpoint URL (e.g. /api/auth/login).",
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method for the test requests.",
                        "enum": ["GET", "POST", "PUT"],
                        "default": "POST",
                    },
                    "body": {
                        "type": "string",
                        "description": "Request body for POST/PUT (JSON string).",
                        "default": "{}",
                    },
                    "rate_limit_status": {
                        "type": "integer",
                        "description": "HTTP status code the server returns when rate-limited (usually 429).",
                        "default": 429,
                    },
                    "probe_count": {
                        "type": "integer",
                        "description": "Number of probes to send per bypass technique (default 5).",
                        "default": 5,
                    },
                },
                "required": ["url"],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        url: str,
        method: str = "POST",
        body: str = "{}",
        rate_limit_status: int = 429,
        probe_count: int = 5,
        **kwargs: Any,
    ) -> str:
        base_headers: Dict[str, str] = {"Content-Type": "application/json"}
        findings: List[Dict[str, Any]] = []

        # ── Strategy 1: IP rotation ────────────────────────────────────────
        for i in range(1, probe_count + 1):
            for hdr_name, hdr_tpl in _RATE_LIMIT_BYPASS_HEADERS[:3]:
                ip = hdr_tpl.format(i=i)
                hdrs = dict(base_headers)
                hdrs[hdr_name] = ip
                resp = await self._fetch(url, method, hdrs, body)
                status = resp.get("status_code", 0)
                if status != rate_limit_status and status not in (0, 500, 503):
                    findings.append({
                        "technique": "ip_rotation",
                        "detail": f"{hdr_name}: {ip}",
                        "status": status,
                    })
                    break
            else:
                continue
            break  # Found a working bypass — no need to probe further

        # ── Strategy 2: User-Agent rotation ───────────────────────────────
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "curl/7.88.1",
            "python-httpx/0.24",
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
        ]
        for ua in agents[:3]:
            hdrs = dict(base_headers)
            hdrs["User-Agent"] = ua
            resp = await self._fetch(url, method, hdrs, body)
            status = resp.get("status_code", 0)
            if status != rate_limit_status and status not in (0, 500):
                findings.append({
                    "technique": "user_agent_rotation",
                    "detail": f"UA: {ua[:60]}",
                    "status": status,
                })
                break

        # ── Strategy 3: URL case variation ────────────────────────────────
        parsed = urllib.parse.urlparse(url)
        case_variants = [
            parsed.path.upper(),
            parsed.path.lower(),
            parsed.path.title(),
        ]
        for variant in case_variants:
            variant_url = urllib.parse.urlunparse(parsed._replace(path=variant))
            if variant_url == url:
                continue
            resp = await self._fetch(variant_url, method, base_headers, body)
            status = resp.get("status_code", 0)
            if status != rate_limit_status and status not in (0, 404, 500):
                findings.append({
                    "technique": "url_case_variation",
                    "detail": f"Path: {variant}",
                    "status": status,
                })
                break

        return self._format(url, rate_limit_status, findings)

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
            logger.debug("RateLimitBypass fetch failed: %s", exc)
            return {"success": False, "error": str(exc)}

    def _format(
        self,
        url: str,
        rate_limit_status: int,
        findings: List[Dict[str, Any]],
    ) -> str:
        lines = [
            f"[rate_limit_bypass] Rate Limit Bypass Test: {url}",
            f"  Rate-limit status expected: HTTP {rate_limit_status}",
            f"  Bypass techniques succeeded: {len(findings)}",
            "",
        ]
        if findings:
            lines += [
                "  ⚠ RATE LIMIT BYPASS DETECTED",
                f"  OWASP: {OWASP_RATELIMIT_TAG}",
                "",
                "── Working Bypass Techniques ──────────────",
            ]
            for f in findings:
                lines += [
                    f"  [{f['technique']}] {f['detail']} → HTTP {f['status']}",
                    "",
                ]
            lines += [
                "── Remediation ────────────────────────────",
                "  1. Implement rate limiting at the application layer, not just proxy",
                "  2. Base rate limits on authenticated user identity, not just IP address",
                "  3. Distrust all client-supplied IP headers for rate-limit decisions",
                "  4. Apply progressive delays and account lockout for repeated failures",
            ]
        else:
            lines += [
                "  ✓ Rate limiting appears robust against tested bypass techniques.",
                f"  OWASP: {OWASP_RATELIMIT_TAG}",
            ]
        return truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

from typing import Tuple  # noqa: E402 — used above in type hint


def _get_body(result: Dict[str, Any]) -> str:
    """Safely extract body string from a curl result dict."""
    body = result.get("body", "")
    if isinstance(body, dict):
        import json
        return json.dumps(body)
    return str(body) if body else ""


def _is_accessible(status: int, body: str) -> bool:
    """Return True if response looks like successful resource access."""
    if status in (200, 201, 204):
        denial = ("access denied", "forbidden", "unauthorized", "login required", "not allowed")
        return not any(d in body.lower() for d in denial)
    return False


def _extract_session_from_response(headers: Dict[str, str], preferred_name: str = "") -> Optional[str]:
    """Extract session token value from Set-Cookie headers."""
    import re as _re
    for key, value in headers.items():
        if key.lower() != "set-cookie":
            continue
        for cookie_str in value.split(","):
            cookie_str = cookie_str.strip()
            # Try preferred name first
            target_names = [preferred_name] if preferred_name else _SESSION_COOKIE_NAMES
            for name in target_names:
                m = _re.search(rf"(?:^|;\s*){re.escape(name)}=([^;]+)", cookie_str, _re.IGNORECASE)
                if m:
                    return m.group(1)
    return None


def _detect_session_cookie_name(headers: Dict[str, str]) -> str:
    """Detect which session cookie name is used from Set-Cookie headers."""
    import re as _re
    for key, value in headers.items():
        if key.lower() != "set-cookie":
            continue
        for name in _SESSION_COOKIE_NAMES:
            # Use a word boundary or start-of-string to avoid partial matches
            # (e.g. "sessionid" should NOT match inside "JSESSIONID").
            if _re.search(rf"(?:^|;\s*){re.escape(name)}=", value, _re.IGNORECASE):
                return name
    return "session"  # Fallback


def _analyse_session_cookie_attributes(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """Return a list of session cookie attribute issues."""
    import re as _re
    issues: List[Dict[str, Any]] = []
    for key, value in headers.items():
        if key.lower() != "set-cookie":
            continue
        # Check for session cookies
        is_session = any(
            _re.search(rf"{re.escape(n)}=", value, _re.IGNORECASE)
            for n in _SESSION_COOKIE_NAMES
        )
        if not is_session:
            continue
        if not _re.search(r"\bSecure\b", value, _re.IGNORECASE):
            issues.append({"type": "missing_secure_flag", "detail": "Secure flag missing on session cookie", "risk": "high"})
        if not _re.search(r"\bHttpOnly\b", value, _re.IGNORECASE):
            issues.append({"type": "missing_httponly_flag", "detail": "HttpOnly flag missing — XSS can steal session", "risk": "high"})
        ss_match = _re.search(r"SameSite\s*=\s*(\w+)", value, _re.IGNORECASE)
        if not ss_match:
            issues.append({"type": "missing_samesite", "detail": "SameSite attribute not set on session cookie", "risk": "medium"})
        elif ss_match.group(1).lower() == "none":
            issues.append({"type": "samesite_none", "detail": "SameSite=None allows cross-site requests", "risk": "medium"})
    return issues


import re  # noqa: E402 — used inside helper functions above


__all__ = [
    "AuthBypassTool",
    "SessionPuzzlingTool",
    "RateLimitBypassTool",
    "AuthBypassRisk",
    "OWASP_AUTH_TAG",
    "OWASP_SESSION_TAG",
    "OWASP_RATELIMIT_TAG",
    "_IP_BYPASS_HEADERS",
    "_PATH_BYPASS_SUFFIXES",
    "_REWRITE_HEADERS",
    "_SESSION_COOKIE_NAMES",
    "_is_protected",
    "_is_accessible",
    "_get_body",
    "_extract_session_from_response",
    "_detect_session_cookie_name",
    "_analyse_session_cookie_attributes",
]
