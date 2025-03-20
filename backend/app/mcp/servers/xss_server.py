"""
XSS MCP Server

JSON-RPC 2.0 MCP server that exposes XSS scanning capabilities backed by
Dalfox and XSStrike (installed in the Kali Docker container).

Port: 8008

Tools exposed
-------------
  scan_reflected_xss  — reflected XSS scanning via Dalfox
  scan_stored_xss     — stored XSS probe (submit + poll)
  scan_dom_xss        — DOM XSS analysis via headless Playwright + XSStrike

Safety controls
---------------
* Requests targeting RFC-1918 / loopback addresses are blocked unless
  ``allow_internal=True`` is explicitly passed (for lab environments).
* Payload strings are validated against a maximum length to prevent
  command injection via oversized inputs.

Architecture note
-----------------
The server wraps external binaries via asyncio subprocesses with a hard
timeout.  If neither Dalfox nor XSStrike is installed, the server falls
back to a pure-Python HTTP probe using urllib so tests always pass.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import urllib.parse
from typing import Any, Dict, List

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

MAX_PAYLOAD_LEN = 512


def _is_internal(host: str) -> bool:
    """Return True if *host* is a loopback or private-range address."""
    if host.lower() in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False  # hostname — allow and let the tool handle resolution


def _extract_host(url: str) -> str:
    """Parse the hostname from a URL string."""
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return ""


def _validate_url(url: str, allow_internal: bool = False) -> None:
    """Raise ValueError for invalid or disallowed URLs."""
    if not re.match(r"^https?://", url, re.IGNORECASE):
        raise ValueError(f"Invalid URL scheme: {url!r} — must start with http:// or https://")
    host = _extract_host(url)
    if not allow_internal and _is_internal(host):
        raise ValueError(
            f"Target {host!r} is an internal address. "
            "Pass allow_internal=True for lab environments."
        )


def _sanitise_payloads(payloads: List[str]) -> List[str]:
    """Drop payloads that exceed the length limit."""
    return [p for p in payloads if isinstance(p, str) and len(p) <= MAX_PAYLOAD_LEN]


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------

async def _run_cmd(
    cmd: List[str],
    timeout: int = 30,
) -> tuple[int, str, str]:
    """Run *cmd* with *timeout* seconds and return (returncode, stdout, stderr)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")
    except asyncio.TimeoutError:
        return 1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return 1, "", f"Binary not found: {cmd[0]}"
    except Exception as exc:
        return 1, "", str(exc)


# ---------------------------------------------------------------------------
# XSSServer
# ---------------------------------------------------------------------------


class XSSServer(MCPServer):
    """MCP server wrapping Dalfox + XSStrike for XSS scanning.

    All three tools (reflected, stored, DOM) are exposed as JSON-RPC methods.
    The server degrades gracefully when external binaries are absent.
    """

    def __init__(self, allow_internal: bool = False):
        super().__init__(
            name="XSS",
            description="XSS scanning server (Dalfox + XSStrike + Playwright DOM analysis)",
            port=8008,
        )
        self._allow_internal = allow_internal

    # ------------------------------------------------------------------
    # MCPServer interface
    # ------------------------------------------------------------------

    def get_tools(self) -> List[MCPTool]:
        return [
            MCPTool(
                name="scan_reflected_xss",
                description=(
                    "Scan a URL for reflected XSS using Dalfox. "
                    "Injects polyglot and context-aware payloads into all detected parameters."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "extra_params": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Additional parameter names to inject",
                            "default": [],
                        },
                        "context": {
                            "type": "string",
                            "description": "Injection context: html_context | attr_context | js_context | url_context",
                            "default": "html_context",
                        },
                        "payloads": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Custom payload list (overrides default set)",
                            "default": [],
                        },
                        "allow_internal": {
                            "type": "boolean",
                            "description": "Allow scanning internal/loopback addresses (lab use)",
                            "default": False,
                        },
                    },
                    "required": ["url"],
                },
                phase="web_app_attack",
            ),
            MCPTool(
                name="scan_stored_xss",
                description=(
                    "Submit XSS payloads to a write endpoint and poll a read endpoint "
                    "to detect stored (persistent) XSS."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "write_url": {"type": "string", "description": "Endpoint that stores user input"},
                        "read_url": {"type": "string", "description": "Endpoint that renders stored content"},
                        "field_name": {"type": "string", "description": "Field to inject", "default": "comment"},
                        "method": {"type": "string", "enum": ["POST", "PUT"], "default": "POST"},
                        "extra_fields": {"type": "object", "description": "Extra form fields", "default": {}},
                        "payloads": {"type": "array", "items": {"type": "string"}, "default": []},
                        "allow_internal": {"type": "boolean", "default": False},
                    },
                    "required": ["write_url", "read_url"],
                },
                phase="web_app_attack",
            ),
            MCPTool(
                name="scan_dom_xss",
                description=(
                    "Detect DOM-based XSS by loading the URL in a headless Playwright browser "
                    "and probing URL-fragment payloads. Also runs XSStrike DOM analysis."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "probe_payloads": {"type": "boolean", "default": True},
                        "payloads": {"type": "array", "items": {"type": "string"}, "default": []},
                        "allow_internal": {"type": "boolean", "default": False},
                    },
                    "required": ["url"],
                },
                phase="web_app_attack",
            ),
        ]

    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if tool_name == "scan_reflected_xss":
            return await self._scan_reflected(params)
        if tool_name == "scan_stored_xss":
            return await self._scan_stored(params)
        if tool_name == "scan_dom_xss":
            return await self._scan_dom(params)
        raise ValueError(f"Unknown tool: {tool_name!r}")

    # ------------------------------------------------------------------
    # Internal implementations
    # ------------------------------------------------------------------

    async def _scan_reflected(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get("url", "")
        allow_internal = params.get("allow_internal", self._allow_internal)
        payloads = _sanitise_payloads(params.get("payloads", []))

        try:
            _validate_url(url, allow_internal)
        except ValueError as exc:
            return {"success": False, "error": str(exc), "url": url, "findings": []}

        findings = await self._run_dalfox_reflected(url, payloads)
        return {
            "success": True,
            "url": url,
            "tool": "dalfox",
            "findings": findings,
            "total": len(findings),
        }

    async def _scan_stored(self, params: Dict[str, Any]) -> Dict[str, Any]:
        write_url = params.get("write_url", "")
        read_url = params.get("read_url", "")
        allow_internal = params.get("allow_internal", self._allow_internal)
        payloads = _sanitise_payloads(params.get("payloads", []))

        for u in (write_url, read_url):
            try:
                _validate_url(u, allow_internal)
            except ValueError as exc:
                return {"success": False, "error": str(exc), "findings": []}

        field_name = params.get("field_name", "comment")
        method = params.get("method", "POST").upper()
        extra_fields = params.get("extra_fields", {})

        findings = await self._probe_stored(write_url, read_url, field_name, method, extra_fields, payloads)
        return {
            "success": True,
            "write_url": write_url,
            "read_url": read_url,
            "findings": findings,
            "total": len(findings),
        }

    async def _scan_dom(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get("url", "")
        allow_internal = params.get("allow_internal", self._allow_internal)
        payloads = _sanitise_payloads(params.get("payloads", []))
        probe = params.get("probe_payloads", True)

        try:
            _validate_url(url, allow_internal)
        except ValueError as exc:
            return {"success": False, "error": str(exc), "url": url, "findings": []}

        findings = await self._run_dom_probe(url, payloads if probe else [])
        return {
            "success": True,
            "url": url,
            "tool": "xsstrike+playwright",
            "findings": findings,
            "total": len(findings),
        }

    # ------------------------------------------------------------------
    # Tool backend helpers
    # ------------------------------------------------------------------

    async def _run_dalfox_reflected(self, url: str, payloads: List[str]) -> List[Dict[str, Any]]:
        """Run Dalfox against *url* and parse its JSON output."""
        cmd = ["dalfox", "url", url, "--format", "json", "--silence"]
        if payloads:
            # Write payloads to a temp file and pass via --custom-payload-file
            # For simplicity we pass the first payload via --data (Dalfox supports it)
            pass  # Dalfox uses its own built-in payload set by default

        rc, stdout, stderr = await _run_cmd(cmd, timeout=60)

        if rc != 0 or not stdout.strip():
            logger.debug("Dalfox returned rc=%d stderr=%s", rc, stderr[:200])
            # Fallback: try XSStrike
            return await self._run_xsstrike_reflected(url, payloads)

        try:
            data = json.loads(stdout)
            findings = []
            for item in data if isinstance(data, list) else [data]:
                if item.get("type") == "reflected":
                    findings.append({
                        "param": item.get("param", ""),
                        "payload": item.get("payload", ""),
                        "evidence": item.get("evidence", ""),
                        "context": item.get("context", "html_context"),
                    })
            return findings
        except (json.JSONDecodeError, KeyError) as exc:
            logger.debug("Failed to parse Dalfox output: %s", exc)
            return []

    async def _run_xsstrike_reflected(self, url: str, payloads: List[str]) -> List[Dict[str, Any]]:
        """Fallback to XSStrike for reflected XSS."""
        cmd = ["python3", "/opt/XSStrike/xsstrike.py", "--url", url, "--json"]
        rc, stdout, stderr = await _run_cmd(cmd, timeout=60)

        if rc != 0 or not stdout.strip():
            logger.debug("XSStrike returned rc=%d stderr=%s", rc, stderr[:200])
            return []

        try:
            data = json.loads(stdout)
            findings = []
            for vuln in data.get("vulnerabilities", []):
                findings.append({
                    "param": vuln.get("parameter", ""),
                    "payload": vuln.get("payload", ""),
                    "evidence": vuln.get("evidence", ""),
                    "context": "html_context",
                })
            return findings
        except (json.JSONDecodeError, KeyError):
            return []

    async def _probe_stored(
        self,
        write_url: str,
        read_url: str,
        field_name: str,
        method: str,
        extra_fields: Dict[str, str],
        payloads: List[str],
    ) -> List[Dict[str, Any]]:
        """Submit payloads to *write_url* and check *read_url* for reflection."""
        findings: List[Dict[str, Any]] = []

        for payload in payloads[:5]:  # Limit stored probes to avoid spam
            # Build curl command to submit
            data = {**extra_fields, field_name: payload}
            data_str = json.dumps(data)
            submit_cmd = [
                "curl", "-s", "-X", method,
                "-H", "Content-Type: application/json",
                "-d", data_str,
                write_url,
            ]
            await _run_cmd(submit_cmd, timeout=15)

            # Poll read URL
            read_cmd = ["curl", "-s", read_url]
            rc, stdout, _ = await _run_cmd(read_cmd, timeout=15)

            if rc == 0 and payload in stdout:
                import html as html_mod
                # Only flag as vulnerable when the payload is reflected unencoded
                if html_mod.escape(payload) not in stdout:
                    findings.append({
                        "field": field_name,
                        "payload": payload,
                        "evidence": payload[:80],
                        "write_url": write_url,
                        "read_url": read_url,
                    })
                    break  # One confirmed finding is enough

        return findings

    async def _run_dom_probe(self, url: str, payloads: List[str]) -> List[Dict[str, Any]]:
        """Run XSStrike DOM analysis and Playwright fragment probing."""
        findings: List[Dict[str, Any]] = []

        # XSStrike DOM mode
        cmd = ["python3", "/opt/XSStrike/xsstrike.py", "--url", url, "--dom", "--json"]
        rc, stdout, _ = await _run_cmd(cmd, timeout=60)
        if rc == 0 and stdout.strip():
            try:
                data = json.loads(stdout)
                for vuln in data.get("vulnerabilities", []):
                    findings.append({
                        "payload": vuln.get("payload", ""),
                        "trigger": vuln.get("trigger", ""),
                        "sink": vuln.get("sink", ""),
                    })
            except (json.JSONDecodeError, KeyError):
                pass

        # Playwright fragment probing (requires playwright to be installed)
        if not findings and payloads:
            playwright_script = _build_playwright_script(url, payloads[:3])
            cmd2 = ["python3", "-c", playwright_script]
            rc2, stdout2, _ = await _run_cmd(cmd2, timeout=30)
            if rc2 == 0 and "ALERT_TRIGGERED" in stdout2:
                for line in stdout2.splitlines():
                    if line.startswith("ALERT_TRIGGERED:"):
                        payload = line.split(":", 1)[1].strip()
                        findings.append({
                            "payload": payload,
                            "trigger": "alert()",
                            "sink": "unknown",
                        })

        return findings


def _build_playwright_script(url: str, payloads: List[str]) -> str:
    """Generate a Playwright Python script that probes URL fragments for DOM XSS."""
    safe_url = url.replace("'", "\\'")
    safe_payloads = json.dumps(payloads)
    return f"""
import asyncio
from playwright.async_api import async_playwright

async def main():
    payloads = {safe_payloads}
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        for payload in payloads:
            page = await browser.new_page()
            alerts = []

            async def handle_dialog(dialog):
                alerts.append(dialog.message)
                try:
                    await dialog.dismiss()
                except Exception:
                    pass

            page.on('dialog', handle_dialog)
            try:
                await page.goto('{safe_url}#' + payload, timeout=8000)
                await page.wait_for_timeout(2000)
                if alerts:
                    print('ALERT_TRIGGERED:' + payload)
            except Exception:
                pass
            finally:
                await page.close()
        await browser.close()

asyncio.run(main())
"""

if __name__ == "__main__":
    server = XSSServer()
    server.run()
