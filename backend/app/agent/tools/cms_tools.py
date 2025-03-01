"""
CMS Scanning Tools

Provides WordPress enumeration (WPScan) and general web server vulnerability
scanning (Nikto) for CMS detection and web application attack phases.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import (
    ToolExecutionError,
    truncate_output,
    with_timeout,
)
from app.mcp.base_server import MCPClient

logger = logging.getLogger(__name__)

NIKTO_URL = "http://kali-tools:8007"


class WPScanTool(BaseTool):
    """
    WordPress vulnerability scanner using WPScan.

    Auto-detects WordPress targets and enumerates plugins, themes, users,
    and known vulnerabilities. Optionally uses the WPScan Vulnerability
    Database API for richer CVE data.
    """

    def __init__(self):
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="wpscan",
            description=(
                "Scan a WordPress installation for vulnerabilities, outdated plugins/themes, "
                "and exposed user accounts using WPScan. "
                "Auto-triggered when Wappalyzer detects WordPress on the target. "
                "An API token enables vulnerability database lookups."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Full URL of the WordPress site (e.g. http://10.10.10.1/)",
                    },
                    "enumerate": {
                        "type": "string",
                        "description": (
                            "Enumeration types: vp=vulnerable plugins, vt=vulnerable themes, "
                            "tt=timthumbs, cb=config backups, dbe=db exports, "
                            "u=users, m=media"
                        ),
                        "default": "vp,vt,tt,cb,dbe,u,m",
                    },
                    "api_token": {
                        "type": "string",
                        "description": "WPScan API token for vulnerability database lookups (optional)",
                        "default": "",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds",
                        "default": 180,
                    },
                    "allow_internal": {
                        "type": "boolean",
                        "description": "Allow RFC-1918/localhost targets (HTB labs)",
                        "default": False,
                    },
                },
                "required": ["url"],
            },
        )

    @with_timeout(300)
    async def execute(
        self,
        url: str,
        enumerate: str = "vp,vt,tt,cb,dbe,u,m",
        api_token: str = "",
        timeout: int = 180,
        allow_internal: bool = False,
        **kwargs: Any,
    ) -> str:
        """Run WPScan and return a structured findings summary."""
        timestamp = int(time.time())
        output_file = f"/tmp/wpscan_{timestamp}.json"

        cmd = [
            "wpscan",
            "--url", url,
            "--format", "json",
            "--output", output_file,
            "--enumerate", enumerate,
            "--no-update",
        ]
        if api_token:
            cmd += ["--api-token", api_token]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

        except FileNotFoundError:
            return (
                "Error: 'wpscan' not found. "
                "Install with: gem install wpscan  "
                "or: apt-get install wpscan"
            )
        except asyncio.TimeoutError:
            return f"WPScan timed out after {timeout}s for {url}."
        except Exception as exc:
            raise ToolExecutionError(
                f"wpscan failed: {exc}", tool_name="wpscan"
            ) from exc

        # Parse JSON output file
        try:
            with open(output_file) as fh:
                scan_data = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            raw = stdout.decode(errors="replace")
            return (
                "WPScan completed but JSON output could not be parsed.\n\n"
                + truncate_output(raw, max_chars=4000)
            )

        return self._format_results(scan_data, url)

    def _format_results(self, data: dict, url: str) -> str:
        """Format WPScan JSON results into a readable summary."""
        lines = [f"=== WPScan Results: {url} ===\n"]

        # WordPress version
        wp_version = data.get("version", {})
        if wp_version:
            ver_num = wp_version.get("number", "unknown")
            ver_status = wp_version.get("status", "")
            lines.append(f"[WordPress Version] {ver_num} ({ver_status})")
            for vuln in wp_version.get("vulnerabilities", []):
                lines.append(f"  [VULN] {vuln.get('title', '?')} — {', '.join(vuln.get('references', {}).get('cve', []))}")

        # Users
        users = data.get("users", {})
        if users:
            lines.append(f"\n[Users] {len(users)} found:")
            for uname in list(users.keys())[:10]:
                lines.append(f"  {uname}")

        # Vulnerable plugins
        plugins = data.get("plugins", {})
        vuln_plugins = {
            name: info for name, info in plugins.items()
            if info.get("vulnerabilities")
        }
        if vuln_plugins:
            lines.append(f"\n[Vulnerable Plugins] {len(vuln_plugins)} found:")
            for name, info in vuln_plugins.items():
                version = info.get("version", {}).get("number", "?")
                lines.append(f"  {name} v{version}:")
                for vuln in info["vulnerabilities"][:3]:
                    cves = ", ".join(vuln.get("references", {}).get("cve", []))
                    lines.append(f"    - {vuln.get('title', '?')} {f'({cves})' if cves else ''}")
        elif plugins:
            lines.append(f"\n[Plugins] {len(plugins)} found (no known vulnerabilities).")

        # Vulnerable themes
        themes = data.get("themes", {})
        vuln_themes = {
            name: info for name, info in themes.items()
            if info.get("vulnerabilities")
        }
        if vuln_themes:
            lines.append(f"\n[Vulnerable Themes] {len(vuln_themes)} found:")
            for name, info in vuln_themes.items():
                version = info.get("version", {}).get("number", "?")
                lines.append(f"  {name} v{version}:")
                for vuln in info["vulnerabilities"][:3]:
                    cves = ", ".join(vuln.get("references", {}).get("cve", []))
                    lines.append(f"    - {vuln.get('title', '?')} {f'({cves})' if cves else ''}")

        # Config backups / interesting findings
        interesting = data.get("interesting_findings", [])
        if interesting:
            lines.append(f"\n[Interesting Findings] {len(interesting)}:")
            for finding in interesting[:10]:
                lines.append(f"  {finding.get('type', '?')}: {finding.get('url', '')}")
                if finding.get("interesting_entries"):
                    for entry in finding["interesting_entries"][:3]:
                        lines.append(f"    → {entry}")

        if not any([wp_version, users, vuln_plugins, vuln_themes, interesting]):
            lines.append("\nNo significant findings. The site may not be WordPress or may be hardened.")

        return "\n".join(lines)


class NiktoAgentTool(BaseTool):
    """
    Web server vulnerability scanner using Nikto via the Nikto MCP server.

    Identifies outdated software, dangerous files, misconfigurations,
    and common web vulnerabilities on HTTP/HTTPS targets.
    """

    def __init__(self, server_url: str = NIKTO_URL):
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="nikto_scan",
            description=(
                "Scan a web server for vulnerabilities using Nikto. "
                "Detects outdated software, dangerous files/CGIs, misconfigurations, "
                "and HTTP security header issues. "
                "Use after initial port scan confirms HTTP/HTTPS services."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target hostname or IP address",
                    },
                    "port": {
                        "type": "integer",
                        "description": "HTTP/HTTPS port",
                        "default": 80,
                    },
                    "ssl": {
                        "type": "boolean",
                        "description": "Use HTTPS/SSL",
                        "default": False,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Scan timeout in seconds",
                        "default": 180,
                    },
                    "allow_internal": {
                        "type": "boolean",
                        "description": "Allow RFC-1918/localhost targets (HTB labs)",
                        "default": False,
                    },
                },
                "required": ["host"],
            },
        )

    @with_timeout(300)
    async def execute(
        self,
        host: str,
        port: int = 80,
        ssl: bool = False,
        timeout: int = 180,
        allow_internal: bool = False,
        **kwargs: Any,
    ) -> str:
        """Run Nikto scan via MCP server and return formatted vulnerability list."""
        try:
            result = await self._client.call_tool(
                "nikto_scan",
                {
                    "host": host,
                    "port": port,
                    "ssl": ssl,
                    "timeout": timeout,
                    "allow_internal": allow_internal,
                },
            )
        except Exception as exc:
            logger.error("nikto_scan error: %s", exc, exc_info=True)
            raise ToolExecutionError(
                f"Nikto scan failed: {exc}", tool_name="nikto_scan"
            ) from exc

        if not result.get("success"):
            return f"Nikto error: {result.get('error', 'Unknown error')}"

        return self._format_result(result, host, port, ssl)

    def _format_result(self, result: dict, host: str, port: int, ssl: bool) -> str:
        """Format Nikto MCP result into a readable vulnerability list."""
        scheme = "https" if ssl else "http"
        target = f"{scheme}://{host}:{port}"

        vulns = result.get("vulnerabilities", [])
        findings = result.get("findings", [])
        items = vulns or findings

        lines = [f"=== Nikto Scan: {target} ===\n"]

        if not items:
            raw = result.get("output", "")
            lines.append("No structured vulnerabilities returned.")
            if raw:
                lines.append("\n--- Raw output ---")
                lines.append(truncate_output(raw, max_chars=4000))
            return "\n".join(lines)

        lines.append(f"Found {len(items)} finding(s):\n")

        for idx, item in enumerate(items[:50], start=1):
            if isinstance(item, dict):
                for key in ("msg", "description", "message"):
                    msg = item.get(key)
                    if msg:
                        break
                else:
                    msg = str(item)
                osvdb = item.get("osvdbid") or item.get("id") or ""
                url = item.get("url") or item.get("uri") or ""
                line = f"[{idx}] {msg}"
                if osvdb:
                    line += f" (OSVDB-{osvdb})"
                if url:
                    line += f"\n     URL: {url}"
                lines.append(line)
            else:
                lines.append(f"[{idx}] {item}")

        if len(items) > 50:
            lines.append(f"\n... and {len(items) - 50} more findings.")

        return "\n".join(lines)
