"""
SearchSploit Tool

Searches ExploitDB for known exploits matching a service name and version.
Returns exploit titles, paths, CVEs, and matching Metasploit modules.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, Optional

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import (
    ToolExecutionError,
    truncate_output,
    with_timeout,
)

logger = logging.getLogger(__name__)


class SearchSploitTool(BaseTool):
    """Search ExploitDB for known exploits using searchsploit."""

    def __init__(self):
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="searchsploit",
            description=(
                "Search ExploitDB for known exploits matching a service name and version. "
                "Returns exploit titles, file paths, CVE references, and Metasploit module "
                "suggestions where available. "
                "Example queries: 'vsftpd 2.3.4', 'apache 2.4.49', 'samba 3.5.0'."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Service name and version to search for, e.g. 'vsftpd 2.3.4'",
                    },
                    "exact": {
                        "type": "boolean",
                        "description": "Use exact version matching (--exact flag)",
                        "default": False,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds",
                        "default": 30,
                    },
                },
                "required": ["query"],
            },
        )

    @with_timeout(60)
    async def execute(
        self,
        query: str,
        exact: bool = False,
        timeout: int = 30,
        **kwargs: Any,
    ) -> str:
        """Search ExploitDB and return formatted exploit list."""
        try:
            cmd = ["searchsploit", "--json"]
            if exact:
                cmd.append("--exact")
            # Split query into separate terms so searchsploit ANDs them
            cmd.extend(query.split())

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

        except FileNotFoundError:
            return (
                "Error: 'searchsploit' not found. "
                "Install with: apt-get install exploitdb  "
                "or: git clone https://github.com/offensive-security/exploitdb"
            )
        except asyncio.TimeoutError:
            return f"searchsploit timed out after {timeout}s for query: {query}"
        except Exception as exc:
            raise ToolExecutionError(
                f"searchsploit failed: {exc}", tool_name="searchsploit"
            ) from exc

        raw = stdout.decode(errors="replace").strip()
        if not raw:
            err = stderr.decode(errors="replace").strip()
            return (
                f"searchsploit returned no output for '{query}'. "
                f"{f'Error: {err}' if err else 'Ensure the exploitdb database is up to date: searchsploit -u'}"
            )

        return self._parse_and_format(raw, query)

    def _parse_and_format(self, raw_json: str, query: str) -> str:
        """Parse JSON output from searchsploit and format results."""
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            # Fallback: return truncated raw output
            return (
                f"searchsploit results for '{query}' (raw output — JSON parse failed):\n\n"
                + truncate_output(raw_json, max_chars=4000)
            )

        exploits = data.get("RESULTS_EXPLOIT", []) + data.get("RESULTS_SHELLCODE", [])

        if not exploits:
            return f"No exploits found in ExploitDB for: {query}"

        lines = [
            f"=== SearchSploit Results for '{query}' ===\n",
            f"Found {len(exploits)} exploit(s):\n",
        ]

        msf_suggestions: list[str] = []

        for idx, exploit in enumerate(exploits[:30], start=1):
            title = exploit.get("Title", "Unknown")
            path = exploit.get("Path", "")
            edb_id = exploit.get("EDB-ID", "")
            exploit_type = exploit.get("Type", "")
            platform = exploit.get("Platform", "")
            cve = self._extract_cve(title + " " + path)

            lines.append(f"\n[{idx}] {title}")
            if edb_id:
                lines.append(f"     EDB-ID  : {edb_id}")
            if cve:
                lines.append(f"     CVE     : {cve}")
            if exploit_type:
                lines.append(f"     Type    : {exploit_type}")
            if platform:
                lines.append(f"     Platform: {platform}")
            if path:
                lines.append(f"     Path    : {path}")

            # Check for Metasploit module annotation
            msf_module = self._suggest_msf_module(title, path)
            if msf_module:
                lines.append(f"     MSF     : {msf_module}")
                msf_suggestions.append(msf_module)

        if len(exploits) > 30:
            lines.append(f"\n... and {len(exploits) - 30} more results (use exact=true to narrow down).")

        if msf_suggestions:
            lines.append("\n\n[Metasploit Suggestions]")
            lines.append("Run in msfconsole:")
            for msf in dict.fromkeys(msf_suggestions):
                lines.append(f"  use {msf}")

        lines.append(
            "\n\nTo view/copy an exploit:\n"
            "  searchsploit -x <EDB-ID>\n"
            "  searchsploit -m <EDB-ID>"
        )

        return "\n".join(lines)

    @staticmethod
    def _extract_cve(text: str) -> Optional[str]:
        """Extract the first CVE identifier from text."""
        match = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
        return match.group(0).upper() if match else None

    @staticmethod
    def _suggest_msf_module(title: str, path: str) -> Optional[str]:
        """
        Suggest a Metasploit module based on known exploit names.

        Maps well-known ExploitDB entries to their Metasploit equivalents.
        """
        combined = (title + " " + path).lower()

        # Known mappings: keyword fragment → MSF module path
        _MSF_MAP = [
            ("vsftpd 2.3.4", "exploit/unix/ftp/vsftpd_234_backdoor"),
            ("ms17-010", "exploit/windows/smb/ms17_010_eternalblue"),
            ("ms08-067", "exploit/windows/smb/ms08_067_netapi"),
            ("eternal blue", "exploit/windows/smb/ms17_010_eternalblue"),
            ("eternalblue", "exploit/windows/smb/ms17_010_eternalblue"),
            ("samba usermap", "exploit/multi/samba/usermap_script"),
            ("usermap_script", "exploit/multi/samba/usermap_script"),
            ("log4j", "exploit/multi/misc/log4shell_header_injection"),
            ("log4shell", "exploit/multi/misc/log4shell_header_injection"),
            ("shellshock", "exploit/multi/http/apache_mod_cgi_bash_env_exec"),
            ("heartbleed", "auxiliary/scanner/ssl/openssl_heartbleed"),
            ("ms14-064", "exploit/windows/browser/ms14_064_ole_code_execution"),
            ("drupalgeddon", "exploit/unix/webapp/drupal_drupalgeddon2"),
            ("struts2", "exploit/multi/http/struts2_content_type_ognl"),
            ("weblogic", "exploit/multi/misc/weblogic_deserialize_asyncresponseservice"),
        ]

        for keyword, module in _MSF_MAP:
            if keyword in combined:
                return module
        return None
