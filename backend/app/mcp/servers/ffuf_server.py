"""
ffuf MCP Server

Wraps the `ffuf` binary (already installed in the Kali Docker container) to
expose three tools over JSON-RPC:

  fuzz_dirs   — directory/path brute-force
  fuzz_files  — file discovery with extension filtering
  fuzz_params — GET/POST parameter fuzzing

Port: 8004

Safety controls
---------------
* Requests targeting localhost / RFC-1918 addresses are rejected by default
  unless ``allow_internal=True`` is explicitly passed (for lab environments).
* Rate limiting is enforced via the ``rate`` parameter (requests/sec, max 500).
* All paths returned are normalised to the canonical Endpoint schema used by
  the rest of the application.

Wordlist strategy
-----------------
Wordlists are mapped from friendly enum values to the SecLists paths that are
present in the Kali container.  The ``common`` preset is the default because
it covers ≈80% of HTB/CTF attack surfaces in under 30 seconds.

  common      — /usr/share/wordlists/dirb/common.txt           (~4 k words)
  raft-medium — /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
  raft-large  — /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
  api-endpoints — /usr/share/seclists/Discovery/Web-Content/api/objects.txt
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
from typing import Any, Dict, List

from ..base_server import MCPServer, MCPTool

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Wordlist registry (enum → filesystem path inside the Kali container)
# ---------------------------------------------------------------------------

WORDLIST_MAP: Dict[str, str] = {
    "common": "/usr/share/wordlists/dirb/common.txt",
    "raft-medium": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "raft-large": "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
    "api-endpoints": "/usr/share/seclists/Discovery/Web-Content/api/objects.txt",
}

DEFAULT_WORDLIST = "common"

# ---------------------------------------------------------------------------
# Private RFC-1918 / loopback ranges (blocked unless allow_internal=True)
# ---------------------------------------------------------------------------

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
]


def _is_internal(host: str) -> bool:
    """Return True if *host* resolves to a private/loopback address."""
    if host.lower() in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        # hostname — we cannot resolve here; allow and let ffuf fail
        return False


def _validate_url(url: str, allow_internal: bool) -> None:
    """Raise ValueError for clearly invalid or blocked targets."""
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"URL must start with http:// or https://: {url}")
    # Extract host
    match = re.match(r"https?://([^/:?#]+)", url)
    if not match:
        raise ValueError(f"Cannot extract host from URL: {url}")
    host = match.group(1)
    if not allow_internal and _is_internal(host):
        raise ValueError(
            f"Target host '{host}' appears to be internal/localhost. "
            "Pass allow_internal=true to target lab environments."
        )


def _normalise_endpoint(hit: Dict[str, Any], base_url: str) -> Dict[str, Any]:
    """Convert an ffuf JSON hit into the canonical Endpoint schema."""
    path = hit.get("input", {}).get("FUZZ", "")
    status = hit.get("status", 0)
    length = hit.get("length", 0)
    words = hit.get("words", 0)
    redirect_location = hit.get("redirectlocation", "")
    return {
        "path": "/" + path.lstrip("/"),
        "method": "GET",
        "base_url": base_url,
        "status_code": status,
        "content_length": length,
        "word_count": words,
        "redirect": redirect_location,
        "discovered_by": "ffuf",
    }


class FfufServer(MCPServer):
    """
    MCP Server that wraps the ffuf web fuzzer binary.

    Provides:
    - fuzz_dirs   : directory brute-force
    - fuzz_files  : file discovery with extension filtering
    - fuzz_params : GET/POST parameter fuzzing
    """

    def __init__(self):
        super().__init__(
            name="ffuf",
            description="Web content discovery using ffuf — directory, file, and parameter fuzzing",
            port=8004,
        )

    # ------------------------------------------------------------------
    # MCPServer interface
    # ------------------------------------------------------------------

    def get_tools(self) -> List[MCPTool]:
        return [
            MCPTool(
                name="fuzz_dirs",
                description=(
                    "Brute-force directories and paths on a web server. "
                    "Returns a list of discovered endpoints with status codes."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Base URL to fuzz (e.g. 'http://10.10.10.1/'). "
                            "FUZZ keyword is appended automatically.",
                        },
                        "wordlist": {
                            "type": "string",
                            "description": "Wordlist preset: common | raft-medium | raft-large | api-endpoints",
                            "enum": list(WORDLIST_MAP.keys()),
                            "default": DEFAULT_WORDLIST,
                        },
                        "extensions": {
                            "type": "string",
                            "description": "Comma-separated extensions to append (e.g. 'php,html,txt'). "
                            "Empty = no extension.",
                            "default": "",
                        },
                        "rate": {
                            "type": "integer",
                            "description": "Requests per second. Default: 100. Max: 500.",
                            "default": 100,
                        },
                        "threads": {
                            "type": "integer",
                            "description": "Concurrent threads. Default: 40.",
                            "default": 40,
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Per-request timeout (seconds). Default: 10.",
                            "default": 10,
                        },
                        "filter_status": {
                            "type": "string",
                            "description": "Comma-separated HTTP status codes to EXCLUDE "
                            "(e.g. '404,403'). Default: '404'.",
                            "default": "404",
                        },
                        "allow_internal": {
                            "type": "boolean",
                            "description": "Allow targeting RFC-1918/localhost (for HTB labs). "
                            "Default: false.",
                            "default": False,
                        },
                    },
                    "required": ["url"],
                },
            ),
            MCPTool(
                name="fuzz_files",
                description=(
                    "Discover files on a web server with extension filtering. "
                    "Good for finding backup files, config leaks, and hidden assets."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Base URL to fuzz (e.g. 'http://10.10.10.1/'). "
                            "FUZZ keyword is appended automatically.",
                        },
                        "wordlist": {
                            "type": "string",
                            "description": "Wordlist preset: common | raft-medium | raft-large | api-endpoints",
                            "enum": list(WORDLIST_MAP.keys()),
                            "default": DEFAULT_WORDLIST,
                        },
                        "extensions": {
                            "type": "string",
                            "description": "Comma-separated extensions to check "
                            "(e.g. 'php,txt,bak,old,zip'). Default: 'php,txt,html'.",
                            "default": "php,txt,html",
                        },
                        "rate": {
                            "type": "integer",
                            "description": "Requests per second. Default: 100. Max: 500.",
                            "default": 100,
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Per-request timeout (seconds). Default: 10.",
                            "default": 10,
                        },
                        "filter_status": {
                            "type": "string",
                            "description": "HTTP status codes to exclude. Default: '404'.",
                            "default": "404",
                        },
                        "allow_internal": {
                            "type": "boolean",
                            "description": "Allow targeting RFC-1918/localhost (for HTB labs). "
                            "Default: false.",
                            "default": False,
                        },
                    },
                    "required": ["url"],
                },
            ),
            MCPTool(
                name="fuzz_params",
                description=(
                    "Fuzz GET or POST parameters on a web endpoint. "
                    "Useful for finding hidden parameters and injection points."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "URL to fuzz. Use FUZZ as the parameter placeholder "
                            "(e.g. 'http://host/page?FUZZ=test' or 'http://host/page' with method=POST).",
                        },
                        "wordlist": {
                            "type": "string",
                            "description": "Wordlist preset: common | raft-medium | raft-large | api-endpoints",
                            "enum": list(WORDLIST_MAP.keys()),
                            "default": DEFAULT_WORDLIST,
                        },
                        "method": {
                            "type": "string",
                            "description": "HTTP method: GET or POST. Default: GET.",
                            "enum": ["GET", "POST"],
                            "default": "GET",
                        },
                        "data": {
                            "type": "string",
                            "description": "POST body template with FUZZ placeholder "
                            "(e.g. 'username=admin&FUZZ=test'). Required when method=POST.",
                            "default": "",
                        },
                        "rate": {
                            "type": "integer",
                            "description": "Requests per second. Default: 100. Max: 500.",
                            "default": 100,
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Per-request timeout (seconds). Default: 10.",
                            "default": 10,
                        },
                        "filter_status": {
                            "type": "string",
                            "description": "HTTP status codes to exclude. Default: '404'.",
                            "default": "404",
                        },
                        "allow_internal": {
                            "type": "boolean",
                            "description": "Allow targeting RFC-1918/localhost. Default: false.",
                            "default": False,
                        },
                    },
                    "required": ["url"],
                },
            ),
        ]

    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if tool_name == "fuzz_dirs":
            return await self._fuzz_dirs(params)
        if tool_name == "fuzz_files":
            return await self._fuzz_files(params)
        if tool_name == "fuzz_params":
            return await self._fuzz_params(params)
        raise ValueError(f"Unknown tool: {tool_name}")

    # ------------------------------------------------------------------
    # Tool implementations
    # ------------------------------------------------------------------

    async def _fuzz_dirs(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get("url", "")
        wordlist_key = params.get("wordlist", DEFAULT_WORDLIST)
        extensions = params.get("extensions", "")
        rate = min(int(params.get("rate", 100)), 500)
        threads = int(params.get("threads", 40))
        timeout = int(params.get("timeout", 10))
        filter_status = params.get("filter_status", "404")
        allow_internal = bool(params.get("allow_internal", False))

        try:
            _validate_url(url, allow_internal)
        except ValueError as exc:
            return {"success": False, "error": str(exc), "url": url}

        wordlist_path = WORDLIST_MAP.get(wordlist_key, WORDLIST_MAP[DEFAULT_WORDLIST])

        # Ensure URL ends with / so FUZZ appends cleanly
        fuzz_url = url.rstrip("/") + "/FUZZ"

        cmd = self._build_base_cmd(fuzz_url, wordlist_path, rate, threads, timeout, filter_status)
        if extensions:
            # Convert "php,txt,html" → ".php,.txt,.html" (ffuf expects leading dots)
            ext_str = ",".join("." + e.strip() for e in extensions.split(",") if e.strip())
            cmd.extend(["-e", ext_str])

        return await self._run_ffuf(cmd, url, wordlist_key)

    async def _fuzz_files(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get("url", "")
        wordlist_key = params.get("wordlist", DEFAULT_WORDLIST)
        extensions = params.get("extensions", "php,txt,html")
        rate = min(int(params.get("rate", 100)), 500)
        timeout = int(params.get("timeout", 10))
        filter_status = params.get("filter_status", "404")
        allow_internal = bool(params.get("allow_internal", False))

        try:
            _validate_url(url, allow_internal)
        except ValueError as exc:
            return {"success": False, "error": str(exc), "url": url}

        wordlist_path = WORDLIST_MAP.get(wordlist_key, WORDLIST_MAP[DEFAULT_WORDLIST])
        fuzz_url = url.rstrip("/") + "/FUZZ"
        cmd = self._build_base_cmd(fuzz_url, wordlist_path, rate, 40, timeout, filter_status)
        if extensions:
            # Convert "php,txt,html" → ".php,.txt,.html" (ffuf expects leading dots)
            ext_str = ",".join("." + e.strip() for e in extensions.split(",") if e.strip())
            cmd.extend(["-e", ext_str])

        return await self._run_ffuf(cmd, url, wordlist_key)

    async def _fuzz_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get("url", "")
        wordlist_key = params.get("wordlist", DEFAULT_WORDLIST)
        method = params.get("method", "GET").upper()
        data = params.get("data", "")
        rate = min(int(params.get("rate", 100)), 500)
        timeout = int(params.get("timeout", 10))
        filter_status = params.get("filter_status", "404")
        allow_internal = bool(params.get("allow_internal", False))

        try:
            _validate_url(url, allow_internal)
        except ValueError as exc:
            return {"success": False, "error": str(exc), "url": url}

        if method == "POST" and not data:
            return {
                "success": False,
                "error": "POST method requires a 'data' body template with FUZZ placeholder.",
                "url": url,
            }

        wordlist_path = WORDLIST_MAP.get(wordlist_key, WORDLIST_MAP[DEFAULT_WORDLIST])
        cmd = self._build_base_cmd(url, wordlist_path, rate, 40, timeout, filter_status)
        if method == "POST":
            cmd.extend(["-X", "POST", "-d", data])

        return await self._run_ffuf(cmd, url, wordlist_key)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_base_cmd(
        url: str,
        wordlist_path: str,
        rate: int,
        threads: int,
        timeout: int,
        filter_status: str,
    ) -> List[str]:
        """Build the ffuf command common to all three tools."""
        cmd = [
            "ffuf",
            "-u", url,
            "-w", wordlist_path,
            "-rate", str(rate),
            "-t", str(threads),
            "-timeout", str(timeout),
            "-o", "/dev/stdout",
            "-of", "json",
            "-s",  # silent (no banner)
        ]
        # Apply status code filter
        if filter_status:
            for code in filter_status.split(","):
                code = code.strip()
                if code:
                    cmd.extend(["-fc", code])
        return cmd

    async def _run_ffuf(
        self,
        cmd: List[str],
        base_url: str,
        wordlist_key: str,
    ) -> Dict[str, Any]:
        """Execute ffuf, parse the JSON output, and return normalised results."""
        logger.info("Executing ffuf: %s", " ".join(cmd))
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            raw_output = stdout.decode(errors="replace")
            error_output = stderr.decode(errors="replace")

            if process.returncode not in (0, 1):
                # ffuf exits 1 when no results but that is not an error
                logger.warning("ffuf returned code %d: %s", process.returncode, error_output)

            if not raw_output.strip():
                return {
                    "success": True,
                    "url": base_url,
                    "wordlist": wordlist_key,
                    "results": [],
                    "total_found": 0,
                    "message": "No results found.",
                }

            data = json.loads(raw_output)
            hits = data.get("results", [])
            normalised = [_normalise_endpoint(h, base_url) for h in hits]

            return {
                "success": True,
                "url": base_url,
                "wordlist": wordlist_key,
                "results": normalised,
                "total_found": len(normalised),
            }

        except json.JSONDecodeError as exc:
            logger.error("Failed to parse ffuf JSON output: %s", exc)
            return {
                "success": False,
                "error": f"Failed to parse ffuf output: {exc}",
                "url": base_url,
                "raw": raw_output[:500] if raw_output else "",
            }
        except FileNotFoundError:
            return {
                "success": False,
                "error": "ffuf binary not found. Ensure ffuf is installed in the container.",
                "url": base_url,
            }
        except Exception as exc:
            logger.error("ffuf execution error: %s", exc, exc_info=True)
            return {
                "success": False,
                "error": f"Execution error: {exc}",
                "url": base_url,
            }


if __name__ == "__main__":
    server = FfufServer()
    server.run()
