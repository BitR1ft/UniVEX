"""
Hash Cracker MCP Server

Wraps hashid, John the Ripper, and Hashcat to expose three tools:

  identify_hash  — detect the type of a hash string
  crack_john     — crack hashes with John the Ripper + rockyou wordlist
  crack_hashcat  — crack hashes with Hashcat (GPU if available, else CPU)

Port: 8006

Safety controls
---------------
* Only hash values are accepted — no plaintext credentials are stored in
  output beyond the cracking result itself.
* Wordlists default to rockyou.txt; custom paths must be absolute and cannot
  traverse outside /usr/share/wordlists.
* All processes are run with a configurable timeout to prevent runaway jobs.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import tempfile
from typing import Any, Dict, List, Optional

from ..base_server import MCPServer, MCPTool

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Binary paths (override via env vars if the container layout differs)
# ---------------------------------------------------------------------------

JOHN_BINARY = os.environ.get("JOHN_PATH", "john")
HASHCAT_BINARY = os.environ.get("HASHCAT_PATH", "hashcat")
HASHID_BINARY = os.environ.get("HASHID_PATH", "hashid")

DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"

# Hashcat mode map for common hash types
_HASHCAT_MODES: Dict[str, int] = {
    "md5": 0,
    "sha1": 100,
    "sha256": 1400,
    "sha512": 1700,
    "ntlm": 1000,
    "lm": 3000,
    "bcrypt": 3200,
    "sha512crypt": 1800,
    "sha256crypt": 7400,
    "md5crypt": 500,
    "descrypt": 1500,
    "netntlmv2": 5600,
    "netntlm": 5500,
    "kerberos5": 13100,
}

# Common hash lengths / patterns for simple detection without hashid
_HASH_PATTERNS: List[Dict[str, Any]] = [
    {"name": "MD5", "pattern": r"^[a-f0-9]{32}$"},
    {"name": "SHA1", "pattern": r"^[a-f0-9]{40}$"},
    {"name": "SHA256", "pattern": r"^[a-f0-9]{64}$"},
    {"name": "SHA512", "pattern": r"^[a-f0-9]{128}$"},
    {"name": "NTLM", "pattern": r"^[a-f0-9]{32}$"},  # same length as MD5
    {"name": "bcrypt", "pattern": r"^\$2[aby]\$\d{2}\$.{53}$"},
    {"name": "sha512crypt", "pattern": r"^\$6\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{86}$"},
    {"name": "sha256crypt", "pattern": r"^\$5\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{43}$"},
    {"name": "md5crypt", "pattern": r"^\$1\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{22}$"},
    {"name": "NetNTLMv2", "pattern": r"^[^:]+::[^:]+:[a-f0-9]{16}:[a-f0-9]{32}:[a-f0-9]+$"},
]


def _validate_wordlist_path(path: str) -> str:
    """Ensure wordlist path is absolute and within /usr/share/wordlists."""
    abs_path = os.path.realpath(path)
    allowed_prefixes = ("/usr/share/wordlists", "/usr/share/seclists")
    if not any(abs_path.startswith(p) for p in allowed_prefixes):
        raise ValueError(
            f"Wordlist path '{path}' is outside allowed directories. "
            "Use a path under /usr/share/wordlists or /usr/share/seclists."
        )
    return abs_path


async def _run(args: List[str], timeout: int = 600) -> str:
    """Run a subprocess and return stdout+stderr."""
    logger.debug("Running: %s", " ".join(args))
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace") + stderr.decode(errors="replace")
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        raise TimeoutError(f"Process timed out after {timeout}s: {args[0]}")
    except FileNotFoundError:
        raise RuntimeError(f"Binary not found: {args[0]}")


def _simple_identify(hash_value: str) -> List[str]:
    """Simple regex-based hash identification (fallback when hashid is absent)."""
    results = []
    for entry in _HASH_PATTERNS:
        if re.match(entry["pattern"], hash_value, re.IGNORECASE):
            results.append(entry["name"])
    return results


class CrackerServer(MCPServer):
    """
    MCP Server for hash identification and cracking.

    Provides:
    - identify_hash : detect hash type
    - crack_john    : crack with John the Ripper
    - crack_hashcat : crack with Hashcat
    """

    def __init__(self):
        super().__init__(
            name="cracker",
            description="Hash identification and cracking using hashid, John the Ripper, and Hashcat",
            port=8006,
        )

    def get_tools(self) -> List[MCPTool]:
        return [
            MCPTool(
                name="identify_hash",
                description=(
                    "Identify the type of a hash string using hashid and pattern matching. "
                    "Returns a list of probable hash formats with recommended Hashcat modes."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "hash_value": {
                            "type": "string",
                            "description": "The hash string to identify",
                        },
                    },
                    "required": ["hash_value"],
                },
            ),
            MCPTool(
                name="crack_john",
                description=(
                    "Crack one or more hashes using John the Ripper with rockyou wordlist. "
                    "Accepts hash values directly or a path to a hash file."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "hashes": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of hash strings to crack",
                        },
                        "hash_format": {
                            "type": "string",
                            "description": "John format string (e.g. 'raw-md5', 'bcrypt', 'nt'). "
                            "Auto-detected if empty.",
                            "default": "",
                        },
                        "wordlist": {
                            "type": "string",
                            "description": "Wordlist path (default: rockyou.txt)",
                            "default": DEFAULT_WORDLIST,
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Max seconds for cracking (default: 300)",
                            "default": 300,
                        },
                    },
                    "required": ["hashes"],
                },
            ),
            MCPTool(
                name="crack_hashcat",
                description=(
                    "Crack hashes using Hashcat (GPU if available, CPU fallback). "
                    "Faster than John for large wordlists."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "hashes": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of hash strings to crack",
                        },
                        "hash_type": {
                            "type": "string",
                            "description": (
                                "Hash type: md5, sha1, sha256, sha512, ntlm, bcrypt, "
                                "sha512crypt, netntlmv2, kerberos5, etc. Auto-detected if empty."
                            ),
                            "default": "",
                        },
                        "wordlist": {
                            "type": "string",
                            "description": "Wordlist path (default: rockyou.txt)",
                            "default": DEFAULT_WORDLIST,
                        },
                        "rules": {
                            "type": "string",
                            "description": "Hashcat rules file path (optional)",
                            "default": "",
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Max seconds for cracking (default: 300)",
                            "default": 300,
                        },
                    },
                    "required": ["hashes"],
                },
            ),
        ]

    async def _handle_tool_call(self, tool_name: str, params: Dict[str, Any]) -> Any:
        handlers = {
            "identify_hash": self._identify_hash,
            "crack_john": self._crack_john,
            "crack_hashcat": self._crack_hashcat,
        }
        handler = handlers.get(tool_name)
        if not handler:
            raise ValueError(f"Unknown tool: {tool_name}")
        return await handler(params)

    # ------------------------------------------------------------------
    # Tool implementations
    # ------------------------------------------------------------------

    async def _identify_hash(self, params: Dict[str, Any]) -> Dict[str, Any]:
        hash_value = params["hash_value"].strip()
        candidates: List[Dict[str, Any]] = []

        # Try hashid first
        try:
            output = await _run([HASHID_BINARY, hash_value, "-m"], timeout=10)
            for line in output.splitlines():
                if "[+]" in line or "Hashcat" in line:
                    name_match = re.search(r"\[([^\]]+)\]", line)
                    mode_match = re.search(r"Hashcat Mode[:\s]+(\d+)", line, re.IGNORECASE)
                    if name_match:
                        candidates.append(
                            {
                                "name": name_match.group(1),
                                "hashcat_mode": int(mode_match.group(1)) if mode_match else None,
                            }
                        )
        except Exception:
            # hashid not available — use simple regex detection
            simple = _simple_identify(hash_value)
            for name in simple:
                candidates.append(
                    {
                        "name": name,
                        "hashcat_mode": _HASHCAT_MODES.get(name.lower()),
                    }
                )

        return {
            "hash_value": hash_value,
            "candidates": candidates,
            "most_likely": candidates[0]["name"] if candidates else "unknown",
        }

    async def _crack_john(self, params: Dict[str, Any]) -> Dict[str, Any]:
        hashes: List[str] = params["hashes"]
        hash_format: str = params.get("hash_format", "")
        wordlist_path: str = params.get("wordlist", DEFAULT_WORDLIST)
        timeout: int = params.get("timeout", 300)

        validated_wl = _validate_wordlist_path(wordlist_path)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as hf:
            hf.write("\n".join(hashes) + "\n")
            hash_file = hf.name

        try:
            args = [JOHN_BINARY, hash_file, f"--wordlist={validated_wl}"]
            if hash_format:
                args.append(f"--format={hash_format}")

            await _run(args, timeout=timeout)

            # Retrieve cracked passwords
            show_args = [JOHN_BINARY, "--show", hash_file]
            if hash_format:
                show_args.append(f"--format={hash_format}")
            show_output = await _run(show_args, timeout=30)

            cracked = _parse_john_show(show_output)
        finally:
            try:
                os.unlink(hash_file)
            except OSError:
                pass

        return {
            "cracked": cracked,
            "cracked_count": len(cracked),
            "total": len(hashes),
        }

    async def _crack_hashcat(self, params: Dict[str, Any]) -> Dict[str, Any]:
        hashes: List[str] = params["hashes"]
        hash_type_str: str = params.get("hash_type", "").lower()
        wordlist_path: str = params.get("wordlist", DEFAULT_WORDLIST)
        rules: str = params.get("rules", "")
        timeout: int = params.get("timeout", 300)

        validated_wl = _validate_wordlist_path(wordlist_path)

        # Determine hashcat mode
        mode: Optional[int] = _HASHCAT_MODES.get(hash_type_str)
        if mode is None and hash_type_str:
            # Try numeric mode directly
            if hash_type_str.isdigit():
                mode = int(hash_type_str)
            else:
                mode = 0  # default MD5

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as hf:
            hf.write("\n".join(hashes) + "\n")
            hash_file = hf.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".potfile", delete=False) as pf:
            potfile = pf.name

        try:
            args = [
                HASHCAT_BINARY,
                "-m", str(mode if mode is not None else 0),
                hash_file,
                validated_wl,
                "--potfile-path", potfile,
                "--force",            # skip GPU driver warnings
                "--status",
                "--status-timer", "10",
                "-q",                 # quiet
            ]
            if rules:
                validated_rules = os.path.realpath(rules)
                args += ["-r", validated_rules]

            await _run(args, timeout=timeout)

            # Parse potfile for results
            cracked = _parse_hashcat_potfile(potfile, hashes)
        finally:
            for path in (hash_file, potfile):
                try:
                    os.unlink(path)
                except OSError:
                    pass

        return {
            "cracked": cracked,
            "cracked_count": len(cracked),
            "total": len(hashes),
            "hashcat_mode": mode,
        }


# ---------------------------------------------------------------------------
# Output parsers
# ---------------------------------------------------------------------------

def _parse_john_show(output: str) -> List[Dict[str, str]]:
    """Parse ``john --show`` output into a list of {hash, password} dicts."""
    results = []
    for line in output.splitlines():
        line = line.strip()
        if ":" in line and not line.startswith("#"):
            parts = line.split(":", 1)
            if len(parts) == 2 and parts[1]:
                results.append({"hash": parts[0], "password": parts[1]})
    return results


def _parse_hashcat_potfile(potfile_path: str, original_hashes: List[str]) -> List[Dict[str, str]]:
    """Parse a hashcat potfile and match results to original hashes."""
    results = []
    try:
        with open(potfile_path) as fh:
            for line in fh:
                line = line.strip()
                if ":" in line:
                    parts = line.rsplit(":", 1)
                    if len(parts) == 2:
                        results.append({"hash": parts[0], "password": parts[1]})
    except FileNotFoundError:
        pass
    return results
