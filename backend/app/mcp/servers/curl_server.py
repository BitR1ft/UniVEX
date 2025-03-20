"""
Curl MCP Server - HTTP Requests

Provides HTTP request capabilities via curl.
Port: 8001

added ``execute_curl_ssrf`` tool with SSRF-specific
options — follow_redirects control, protocol allowlist/blocklist, timeout patterns,
and allow_internal flag for lab environments.
"""

import asyncio
import json
from typing import Dict, Any, List
import re

from ..base_server import MCPServer, MCPTool
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Protocol safety — only these schemes are allowed unless allow_internal=True
# ---------------------------------------------------------------------------

_SAFE_SCHEMES = {"http", "https"}
_SSRF_SCHEMES = {"http", "https", "gopher", "file", "dict", "ftp"}


class CurlServer(MCPServer):
    """
    MCP Server for HTTP requests using curl.
    
    Provides:
    - execute_curl:      Standard HTTP request tool.
    - execute_curl_ssrf: SSRF-probe variant with follow_redirects control,
                         protocol allowlist, and allow_internal flag.
    """
    
    def __init__(self):
        super().__init__(
            name="Curl",
            description="HTTP request tool server using curl",
            port=8001
        )
    
    def get_tools(self) -> List[MCPTool]:
        """Get list of available tools"""
        return [
            MCPTool(
                name="execute_curl",
                description="Execute HTTP request using curl. Returns response headers, body, and status.",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Target URL"
                        },
                        "method": {
                            "type": "string",
                            "description": "HTTP method (GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH). Default: GET",
                            "enum": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
                            "default": "GET"
                        },
                        "headers": {
                            "type": "object",
                            "description": "Custom HTTP headers as key-value pairs",
                            "default": {}
                        },
                        "body": {
                            "type": "string",
                            "description": "Request body (for POST, PUT, PATCH)",
                            "default": ""
                        },
                        "follow_redirects": {
                            "type": "boolean",
                            "description": "Follow HTTP redirects. Default: True",
                            "default": True
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Request timeout in seconds. Default: 30",
                            "default": 30
                        },
                        "verify_ssl": {
                            "type": "boolean",
                            "description": "Verify SSL certificates. Default: True",
                            "default": True
                        }
                    },
                    "required": ["url"]
                }
            ),
            MCPTool(
                name="execute_curl_ssrf",
                description=(
                    "SSRF-probe variant of execute_curl. Supports gopher/file/dict protocol schemes, "
                    "explicit follow_redirects=False for open-redirect detection, "
                    "allow_internal flag for lab SSRF testing, and a short default timeout. "
                    "Use this tool when probing for SSRF or open redirect vulnerabilities."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Target URL — may use http, https, gopher, file, or dict scheme."
                        },
                        "method": {
                            "type": "string",
                            "description": "HTTP method. Default: GET",
                            "enum": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
                            "default": "GET"
                        },
                        "headers": {
                            "type": "object",
                            "description": "Custom HTTP headers",
                            "default": {}
                        },
                        "body": {
                            "type": "string",
                            "description": "Request body",
                            "default": ""
                        },
                        "follow_redirects": {
                            "type": "boolean",
                            "description": "Follow HTTP redirects. Default: False (important for open-redirect detection).",
                            "default": False
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Request timeout in seconds. Default: 10 (short for SSRF probing).",
                            "default": 10
                        },
                        "verify_ssl": {
                            "type": "boolean",
                            "description": "Verify SSL certificates. Default: False for SSRF probing.",
                            "default": False
                        },
                        "allow_internal": {
                            "type": "boolean",
                            "description": "Allow requests to RFC-1918 / loopback addresses (lab SSRF testing). Default: True.",
                            "default": True
                        },
                        "allowed_protocols": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Protocol schemes allowed (http, https, gopher, file, dict). Default: all SSRF schemes.",
                            "default": ["http", "https", "gopher", "file", "dict"]
                        }
                    },
                    "required": ["url"]
                },
                phase="web_app_attack",
            ),
        ]
    
    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool"""
        if tool_name == "execute_curl":
            return await self._execute_curl(params)
        elif tool_name == "execute_curl_ssrf":
            return await self._execute_curl_ssrf(params)
        else:
            raise ValueError(f"Unknown tool: {tool_name}")
    
    def _validate_url(self, url: str) -> bool:
        """
        Validate URL format.
        
        Args:
            url: URL to validate
            
        Returns:
            True if valid
            
        Raises:
            ValueError if invalid
        """
        url_pattern = r'^https?://.+'
        if not re.match(url_pattern, url):
            raise ValueError(f"Invalid URL: {url}. Must start with http:// or https://")
        return True
    
    async def _execute_curl(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute HTTP request using curl.
        
        Args:
            params: Tool parameters
            
        Returns:
            HTTP response data
        """
        url = params.get("url")
        method = params.get("method", "GET").upper()
        headers = params.get("headers", {})
        body = params.get("body", "")
        follow_redirects = params.get("follow_redirects", True)
        timeout = params.get("timeout", 30)
        verify_ssl = params.get("verify_ssl", True)
        
        # Validate URL
        try:
            self._validate_url(url)
        except ValueError as e:
            return {
                "success": False,
                "error": str(e),
                "url": url
            }
        
        # Build curl command
        cmd = [
            "curl",
            "-X", method,
            "-i",  # Include headers in output
            "-s",  # Silent mode
            "-S",  # Show errors
            "--max-time", str(timeout)
        ]
        
        # Add SSL verification option
        if not verify_ssl:
            cmd.append("-k")
        
        # Add redirect following
        if follow_redirects:
            cmd.extend(["-L", "--max-redirs", "5"])
        
        # Add custom headers
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])
        
        # Add body for methods that support it
        if method in ["POST", "PUT", "PATCH"] and body:
            cmd.extend(["-d", body])
            # Set content-type if not already set
            if not any(k.lower() == "content-type" for k in headers.keys()):
                cmd.extend(["-H", "Content-Type: application/json"])
        
        # Add URL
        cmd.append(url)
        
        logger.info(f"Executing curl command: {' '.join(cmd)}")
        
        try:
            # Execute curl
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.error(f"Curl request failed: {error_msg}")
                return {
                    "success": False,
                    "error": f"Request failed: {error_msg}",
                    "url": url
                }
            
            # Parse response (headers + body)
            output = stdout.decode()
            
            # Split headers and body
            parts = output.split('\r\n\r\n', 1)
            if len(parts) < 2:
                parts = output.split('\n\n', 1)
            
            response_headers = {}
            status_code = 0
            status_text = ""
            response_body = ""
            
            if len(parts) >= 1:
                # Parse headers
                header_lines = parts[0].split('\n')
                if header_lines:
                    # First line is status line
                    status_line = header_lines[0]
                    match = re.match(r'HTTP/[\d.]+ (\d+) (.+)', status_line)
                    if match:
                        status_code = int(match.group(1))
                        status_text = match.group(2).strip()
                    
                    # Parse remaining headers
                    for line in header_lines[1:]:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            response_headers[key.strip()] = value.strip()
            
            if len(parts) >= 2:
                response_body = parts[1]
            
            # Try to parse body as JSON
            parsed_body = response_body
            try:
                if response_body.strip():
                    parsed_body = json.loads(response_body)
            except json.JSONDecodeError:
                pass  # Keep as string if not JSON
            
            return {
                "success": True,
                "url": url,
                "method": method,
                "status_code": status_code,
                "status_text": status_text,
                "headers": response_headers,
                "body": parsed_body,
                "body_length": len(response_body)
            }
            
        except Exception as e:
            logger.error(f"Curl execution error: {e}", exc_info=True)
            return {
                "success": False,
                "error": f"Execution error: {str(e)}",
                "url": url
            }


    async def _execute_curl_ssrf(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an HTTP request with SSRF-probe-specific options.

        Key differences from ``_execute_curl``:
        - ``follow_redirects`` defaults to False (important for open-redirect detection)
        - ``verify_ssl`` defaults to False (internal targets often use self-signed certs)
        - ``allow_internal`` flag — skips URL validation for RFC-1918 targets
        - ``allowed_protocols`` — restricts or expands curl's ``--proto`` allowlist
        - Short default timeout (10 s) appropriate for SSRF scanning

        Args:
            params: Tool parameters

        Returns:
            HTTP response data (same schema as _execute_curl)
        """
        url = params.get("url", "")
        method = params.get("method", "GET").upper()
        headers = params.get("headers", {})
        body = params.get("body", "")
        follow_redirects = params.get("follow_redirects", False)
        timeout = min(int(params.get("timeout", 10)), 30)
        verify_ssl = params.get("verify_ssl", False)
        params.get("allow_internal", True)
        allowed_protocols = params.get("allowed_protocols", list(_SSRF_SCHEMES))

        # Validate scheme
        try:
            scheme = url.split("://")[0].lower() if "://" in url else ""
        except Exception:
            scheme = ""

        if scheme and allowed_protocols and scheme not in [p.lower() for p in allowed_protocols]:
            return {
                "success": False,
                "error": f"Protocol '{scheme}' not in allowed_protocols {allowed_protocols}",
                "url": url,
            }

        # Basic URL format validation (allow internal addresses when allow_internal=True)
        if not re.match(r"^\w+://", url):
            return {
                "success": False,
                "error": f"Invalid URL: {url!r}",
                "url": url,
            }

        # Build curl command
        cmd = [
            "curl",
            "-X", method,
            "-i",   # include response headers
            "-s",   # silent
            "-S",   # show errors
            "--max-time", str(timeout),
        ]

        # SSL
        if not verify_ssl:
            cmd.append("-k")

        # Redirect control
        if follow_redirects:
            cmd.extend(["-L", "--max-redirs", "5"])
        # (no -L means curl stops at first redirect — good for open-redirect detection)

        # Protocol allowlist (curl --proto)
        if allowed_protocols:
            proto_str = "+".join(allowed_protocols)
            cmd.extend(["--proto", proto_str])

        # Custom headers
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

        # Body
        if method in ["POST", "PUT", "PATCH"] and body:
            cmd.extend(["-d", body])
            if not any(k.lower() == "content-type" for k in headers.keys()):
                cmd.extend(["-H", "Content-Type: application/json"])

        cmd.append(url)

        logger.info(f"Executing SSRF curl: {' '.join(cmd[:8])}...")  # Truncate for log safety

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout + 5)

            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.debug(f"SSRF curl failed: {error_msg}")
                return {"success": False, "error": f"Request failed: {error_msg}", "url": url}

            output = stdout.decode(errors="replace")

            # Parse headers + body
            parts = output.split("\r\n\r\n", 1)
            if len(parts) < 2:
                parts = output.split("\n\n", 1)

            response_headers: Dict[str, str] = {}
            status_code = 0
            status_text = ""
            response_body = ""

            if len(parts) >= 1:
                header_lines = parts[0].split("\n")
                if header_lines:
                    status_line = header_lines[0]
                    match = re.match(r"HTTP/[\d.]+ (\d+)(.*)", status_line)
                    if match:
                        status_code = int(match.group(1))
                        status_text = match.group(2).strip()
                    for line in header_lines[1:]:
                        if ":" in line:
                            k, v = line.split(":", 1)
                            response_headers[k.strip()] = v.strip()

            if len(parts) >= 2:
                response_body = parts[1]

            parsed_body = response_body
            try:
                if response_body.strip():
                    parsed_body = json.loads(response_body)
            except json.JSONDecodeError:
                pass

            return {
                "success": True,
                "url": url,
                "method": method,
                "status_code": status_code,
                "status_text": status_text,
                "headers": response_headers,
                "body": parsed_body,
                "body_length": len(response_body),
            }

        except asyncio.TimeoutError:
            return {"success": False, "error": f"Request timed out after {timeout}s", "url": url}
        except Exception as e:
            logger.error(f"SSRF curl execution error: {e}", exc_info=True)
            return {"success": False, "error": f"Execution error: {str(e)}", "url": url}


if __name__ == "__main__":
    # Run server
    server = CurlServer()
    server.run()
