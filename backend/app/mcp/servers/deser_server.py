"""
Deserialization MCP Server — Java / PHP / .NET Deserialization Engine (Port 8012)

MCP JSON-RPC 2.0 server that wraps ysoserial (Java), phpggc (PHP), and
ysoserial.net (.NET) to expose deserialization payload generation and
endpoint detection through the standard MCP call interface.

Tools exposed:
  java_deser_generate       — Generate Java ysoserial payload
  java_deser_list_chains    — List available Java gadget chains
  java_deser_detect         — Detect Java serialized objects
  php_deser_generate        — Generate PHP phpggc payload
  php_deser_list_chains     — List available PHP gadget chains
  php_deser_detect          — Detect PHP serialized objects
  dotnet_deser_generate     — Generate .NET ysoserial.net payload
  dotnet_deser_list_gadgets — List available .NET gadgets
  dotnet_deser_detect       — Detect .NET serialized/ViewState data
  deser_probe_url           — Probe a URL for deserialization endpoints
  deser_analyse_request     — Analyse params/headers/cookies/body
  deser_list_indicators     — List all serialization detection indicators

Environment variables:
  YSOSERIAL_PATH     — path to ysoserial binary (default: ysoserial)
  PHPGGC_PATH        — path to phpggc binary (default: phpggc)
  YSOSERIAL_NET_PATH — path to ysoserial.net binary (default: ysoserial.exe)
  DESER_MCP_PORT     — port for this MCP server (default: 8012)
  DESER_MCP_API_KEY  — bearer token for this MCP server (optional)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List

from app.mcp.base_server import MCPServer, MCPTool

logger = logging.getLogger(__name__)

_DESER_MCP_PORT = int(os.getenv("DESER_MCP_PORT", "8012"))
_DESER_MCP_API_KEY = os.getenv("DESER_MCP_API_KEY", "")


class DeserializationMCPServer(MCPServer):
    """
    MCP Server wrapping Java/PHP/.NET deserialization payload generation engines.

    Agents call these tools to generate exploitation payloads, detect serialized
    objects in application traffic, and probe endpoints for deserialization vulns.
    """

    PORT = _DESER_MCP_PORT

    def __init__(self) -> None:
        super().__init__(
            name="Deserialization",
            description=(
                "Java/PHP/.NET deserialization exploitation engine — "
                "payload generation (ysoserial/phpggc/ysoserial.net), "
                "endpoint detection, and gadget chain database"
            ),
            port=self.PORT,
            api_key=_DESER_MCP_API_KEY or None,
        )

    # ------------------------------------------------------------------
    # Tool declarations
    # ------------------------------------------------------------------

    def get_tools(self) -> List[MCPTool]:
        return [
            # --- Java ---
            MCPTool(
                name="java_deser_generate",
                description="Generate a Java deserialization payload using a ysoserial gadget chain.",
                phase="exploit",
                parameters={
                    "type": "object",
                    "properties": {
                        "gadget": {
                            "type": "string",
                            "description": "Gadget chain (e.g. 'CommonsCollections6', 'URLDNS', 'Spring1').",
                        },
                        "payload_type": {
                            "type": "string",
                            "enum": ["RCE", "DNS", "FileRead"],
                            "description": "Payload type. Default: RCE.",
                        },
                        "command": {
                            "type": "string",
                            "description": "Command (RCE), callback URL (DNS), or file path (FileRead).",
                        },
                        "output_format": {
                            "type": "string",
                            "enum": ["base64", "raw", "hex"],
                            "description": "Output encoding. Default: base64.",
                        },
                    },
                    "required": ["gadget", "command"],
                },
            ),
            MCPTool(
                name="java_deser_list_chains",
                description="List all available Java gadget chains from the database, optionally filtered by library.",
                phase="exploit",
                parameters={
                    "type": "object",
                    "properties": {
                        "library": {
                            "type": "string",
                            "description": "Filter by library name (e.g. 'commons-collections', 'spring').",
                        },
                    },
                },
            ),
            MCPTool(
                name="java_deser_detect",
                description="Detect whether a value contains a serialized Java object (magic bytes / base64 prefix).",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "value": {
                            "type": "string",
                            "description": "Raw or base64-encoded value to check.",
                        },
                    },
                    "required": ["value"],
                },
            ),
            # --- PHP ---
            MCPTool(
                name="php_deser_generate",
                description="Generate a PHP object injection payload using a PHPGGC gadget chain.",
                phase="exploit",
                parameters={
                    "type": "object",
                    "properties": {
                        "chain": {
                            "type": "string",
                            "description": "PHPGGC chain (e.g. 'Laravel/RCE1', 'Symfony/RCE2').",
                        },
                        "payload_type": {
                            "type": "string",
                            "enum": ["RCE", "FileRead", "FileWrite", "SSRF"],
                            "description": "Payload type. Default: RCE.",
                        },
                        "command": {
                            "type": "string",
                            "description": "Command / file path / URL.",
                        },
                        "output_format": {
                            "type": "string",
                            "enum": ["base64", "raw", "url"],
                            "description": "Output encoding. Default: base64.",
                        },
                    },
                    "required": ["chain", "command"],
                },
            ),
            MCPTool(
                name="php_deser_list_chains",
                description="List all PHP gadget chains from the database, optionally filtered by framework.",
                phase="exploit",
                parameters={
                    "type": "object",
                    "properties": {
                        "framework": {
                            "type": "string",
                            "description": "Filter by framework (e.g. 'Laravel', 'Symfony', 'WordPress').",
                        },
                    },
                },
            ),
            MCPTool(
                name="php_deser_detect",
                description="Detect whether a value contains PHP serialized data.",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "value": {
                            "type": "string",
                            "description": "Value to check for PHP serialization format.",
                        },
                    },
                    "required": ["value"],
                },
            ),
            # --- .NET ---
            MCPTool(
                name="dotnet_deser_generate",
                description="Generate a .NET deserialization payload using ysoserial.net.",
                phase="exploit",
                parameters={
                    "type": "object",
                    "properties": {
                        "formatter": {
                            "type": "string",
                            "description": "Target formatter (e.g. 'BinaryFormatter', 'ViewState', 'Json.NET').",
                        },
                        "gadget": {
                            "type": "string",
                            "description": "Gadget chain (e.g. 'TypeConfuseDelegate', 'ObjectDataProvider').",
                        },
                        "command": {
                            "type": "string",
                            "description": "Command to execute.",
                        },
                        "machine_key": {
                            "type": "string",
                            "description": "ASP.NET machineKey decryptionKey (hex) for ViewState.",
                        },
                        "validation_key": {
                            "type": "string",
                            "description": "ASP.NET machineKey validationKey (hex) for ViewState.",
                        },
                        "output_format": {
                            "type": "string",
                            "enum": ["base64", "raw", "hex", "minify"],
                            "description": "Output format. Default: base64.",
                        },
                    },
                    "required": ["formatter", "gadget", "command"],
                },
            ),
            MCPTool(
                name="dotnet_deser_list_gadgets",
                description="List all .NET deserialization gadgets, optionally filtered by formatter.",
                phase="exploit",
                parameters={
                    "type": "object",
                    "properties": {
                        "formatter": {
                            "type": "string",
                            "description": "Filter by formatter name.",
                        },
                    },
                },
            ),
            MCPTool(
                name="dotnet_deser_detect",
                description="Detect .NET serialized data: NRBF binary, ViewState, or custom formatters.",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "value": {
                            "type": "string",
                            "description": "Value to analyse.",
                        },
                        "detect_viewstate": {
                            "type": "boolean",
                            "description": "Perform detailed ViewState analysis. Default: false.",
                        },
                    },
                    "required": ["value"],
                },
            ),
            # --- Generic detection ---
            MCPTool(
                name="deser_probe_url",
                description="Probe a URL for deserialization endpoints by analysing response headers, cookies, and body.",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL to probe."},
                        "timeout": {"type": "integer", "description": "HTTP timeout in seconds. Default: 10."},
                    },
                    "required": ["url"],
                },
            ),
            MCPTool(
                name="deser_analyse_request",
                description="Analyse request parameters, headers, cookies, and POST body for serialized data.",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "params": {"type": "object", "description": "Query/POST parameters dict."},
                        "headers": {"type": "object", "description": "Request headers dict."},
                        "cookies": {"type": "object", "description": "Cookies dict."},
                        "post_body": {"type": "string", "description": "Raw POST body."},
                    },
                },
            ),
            MCPTool(
                name="deser_list_indicators",
                description="List all serialization format detection indicators, magic bytes, and common parameter names.",
                phase="recon",
                parameters={"type": "object", "properties": {}},
            ),
        ]

    # ------------------------------------------------------------------
    # Tool execution router
    # ------------------------------------------------------------------

    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Any:
        from app.agent.tools.deserialization_tools import (
            JavaDeserializeTool,
            PHPDeserializeTool,
            DotNetDeserializeTool,
            DeserializationDetectTool,
        )

        java_tool = JavaDeserializeTool()
        php_tool = PHPDeserializeTool()
        dotnet_tool = DotNetDeserializeTool()
        detect_tool = DeserializationDetectTool()

        if tool_name == "java_deser_generate":
            return await java_tool.execute(
                action="generate",
                gadget=params.get("gadget"),
                payload_type=params.get("payload_type", "RCE"),
                command=params.get("command"),
                output_format=params.get("output_format", "base64"),
            )
        elif tool_name == "java_deser_list_chains":
            return await java_tool.execute(
                action="list_chains",
                library=params.get("library"),
            )
        elif tool_name == "java_deser_detect":
            return await java_tool.execute(
                action="detect",
                value=params.get("value"),
            )
        elif tool_name == "php_deser_generate":
            return await php_tool.execute(
                action="generate",
                chain=params.get("chain"),
                payload_type=params.get("payload_type", "RCE"),
                command=params.get("command"),
                output_format=params.get("output_format", "base64"),
            )
        elif tool_name == "php_deser_list_chains":
            return await php_tool.execute(
                action="list_chains",
                framework=params.get("framework"),
            )
        elif tool_name == "php_deser_detect":
            return await php_tool.execute(
                action="detect",
                value=params.get("value"),
            )
        elif tool_name == "dotnet_deser_generate":
            return await dotnet_tool.execute(
                action="generate",
                formatter=params.get("formatter"),
                gadget=params.get("gadget"),
                command=params.get("command"),
                machine_key=params.get("machine_key"),
                validation_key=params.get("validation_key"),
                output_format=params.get("output_format", "base64"),
            )
        elif tool_name == "dotnet_deser_list_gadgets":
            return await dotnet_tool.execute(
                action="list_gadgets",
                formatter=params.get("formatter"),
            )
        elif tool_name == "dotnet_deser_detect":
            if params.get("detect_viewstate") is True:
                return await dotnet_tool.execute(
                    action="detect_viewstate",
                    value=params.get("value"),
                )
            return await dotnet_tool.execute(
                action="detect",
                value=params.get("value"),
            )
        elif tool_name == "deser_probe_url":
            return await detect_tool.execute(
                action="probe_url",
                url=params.get("url"),
                timeout=params.get("timeout", 10),
            )
        elif tool_name == "deser_analyse_request":
            return await detect_tool.execute(
                action="analyse_request",
                params=params.get("params"),
                headers=params.get("headers"),
                cookies=params.get("cookies"),
                post_body=params.get("post_body"),
            )
        elif tool_name == "deser_list_indicators":
            return await detect_tool.execute(action="list_indicators")
        else:
            raise ValueError(f"Unknown tool: {tool_name}")


def create_server() -> DeserializationMCPServer:
    """Factory function used by the MCP server runner."""
    return DeserializationMCPServer()
