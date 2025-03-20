"""
Packet Analysis MCP Server — Network Packet Capture & Analysis Engine (Port 8013)

MCP JSON-RPC 2.0 server that wraps tcpdump and tshark to expose packet capture,
protocol analysis, and credential sniffing through the standard MCP call interface.

Tools exposed:
  packet_capture_start      — Start tcpdump capture on an interface
  packet_capture_stop       — Stop a running capture session
  packet_capture_status     — Get status of a capture session
  packet_capture_list       — List all capture sessions
  packet_capture_delete     — Delete a capture session and its pcap file
  pcap_analyze              — Analyze a .pcap file (protocols, top talkers, credentials)
  pcap_protocols            — Extract protocol distribution from pcap
  pcap_top_talkers          — Extract top talker IPs from pcap
  pcap_credentials          — Extract plaintext credentials from pcap
  credential_sniff_live     — Live credential sniffing on an interface
  protocol_analyze_http     — Deep HTTP protocol analysis
  protocol_analyze_dns      — Deep DNS protocol analysis
  protocol_analyze_smb      — Deep SMB protocol analysis
  protocol_analyze_kerberos — Deep Kerberos protocol analysis

Environment variables:
  PACKET_MCP_PORT    — port for this MCP server (default: 8013)
  PACKET_MCP_API_KEY — bearer token for this MCP server (optional)
  PACKET_CMD_TIMEOUT — timeout for external commands in seconds (default: 30)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List

from app.mcp.base_server import MCPServer, MCPTool

logger = logging.getLogger(__name__)

_PACKET_MCP_PORT = int(os.getenv("PACKET_MCP_PORT", "8013"))
_PACKET_MCP_API_KEY = os.getenv("PACKET_MCP_API_KEY", "")


class PacketMCPServer(MCPServer):
    """
    MCP Server wrapping tcpdump and tshark for packet capture and analysis.

    Agents call these tools to capture live traffic, analyze pcap files,
    extract protocol details, and identify plaintext credentials in network
    traffic during internal penetration tests.
    """

    PORT = _PACKET_MCP_PORT

    def __init__(self) -> None:
        super().__init__(
            name="Packet",
            description=(
                "Network packet capture and analysis engine — "
                "tcpdump capture, tshark pcap analysis, "
                "protocol deep-dive (HTTP/DNS/SMB/Kerberos), and credential sniffing"
            ),
            port=self.PORT,
            api_key=_PACKET_MCP_API_KEY or None,
        )

    # ------------------------------------------------------------------
    # Tool declarations
    # ------------------------------------------------------------------

    def get_tools(self) -> List[MCPTool]:
        return [
            # --- Capture management ---
            MCPTool(
                name="packet_capture_start",
                description=(
                    "Start a tcpdump packet capture on a specified network interface. "
                    "Returns a capture_id for subsequent control operations."
                ),
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "interface": {
                            "type": "string",
                            "description": "Network interface (e.g. eth0, lo, any)",
                        },
                        "bpf_filter": {
                            "type": "string",
                            "description": "BPF filter expression (e.g. 'port 80 and host 10.0.0.1')",
                            "default": "",
                        },
                        "duration": {
                            "type": "integer",
                            "description": "Capture duration in seconds (0 = unlimited)",
                            "default": 60,
                        },
                        "packet_count": {
                            "type": "integer",
                            "description": "Max packets to capture (0 = unlimited)",
                            "default": 0,
                        },
                        "snap_len": {
                            "type": "integer",
                            "description": "Snapshot length in bytes",
                            "default": 65535,
                        },
                    },
                    "required": ["interface"],
                },
            ),
            MCPTool(
                name="packet_capture_stop",
                description="Stop a running tcpdump capture session by capture_id.",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "capture_id": {
                            "type": "string",
                            "description": "Capture session ID returned by packet_capture_start",
                        },
                    },
                    "required": ["capture_id"],
                },
            ),
            MCPTool(
                name="packet_capture_status",
                description="Get the status of a capture session (running/stopped/error).",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "capture_id": {
                            "type": "string",
                            "description": "Capture session ID",
                        },
                    },
                    "required": ["capture_id"],
                },
            ),
            MCPTool(
                name="packet_capture_list",
                description="List all packet capture sessions (active and completed).",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {},
                },
            ),
            MCPTool(
                name="packet_capture_delete",
                description="Delete a capture session and its .pcap file.",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "capture_id": {
                            "type": "string",
                            "description": "Capture session ID to delete",
                        },
                    },
                    "required": ["capture_id"],
                },
            ),
            # --- Pcap analysis ---
            MCPTool(
                name="pcap_analyze",
                description=(
                    "Full analysis of a .pcap file: protocol distribution, top talkers, "
                    "connection map, and plaintext credential extraction."
                ),
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "pcap_path": {
                            "type": "string",
                            "description": "Absolute path to the .pcap or .pcapng file",
                        },
                        "analysis_type": {
                            "type": "string",
                            "enum": ["summary", "protocols", "top_talkers", "connections", "credentials", "full"],
                            "description": "Type of analysis to perform",
                            "default": "full",
                        },
                        "top_n": {
                            "type": "integer",
                            "description": "Number of top talkers / connections to return",
                            "default": 10,
                        },
                        "display_filter": {
                            "type": "string",
                            "description": "Wireshark display filter (e.g. 'http', 'ftp')",
                            "default": "",
                        },
                    },
                    "required": ["pcap_path"],
                },
            ),
            MCPTool(
                name="pcap_protocols",
                description="Extract protocol distribution statistics from a .pcap file.",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "pcap_path": {"type": "string", "description": "Path to .pcap file"},
                        "display_filter": {"type": "string", "description": "Optional display filter"},
                    },
                    "required": ["pcap_path"],
                },
            ),
            MCPTool(
                name="pcap_top_talkers",
                description="Extract top talker IP addresses by packet/byte volume from a .pcap file.",
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "pcap_path": {"type": "string", "description": "Path to .pcap file"},
                        "top_n": {"type": "integer", "description": "Number of top talkers to return", "default": 10},
                    },
                    "required": ["pcap_path"],
                },
            ),
            MCPTool(
                name="pcap_credentials",
                description=(
                    "Extract plaintext credentials from a .pcap file. "
                    "Detects HTTP Basic auth, FTP, SMTP, POP3, IMAP, and NTLM."
                ),
                phase="exploit",
                parameters={
                    "type": "object",
                    "properties": {
                        "pcap_path": {"type": "string", "description": "Path to .pcap file"},
                    },
                    "required": ["pcap_path"],
                },
            ),
            # --- Live sniffing ---
            MCPTool(
                name="credential_sniff_live",
                description=(
                    "Perform real-time credential sniffing on a live network interface. "
                    "Extracts credentials from HTTP, FTP, SMTP, POP3, IMAP, Telnet, and NTLM."
                ),
                phase="exploit",
                parameters={
                    "type": "object",
                    "properties": {
                        "interface": {
                            "type": "string",
                            "description": "Network interface to sniff",
                        },
                        "duration": {
                            "type": "integer",
                            "description": "Sniffing duration in seconds",
                            "default": 30,
                        },
                        "protocols": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Protocols: http, ftp, smtp, pop3, imap, telnet, ntlm",
                        },
                    },
                    "required": ["interface"],
                },
            ),
            # --- Protocol analysis ---
            MCPTool(
                name="protocol_analyze_http",
                description=(
                    "Deep HTTP analysis: extract requests/responses, detect insecure cookies, "
                    "sensitive data in URLs, and other HTTP-layer vulnerabilities."
                ),
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "pcap_path": {"type": "string", "description": "Path to .pcap file"},
                        "max_records": {"type": "integer", "description": "Max HTTP records", "default": 50},
                        "vuln_check": {"type": "boolean", "description": "Run vuln checks", "default": True},
                    },
                    "required": ["pcap_path"],
                },
            ),
            MCPTool(
                name="protocol_analyze_dns",
                description=(
                    "Deep DNS analysis: extract queries/responses, identify suspicious domains "
                    "and DNS tunneling indicators."
                ),
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "pcap_path": {"type": "string", "description": "Path to .pcap file"},
                        "max_records": {"type": "integer", "description": "Max DNS records", "default": 50},
                        "vuln_check": {"type": "boolean", "description": "Run vuln checks", "default": True},
                    },
                    "required": ["pcap_path"],
                },
            ),
            MCPTool(
                name="protocol_analyze_smb",
                description=(
                    "Deep SMB analysis: extract dialect negotiations, identify SMBv1 (EternalBlue), "
                    "SMB signing disabled, and relay attack opportunities."
                ),
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "pcap_path": {"type": "string", "description": "Path to .pcap file"},
                        "max_records": {"type": "integer", "description": "Max SMB records", "default": 50},
                        "vuln_check": {"type": "boolean", "description": "Run vuln checks", "default": True},
                    },
                    "required": ["pcap_path"],
                },
            ),
            MCPTool(
                name="protocol_analyze_kerberos",
                description=(
                    "Deep Kerberos analysis: extract AS-REQ/TGS-REQ/AP-REQ exchanges, "
                    "identify weak encryption types, and AS-REP/Kerberoast opportunities."
                ),
                phase="recon",
                parameters={
                    "type": "object",
                    "properties": {
                        "pcap_path": {"type": "string", "description": "Path to .pcap file"},
                        "max_records": {"type": "integer", "description": "Max Kerberos records", "default": 50},
                        "vuln_check": {"type": "boolean", "description": "Run vuln checks", "default": True},
                    },
                    "required": ["pcap_path"],
                },
            ),
        ]

    # ------------------------------------------------------------------
    # Tool execution
    # ------------------------------------------------------------------

    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Any:
        from app.agent.tools.packet_tools import (
            PacketCaptureTool,
            PcapAnalyzeTool,
            CredentialSnifferTool,
            ProtocolAnalyzerTool,
        )

        capture_tool = PacketCaptureTool()
        analyze_tool = PcapAnalyzeTool()
        sniffer_tool = CredentialSnifferTool()
        proto_tool = ProtocolAnalyzerTool()

        # --- Capture management ---
        if tool_name == "packet_capture_start":
            return await capture_tool.execute(
                action="start",
                interface=params.get("interface", "eth0"),
                bpf_filter=params.get("bpf_filter", ""),
                duration=params.get("duration", 60),
                packet_count=params.get("packet_count", 0),
                snap_len=params.get("snap_len", 65535),
            )
        elif tool_name == "packet_capture_stop":
            return await capture_tool.execute(
                action="stop",
                capture_id=params.get("capture_id"),
            )
        elif tool_name == "packet_capture_status":
            return await capture_tool.execute(
                action="status",
                capture_id=params.get("capture_id"),
            )
        elif tool_name == "packet_capture_list":
            return await capture_tool.execute(action="list")
        elif tool_name == "packet_capture_delete":
            return await capture_tool.execute(
                action="delete",
                capture_id=params.get("capture_id"),
            )

        # --- Pcap analysis ---
        elif tool_name == "pcap_analyze":
            return await analyze_tool.execute(
                pcap_path=params.get("pcap_path", ""),
                analysis_type=params.get("analysis_type", "full"),
                top_n=params.get("top_n", 10),
                display_filter=params.get("display_filter", ""),
            )
        elif tool_name == "pcap_protocols":
            return await analyze_tool.execute(
                pcap_path=params.get("pcap_path", ""),
                analysis_type="protocols",
                display_filter=params.get("display_filter", ""),
            )
        elif tool_name == "pcap_top_talkers":
            return await analyze_tool.execute(
                pcap_path=params.get("pcap_path", ""),
                analysis_type="top_talkers",
                top_n=params.get("top_n", 10),
            )
        elif tool_name == "pcap_credentials":
            return await analyze_tool.execute(
                pcap_path=params.get("pcap_path", ""),
                analysis_type="credentials",
            )

        # --- Live sniffing ---
        elif tool_name == "credential_sniff_live":
            return await sniffer_tool.execute(
                action="sniff_live",
                interface=params.get("interface", "eth0"),
                duration=params.get("duration", 30),
                protocols=params.get("protocols", ["http", "ftp", "smtp", "pop3", "imap", "telnet", "ntlm"]),
            )

        # --- Protocol analysis ---
        elif tool_name == "protocol_analyze_http":
            return await proto_tool.execute(
                pcap_path=params.get("pcap_path", ""),
                protocol="http",
                vuln_check=params.get("vuln_check", True),
                max_records=params.get("max_records", 50),
            )
        elif tool_name == "protocol_analyze_dns":
            return await proto_tool.execute(
                pcap_path=params.get("pcap_path", ""),
                protocol="dns",
                vuln_check=params.get("vuln_check", True),
                max_records=params.get("max_records", 50),
            )
        elif tool_name == "protocol_analyze_smb":
            return await proto_tool.execute(
                pcap_path=params.get("pcap_path", ""),
                protocol="smb",
                vuln_check=params.get("vuln_check", True),
                max_records=params.get("max_records", 50),
            )
        elif tool_name == "protocol_analyze_kerberos":
            return await proto_tool.execute(
                pcap_path=params.get("pcap_path", ""),
                protocol="kerberos",
                vuln_check=params.get("vuln_check", True),
                max_records=params.get("max_records", 50),
            )
        else:
            return {"error": f"Unknown tool: {tool_name}"}
