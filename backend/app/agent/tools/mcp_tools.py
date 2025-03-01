"""
MCP Tools - Wrappers for MCP server tools

These tools integrate MCP servers with the agent framework.
"""

from typing import Dict
from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.mcp.base_server import MCPClient
import logging

logger = logging.getLogger(__name__)


class NaabuTool(BaseTool):
    """Port scanning tool using Naabu MCP server"""
    
    def __init__(self, server_url: str = "http://kali-tools:8000"):
        """
        Initialize Naabu tool.
        
        Args:
            server_url: URL of Naabu MCP server
        """
        self.client = MCPClient(server_url)
        super().__init__()
    
    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="naabu_scan",
            description="Execute port scan on target using Naabu. Fast and efficient port scanner.",
            parameters={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP, CIDR, or hostname"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port range (e.g., '1-1000', '80,443', 'top-100')",
                        "default": "top-100"
                    }
                },
                "required": ["target"]
            }
        )
    
    async def execute(self, target: str, ports: str = "top-100", **kwargs) -> str:
        """Execute port scan"""
        try:
            result = await self.client.call_tool(
                "execute_naabu",
                {"target": target, "ports": ports}
            )
            
            if not result.get("success"):
                return f"Error: {result.get('error', 'Unknown error')}"
            
            open_ports = result.get("ports", [])
            if not open_ports:
                return f"No open ports found on {target}"
            
            output = f"Port scan results for {target}:\n"
            for port_info in open_ports:
                output += f"  - Port {port_info['port']}/tcp open\n"
            
            return output
            
        except Exception as e:
            logger.error(f"Naabu tool error: {e}", exc_info=True)
            return f"Error: {str(e)}"


class CurlTool(BaseTool):
    """HTTP request tool using Curl MCP server"""
    
    def __init__(self, server_url: str = "http://kali-tools:8001"):
        """
        Initialize Curl tool.
        
        Args:
            server_url: URL of Curl MCP server
        """
        self.client = MCPClient(server_url)
        super().__init__()
    
    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="http_request",
            description="Make HTTP requests to web servers. Supports all HTTP methods.",
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL"
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP method (GET, POST, etc.)",
                        "default": "GET"
                    },
                    "headers": {
                        "type": "object",
                        "description": "Custom headers",
                        "default": {}
                    }
                },
                "required": ["url"]
            }
        )
    
    async def execute(self, url: str, method: str = "GET", headers: Dict = None, **kwargs) -> str:
        """Execute HTTP request"""
        try:
            params = {"url": url, "method": method}
            if headers:
                params["headers"] = headers
            
            result = await self.client.call_tool("execute_curl", params)
            
            if not result.get("success"):
                return f"Error: {result.get('error', 'Unknown error')}"
            
            status_code = result.get("status_code", 0)
            headers = result.get("headers", {})
            body_length = result.get("body_length", 0)
            
            output = f"HTTP {method} {url}\n"
            output += f"Status: {status_code}\n"
            output += f"Content-Length: {body_length} bytes\n"
            output += f"Server: {headers.get('Server', 'Unknown')}\n"
            
            return output
            
        except Exception as e:
            logger.error(f"Curl tool error: {e}", exc_info=True)
            return f"Error: {str(e)}"


class NucleiTool(BaseTool):
    """Vulnerability scanning tool using Nuclei MCP server"""
    
    def __init__(self, server_url: str = "http://kali-tools:8002"):
        """
        Initialize Nuclei tool.
        
        Args:
            server_url: URL of Nuclei MCP server
        """
        self.client = MCPClient(server_url)
        super().__init__()
    
    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="nuclei_scan",
            description="Execute vulnerability scan using Nuclei. Fast and customizable vulnerability scanner.",
            parameters={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target URL or IP"
                    },
                    "templates": {
                        "type": "string",
                        "description": "Template tags (e.g., 'cve', 'xss', 'sqli')",
                        "default": ""
                    },
                    "severity": {
                        "type": "string",
                        "description": "Minimum severity (info, low, medium, high, critical)",
                        "default": "medium"
                    }
                },
                "required": ["target"]
            }
        )
    
    async def execute(self, target: str, templates: str = "", severity: str = "medium", **kwargs) -> str:
        """Execute vulnerability scan"""
        try:
            result = await self.client.call_tool(
                "execute_nuclei",
                {"target": target, "templates": templates, "severity": severity}
            )
            
            if not result.get("success"):
                return f"Error: {result.get('error', 'Unknown error')}"
            
            findings = result.get("findings", [])
            if not findings:
                return f"No vulnerabilities found on {target}"
            
            severity_breakdown = result.get("severity_breakdown", {})
            
            output = f"Vulnerability scan results for {target}:\n"
            output += f"Total findings: {len(findings)}\n"
            output += "Severity breakdown: "
            output += f"Critical: {severity_breakdown.get('critical', 0)}, "
            output += f"High: {severity_breakdown.get('high', 0)}, "
            output += f"Medium: {severity_breakdown.get('medium', 0)}\n\n"
            
            # Show top findings
            for finding in findings[:5]:
                output += f"  - [{finding['severity'].upper()}] {finding['template_name']}\n"
                output += f"    Template: {finding['template_id']}\n"
            
            if len(findings) > 5:
                output += f"\n... and {len(findings) - 5} more findings"
            
            return output
            
        except Exception as e:
            logger.error(f"Nuclei tool error: {e}", exc_info=True)
            return f"Error: {str(e)}"


class MetasploitTool(BaseTool):
    """Metasploit framework tool using Metasploit MCP server"""
    
    def __init__(self, server_url: str = "http://kali-tools:8003"):
        """
        Initialize Metasploit tool.
        
        Args:
            server_url: URL of Metasploit MCP server
        """
        self.client = MCPClient(server_url)
        super().__init__()
    
    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="metasploit_search",
            description="Search for Metasploit exploits and modules by keyword or CVE.",
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query (keyword or CVE-ID)"
                    },
                    "module_type": {
                        "type": "string",
                        "description": "Module type filter",
                        "default": "exploit"
                    }
                },
                "required": ["query"]
            }
        )
    
    async def execute(self, query: str, module_type: str = "exploit", **kwargs) -> str:
        """Search Metasploit modules"""
        try:
            result = await self.client.call_tool(
                "search_modules",
                {"query": query, "module_type": module_type}
            )
            
            if not result.get("success"):
                return f"Error: {result.get('error', 'Unknown error')}"
            
            modules = result.get("modules", [])
            if not modules:
                return f"No modules found for query: {query}"
            
            output = f"Metasploit modules for '{query}':\n"
            for module in modules:
                output += f"  - {module['path']}\n"
                if module.get('description'):
                    output += f"    {module['description']}\n"
            
            return output
            
        except Exception as e:
            logger.error(f"Metasploit tool error: {e}", exc_info=True)
            return f"Error: {str(e)}"
