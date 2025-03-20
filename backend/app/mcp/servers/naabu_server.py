"""
Naabu MCP Server - Port Scanning

Provides port scanning capabilities via Naabu tool.
Port: 8000
"""

import asyncio
import json
from typing import Dict, Any, List
import ipaddress
import re

from ..base_server import MCPServer, MCPTool
import logging

logger = logging.getLogger(__name__)


class NaabuServer(MCPServer):
    """
    MCP Server for Naabu port scanning tool.
    
    Provides:
    - execute_naabu: Run port scans on targets
    """
    
    def __init__(self):
        super().__init__(
            name="Naabu",
            description="Port scanning tool server using Naabu",
            port=8000
        )
    
    def get_tools(self) -> List[MCPTool]:
        """Get list of available tools"""
        return [
            MCPTool(
                name="execute_naabu",
                description="Execute port scan on target using Naabu. Returns list of open ports.",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target IP address, CIDR, or hostname to scan"
                        },
                        "ports": {
                            "type": "string",
                            "description": "Port range to scan (e.g., '1-1000', '80,443,8080', 'top-100'). Default: top-100",
                            "default": "top-100"
                        },
                        "rate": {
                            "type": "integer",
                            "description": "Packets per second rate. Default: 1000",
                            "default": 1000
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Timeout in seconds. Default: 10",
                            "default": 10
                        }
                    },
                    "required": ["target"]
                }
            )
        ]
    
    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool"""
        if tool_name == "execute_naabu":
            return await self._execute_naabu(params)
        else:
            raise ValueError(f"Unknown tool: {tool_name}")
    
    def _validate_target(self, target: str) -> bool:
        """
        Validate target IP/hostname/CIDR.
        
        Args:
            target: Target to validate
            
        Returns:
            True if valid
            
        Raises:
            ValueError if invalid
        """
        # Try to parse as IP address
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass
        
        # Try to parse as CIDR
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            pass
        
        # Validate hostname (basic check)
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if re.match(hostname_pattern, target):
            return True
        
        raise ValueError(f"Invalid target: {target}. Must be IP, CIDR, or valid hostname.")
    
    def _validate_ports(self, ports: str) -> bool:
        """
        Validate port specification.
        
        Args:
            ports: Port specification
            
        Returns:
            True if valid
            
        Raises:
            ValueError if invalid
        """
        # Allow predefined ranges
        if ports in ['top-100', 'top-1000', 'full']:
            return True
        
        # Validate port ranges like "1-1000" or "80,443,8080"
        port_pattern = r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$'
        if not re.match(port_pattern, ports):
            raise ValueError(f"Invalid port specification: {ports}")
        
        # Check individual ports are in valid range
        for part in ports.split(','):
            if '-' in part:
                start, end = part.split('-')
                if not (1 <= int(start) <= 65535 and 1 <= int(end) <= 65535):
                    raise ValueError(f"Port numbers must be between 1 and 65535: {part}")
            else:
                if not (1 <= int(part) <= 65535):
                    raise ValueError(f"Port number must be between 1 and 65535: {part}")
        
        return True
    
    async def _execute_naabu(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute Naabu port scan.
        
        Args:
            params: Tool parameters
            
        Returns:
            Scan results
        """
        target = params.get("target")
        ports = params.get("ports", "top-100")
        rate = params.get("rate", 1000)
        timeout = params.get("timeout", 10)
        
        # Validate inputs
        try:
            self._validate_target(target)
            self._validate_ports(ports)
        except ValueError as e:
            return {
                "success": False,
                "error": str(e),
                "target": target
            }
        
        # Build naabu command
        cmd = [
            "naabu",
            "-host", target,
            "-json",
            "-silent",
            "-rate", str(rate),
            "-timeout", str(timeout)
        ]
        
        # Add port specification
        if ports == "top-100":
            cmd.extend(["-top-ports", "100"])
        elif ports == "top-1000":
            cmd.extend(["-top-ports", "1000"])
        elif ports == "full":
            cmd.extend(["-p", "1-65535"])
        else:
            cmd.extend(["-p", ports])
        
        logger.info(f"Executing naabu command: {' '.join(cmd)}")
        
        try:
            # Execute naabu
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.error(f"Naabu scan failed: {error_msg}")
                return {
                    "success": False,
                    "error": f"Scan failed: {error_msg}",
                    "target": target
                }
            
            # Parse JSON output
            output = stdout.decode()
            if not output.strip():
                return {
                    "success": True,
                    "target": target,
                    "ports": [],
                    "open_count": 0,
                    "message": "No open ports found"
                }
            
            # Parse line-by-line JSON
            open_ports = []
            for line in output.strip().split('\n'):
                if line.strip():
                    try:
                        result = json.loads(line)
                        open_ports.append({
                            "ip": result.get("ip", target),
                            "port": result.get("port"),
                            "timestamp": result.get("timestamp", "")
                        })
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse JSON line: {line}")
                        continue
            
            return {
                "success": True,
                "target": target,
                "ports": open_ports,
                "open_count": len(open_ports),
                "scan_config": {
                    "ports_scanned": ports,
                    "rate": rate,
                    "timeout": timeout
                }
            }
            
        except Exception as e:
            logger.error(f"Naabu execution error: {e}", exc_info=True)
            return {
                "success": False,
                "error": f"Execution error: {str(e)}",
                "target": target
            }


if __name__ == "__main__":
    # Run server
    server = NaabuServer()
    server.run()
