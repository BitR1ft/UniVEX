"""
Nuclei MCP Server - Vulnerability Scanning

Provides vulnerability scanning capabilities via Nuclei.
Port: 8002
"""

import asyncio
import json
from typing import Dict, Any, List
import re

from ..base_server import MCPServer, MCPTool
import logging

logger = logging.getLogger(__name__)


class NucleiServer(MCPServer):
    """
    MCP Server for Nuclei vulnerability scanning tool.
    
    Provides:
    - execute_nuclei: Run vulnerability scans on targets
    """
    
    def __init__(self):
        super().__init__(
            name="Nuclei",
            description="Vulnerability scanning tool server using Nuclei",
            port=8002
        )
    
    def get_tools(self) -> List[MCPTool]:
        """Get list of available tools"""
        return [
            MCPTool(
                name="execute_nuclei",
                description="Execute vulnerability scan on target using Nuclei. Returns list of findings.",
                parameters={
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target URL or IP to scan"
                        },
                        "templates": {
                            "type": "string",
                            "description": "Template tags or IDs to use (e.g., 'cve', 'xss', 'sqli', 'owasp-top-10'). Default: all",
                            "default": ""
                        },
                        "severity": {
                            "type": "string",
                            "description": "Minimum severity level (info, low, medium, high, critical). Default: info",
                            "enum": ["info", "low", "medium", "high", "critical"],
                            "default": "info"
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Timeout in seconds per template. Default: 10",
                            "default": 10
                        },
                        "rate_limit": {
                            "type": "integer",
                            "description": "Maximum requests per second. Default: 150",
                            "default": 150
                        }
                    },
                    "required": ["target"]
                }
            )
        ]
    
    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool"""
        if tool_name == "execute_nuclei":
            return await self._execute_nuclei(params)
        else:
            raise ValueError(f"Unknown tool: {tool_name}")
    
    def _validate_target(self, target: str) -> bool:
        """
        Validate target URL or IP.
        
        Args:
            target: Target to validate
            
        Returns:
            True if valid
            
        Raises:
            ValueError if invalid
        """
        # Check if it's a URL
        url_pattern = r'^https?://.+'
        if re.match(url_pattern, target):
            return True
        
        # Check if it's an IP
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, target):
            return True
        
        # Check if it's a hostname
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if re.match(hostname_pattern, target):
            return True
        
        raise ValueError(f"Invalid target: {target}. Must be URL, IP, or hostname.")
    
    async def _execute_nuclei(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute Nuclei vulnerability scan.
        
        Args:
            params: Tool parameters
            
        Returns:
            Scan results
        """
        target = params.get("target")
        templates = params.get("templates", "")
        severity = params.get("severity", "info")
        timeout = params.get("timeout", 10)
        rate_limit = params.get("rate_limit", 150)
        
        # Validate target
        try:
            self._validate_target(target)
        except ValueError as e:
            return {
                "success": False,
                "error": str(e),
                "target": target
            }
        
        # Build nuclei command
        cmd = [
            "nuclei",
            "-u", target,
            "-json",
            "-silent",
            "-timeout", str(timeout),
            "-rate-limit", str(rate_limit),
            "-severity", severity
        ]
        
        # Add template specification if provided
        if templates:
            # Check if it's a tag or template ID
            if any(tag in templates for tag in ['cve', 'xss', 'sqli', 'lfi', 'rce', 'ssrf', 'owasp']):
                cmd.extend(["-tags", templates])
            else:
                cmd.extend(["-t", templates])
        
        logger.info(f"Executing nuclei command: {' '.join(cmd)}")
        
        try:
            # Execute nuclei
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Note: Nuclei returns non-zero when vulnerabilities are found
            # So we check stderr instead
            if stderr and b"error" in stderr.lower():
                error_msg = stderr.decode()
                logger.error(f"Nuclei scan failed: {error_msg}")
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
                    "findings": [],
                    "finding_count": 0,
                    "message": "No vulnerabilities found"
                }
            
            # Parse line-by-line JSON
            findings = []
            for line in output.strip().split('\n'):
                if line.strip():
                    try:
                        result = json.loads(line)
                        findings.append({
                            "template_id": result.get("template-id", "unknown"),
                            "template_name": result.get("info", {}).get("name", "Unknown"),
                            "severity": result.get("info", {}).get("severity", "unknown"),
                            "matched_at": result.get("matched-at", target),
                            "extracted_results": result.get("extracted-results", []),
                            "matcher_name": result.get("matcher-name", ""),
                            "type": result.get("type", ""),
                            "host": result.get("host", target),
                            "ip": result.get("ip", ""),
                            "timestamp": result.get("timestamp", "")
                        })
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse JSON line: {line}")
                        continue
            
            # Group findings by severity
            severity_counts = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
            
            for finding in findings:
                sev = finding.get("severity", "info").lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1
            
            return {
                "success": True,
                "target": target,
                "findings": findings,
                "finding_count": len(findings),
                "severity_breakdown": severity_counts,
                "scan_config": {
                    "templates": templates or "all",
                    "min_severity": severity,
                    "timeout": timeout,
                    "rate_limit": rate_limit
                }
            }
            
        except Exception as e:
            logger.error(f"Nuclei execution error: {e}", exc_info=True)
            return {
                "success": False,
                "error": f"Execution error: {str(e)}",
                "target": target
            }


if __name__ == "__main__":
    # Run server
    server = NucleiServer()
    server.run()
