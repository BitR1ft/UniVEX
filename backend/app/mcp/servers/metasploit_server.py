"""
Metasploit MCP Server - Exploitation Framework

Provides Metasploit console interaction capabilities.
Port: 8003
"""

import asyncio
from typing import Dict, Any, List
import re

from ..base_server import MCPServer, MCPTool
import logging

logger = logging.getLogger(__name__)


class MetasploitServer(MCPServer):
    """
    MCP Server for Metasploit Framework.
    
    Provides:
    - search_modules: Search for Metasploit modules
    - get_module_info: Get information about a module
    - execute_module: Execute a Metasploit module (with safety checks)
    - list_sessions: List active Metasploit sessions
    - session_command: Execute a command in an active session
    """
    
    def __init__(self):
        super().__init__(
            name="Metasploit",
            description="Metasploit Framework tool server",
            port=8003
        )
        self._console_process = None
    
    def get_tools(self) -> List[MCPTool]:
        """Get list of available tools"""
        return [
            MCPTool(
                name="search_modules",
                description="Search for Metasploit modules by keyword, CVE, or type.",
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query (keyword, CVE-ID, or module name)"
                        },
                        "module_type": {
                            "type": "string",
                            "description": "Filter by module type",
                            "enum": ["exploit", "auxiliary", "post", "payload", "encoder", "nop", "all"],
                            "default": "all"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum results to return. Default: 10",
                            "default": 10
                        }
                    },
                    "required": ["query"]
                }
            ),
            MCPTool(
                name="get_module_info",
                description="Get detailed information about a Metasploit module.",
                parameters={
                    "type": "object",
                    "properties": {
                        "module_path": {
                            "type": "string",
                            "description": "Full module path (e.g., 'exploit/windows/smb/ms17_010_eternalblue')"
                        }
                    },
                    "required": ["module_path"]
                }
            ),
            MCPTool(
                name="check_target",
                description="Check if a target is vulnerable to a specific exploit (uses check command, safe operation).",
                parameters={
                    "type": "object",
                    "properties": {
                        "module_path": {
                            "type": "string",
                            "description": "Exploit module path"
                        },
                        "rhosts": {
                            "type": "string",
                            "description": "Target host(s)"
                        },
                        "rport": {
                            "type": "integer",
                            "description": "Target port (optional)"
                        }
                    },
                    "required": ["module_path", "rhosts"]
                }
            ),
            MCPTool(
                name="execute_module",
                description="Execute a Metasploit module against a target.",
                parameters={
                    "type": "object",
                    "properties": {
                        "module_path": {
                            "type": "string",
                            "description": "Full module path (e.g., 'exploit/windows/smb/ms17_010_eternalblue')"
                        },
                        "rhosts": {
                            "type": "string",
                            "description": "Target host(s)"
                        },
                        "rport": {
                            "type": "integer",
                            "description": "Target port (optional)"
                        },
                        "payload": {
                            "type": "string",
                            "description": "Payload to use (e.g., 'generic/shell_reverse_tcp')"
                        },
                        "lhost": {
                            "type": "string",
                            "description": "Local host for reverse connections"
                        },
                        "lport": {
                            "type": "integer",
                            "description": "Local port for reverse connections",
                            "default": 4444
                        },
                        "options": {
                            "type": "object",
                            "description": "Additional module options as key-value pairs"
                        }
                    },
                    "required": ["module_path", "rhosts"]
                }
            ),
            MCPTool(
                name="list_sessions",
                description="List active Metasploit sessions.",
                parameters={
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            ),
            MCPTool(
                name="session_command",
                description="Execute a command in an active Metasploit session.",
                parameters={
                    "type": "object",
                    "properties": {
                        "session_id": {
                            "type": "integer",
                            "description": "Session ID to interact with"
                        },
                        "command": {
                            "type": "string",
                            "description": "Command to execute in the session"
                        }
                    },
                    "required": ["session_id", "command"]
                }
            )
        ]
    
    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool"""
        if tool_name == "search_modules":
            return await self._search_modules(params)
        elif tool_name == "get_module_info":
            return await self._get_module_info(params)
        elif tool_name == "check_target":
            return await self._check_target(params)
        elif tool_name == "execute_module":
            return await self._execute_module(params)
        elif tool_name == "list_sessions":
            return await self._list_sessions(params)
        elif tool_name == "session_command":
            return await self._session_command(params)
        else:
            raise ValueError(f"Unknown tool: {tool_name}")
    
    async def _search_modules(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Search for Metasploit modules.
        
        Args:
            params: Search parameters
            
        Returns:
            Search results
        """
        query = params.get("query")
        module_type = params.get("module_type", "all")
        limit = params.get("limit", 10)
        
        # Build msfconsole command
        search_cmd = f"search {query}"
        if module_type != "all":
            search_cmd += f" type:{module_type}"
        
        cmd = [
            "msfconsole",
            "-q",  # Quiet mode
            "-x", search_cmd + "; exit"
        ]
        
        logger.info(f"Executing msfconsole search: {search_cmd}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.error(f"Metasploit search failed: {error_msg}")
                return {
                    "success": False,
                    "error": f"Search failed: {error_msg}",
                    "query": query
                }
            
            # Parse output
            output = stdout.decode()
            
            # Extract module information from output
            modules = []
            lines = output.split('\n')
            
            in_results = False
            for line in lines:
                # Look for the results table
                if 'Matching Modules' in line or '============' in line:
                    in_results = True
                    continue
                
                if in_results and line.strip():
                    # Parse module line (format varies but typically: index name disclosure_date rank check description)
                    parts = line.split()
                    if len(parts) >= 2:
                        # First non-index part is usually the module path
                        for part in parts:
                            if '/' in part:
                                modules.append({
                                    "path": part,
                                    "description": " ".join(parts[parts.index(part)+1:]) if len(parts) > parts.index(part)+1 else ""
                                })
                                break
                
                if len(modules) >= limit:
                    break
            
            return {
                "success": True,
                "query": query,
                "module_type": module_type,
                "modules": modules[:limit],
                "result_count": len(modules)
            }
            
        except Exception as e:
            logger.error(f"Metasploit search error: {e}", exc_info=True)
            return {
                "success": False,
                "error": f"Execution error: {str(e)}",
                "query": query
            }
    
    async def _get_module_info(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get information about a specific module.
        
        Args:
            params: Module parameters
            
        Returns:
            Module information
        """
        module_path = params.get("module_path")
        
        # Build msfconsole command
        cmd = [
            "msfconsole",
            "-q",
            "-x", f"use {module_path}; info; exit"
        ]
        
        logger.info(f"Getting info for module: {module_path}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                return {
                    "success": False,
                    "error": f"Failed to get module info: {error_msg}",
                    "module": module_path
                }
            
            output = stdout.decode()
            
            # Parse module information
            info = {
                "module_path": module_path,
                "name": "",
                "description": "",
                "author": [],
                "platform": [],
                "references": [],
                "targets": [],
                "options": []
            }
            
            # Extract information from output
            lines = output.split('\n')
            current_section = None
            
            for line in lines:
                line = line.strip()
                
                if line.startswith("Name:"):
                    info["name"] = line.split("Name:", 1)[1].strip()
                elif line.startswith("Platform:"):
                    info["platform"] = [p.strip() for p in line.split("Platform:", 1)[1].strip().split(',')]
                elif "Author:" in line or "Authors:" in line:
                    current_section = "authors"
                elif "References:" in line:
                    current_section = "references"
                elif "Available targets:" in line:
                    current_section = "targets"
                elif current_section == "authors" and line:
                    info["author"].append(line)
                elif current_section == "references" and line:
                    info["references"].append(line)
            
            return {
                "success": True,
                "module": module_path,
                "info": info
            }
            
        except Exception as e:
            logger.error(f"Get module info error: {e}", exc_info=True)
            return {
                "success": False,
                "error": f"Execution error: {str(e)}",
                "module": module_path
            }
    
    async def _check_target(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check if target is vulnerable (safe check operation).
        
        Args:
            params: Check parameters
            
        Returns:
            Check results
        """
        module_path = params.get("module_path")
        rhosts = params.get("rhosts")
        rport = params.get("rport")
        
        # Build msfconsole command for safe check
        commands = [
            f"use {module_path}",
            f"set RHOSTS {rhosts}"
        ]
        
        if rport:
            commands.append(f"set RPORT {rport}")
        
        commands.extend(["check", "exit"])
        
        cmd = [
            "msfconsole",
            "-q",
            "-x", "; ".join(commands)
        ]
        
        logger.info(f"Checking target {rhosts} with module {module_path}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={"TERM": "dumb"}  # Prevent terminal escape codes
            )
            
            stdout, stderr = await process.communicate()
            
            output = stdout.decode()
            
            # Analyze check result
            vulnerable = False
            check_result = "unknown"
            
            if "appears to be vulnerable" in output.lower() or "vulnerable" in output.lower():
                vulnerable = True
                check_result = "vulnerable"
            elif "not vulnerable" in output.lower() or "not exploitable" in output.lower():
                check_result = "not_vulnerable"
            elif "check failed" in output.lower():
                check_result = "check_failed"
            
            return {
                "success": True,
                "module": module_path,
                "target": rhosts,
                "port": rport,
                "vulnerable": vulnerable,
                "check_result": check_result,
                "output": output[-500:]  # Last 500 chars of output
            }
            
        except Exception as e:
            logger.error(f"Check target error: {e}", exc_info=True)
            return {
                "success": False,
                "error": f"Execution error: {str(e)}",
                "module": module_path,
                "target": rhosts
            }
    
    @staticmethod
    def _validate_module_path(path: str) -> str:
        """Validate that a module path only contains safe characters."""
        if not re.match(r'^[a-zA-Z0-9_/\-]+$', path):
            raise ValueError(f"Invalid module path: {path}")
        return path

    @staticmethod
    def _validate_host(host: str) -> str:
        """Validate that a host value only contains safe characters."""
        if not re.match(r'^[a-zA-Z0-9.\-:/,]+$', host):
            raise ValueError(f"Invalid host value: {host}")
        return host

    async def _execute_module(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a Metasploit module against a target.
        
        Args:
            params: Module execution parameters
            
        Returns:
            Execution results with session info
        """
        module_path = self._validate_module_path(params.get("module_path", ""))
        rhosts = self._validate_host(params.get("rhosts", ""))
        rport = params.get("rport")
        payload = params.get("payload")
        lhost = params.get("lhost")
        lport = params.get("lport", 4444)
        options = params.get("options", {})
        
        # Build msfconsole commands
        commands = [
            f"use {module_path}",
            f"set RHOSTS {rhosts}"
        ]
        
        if rport:
            commands.append(f"set RPORT {int(rport)}")
        
        if payload:
            commands.append(f"set PAYLOAD {self._validate_module_path(payload)}")
        
        if lhost:
            commands.append(f"set LHOST {self._validate_host(lhost)}")
        
        if lport is not None:
            commands.append(f"set LPORT {int(lport)}")
        
        for key, value in options.items():
            safe_key = re.sub(r'[^a-zA-Z0-9_]', '', str(key))
            safe_value = re.sub(r'[^a-zA-Z0-9 _\-\./=:@,]', '', str(value))
            commands.append(f"set {safe_key} {safe_value}")
        
        commands.extend(["run", "exit"])
        
        cmd = [
            "msfconsole",
            "-q",
            "-x", "; ".join(commands)
        ]
        
        logger.info(f"Executing module {module_path} against {rhosts}")
        logger.info(f"Commands: {'; '.join(commands)}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={"TERM": "dumb"}
            )
            
            stdout, stderr = await process.communicate()
            
            output = stdout.decode()
            
            # Parse output for session creation indicators
            session_opened = False
            session_info = None
            
            session_match = re.search(r"session (\d+) opened", output, re.IGNORECASE)
            if not session_match:
                session_match = re.search(r"Meterpreter session (\d+)", output, re.IGNORECASE)
            
            if session_match:
                session_opened = True
                session_info = {
                    "session_id": int(session_match.group(1)),
                    "type": "meterpreter" if "meterpreter" in output.lower() else "shell"
                }
                logger.info(f"Session opened: {session_info}")
            
            logger.info(f"Module execution completed. Session opened: {session_opened}")
            
            return {
                "success": True,
                "module": module_path,
                "target": rhosts,
                "session_opened": session_opened,
                "session_info": session_info,
                "output": output[-500:]
            }
            
        except Exception as e:
            logger.error(f"Execute module error: {e}", exc_info=True)
            return {
                "success": False,
                "error": f"Execution error: {str(e)}",
                "module": module_path,
                "target": rhosts
            }
    
    async def _list_sessions(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        List active Metasploit sessions.
        
        Args:
            params: No parameters required
            
        Returns:
            List of active sessions
        """
        cmd = [
            "msfconsole",
            "-q",
            "-x", "sessions -l; exit"
        ]
        
        logger.info("Listing active Metasploit sessions")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={"TERM": "dumb"}
            )
            
            stdout, stderr = await process.communicate()
            
            output = stdout.decode()
            
            # Parse session list output
            sessions = []
            lines = output.split('\n')
            
            in_sessions = False
            for line in lines:
                if line.strip().startswith('---'):
                    in_sessions = True
                    continue
                
                if in_sessions and line.strip():
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].isdigit():
                        session = {
                            "id": int(parts[0]),
                            "type": parts[1] if len(parts) > 1 else "unknown",
                            "info": " ".join(parts[2:]) if len(parts) > 2 else ""
                        }
                        sessions.append(session)
            
            return {
                "success": True,
                "sessions": sessions,
                "session_count": len(sessions)
            }
            
        except Exception as e:
            logger.error(f"List sessions error: {e}", exc_info=True)
            return {
                "success": False,
                "error": f"Execution error: {str(e)}"
            }
    
    @staticmethod
    def _sanitize_session_command(command: str) -> str:
        """
        Sanitize a command to be run inside a Metasploit session.

        Strips shell metacharacters that could escape the msfconsole
        session context.  Only alphanumeric characters, basic
        punctuation and common filesystem characters are allowed.

        Args:
            command: Raw command string

        Returns:
            Sanitized command string
        """
        # Allow only safe characters for session commands
        return re.sub(r'[^a-zA-Z0-9 _\-\./=:@,]', '', command)

    async def _session_command(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a command in an active Metasploit session.
        
        Args:
            params: Session command parameters
            
        Returns:
            Command output
        """
        session_id = params.get("session_id")
        command = params.get("command")

        # Validate inputs
        session_id = int(session_id)
        safe_command = self._sanitize_session_command(command)
        
        cmd = [
            "msfconsole",
            "-q",
            "-x", f"sessions -i {session_id} -c '{safe_command}'; exit"
        ]
        
        logger.info(f"Executing command in session {session_id}: {safe_command}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={"TERM": "dumb"}
            )
            
            stdout, stderr = await process.communicate()
            
            output = stdout.decode()
            
            return {
                "success": True,
                "session_id": session_id,
                "command": command,
                "output": output
            }
            
        except Exception as e:
            logger.error(f"Session command error: {e}", exc_info=True)
            return {
                "success": False,
                "error": f"Execution error: {str(e)}",
                "session_id": session_id,
                "command": command
            }


if __name__ == "__main__":
    # Run server
    server = MetasploitServer()
    server.run()
