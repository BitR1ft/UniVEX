"""
AutoChain Schemas

Defines the data models used by the AutoChain orchestrator:

  ScanPlan        — describes what will be done (target, phases, tools)
  ExploitCandidate — a ranked exploit option derived from recon output
  ExploitPlan     — ordered list of ExploitCandidates with fallback logic
  ChainStep       — a single completed step in the chain execution log
  ChainResult     — the final (or current) result of an AutoChain run
  ChainStatus     — enum of possible chain run states
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ChainStatus(str, Enum):
    """Lifecycle states for an AutoChain run."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    STOPPED = "stopped"


class ChainPhase(str, Enum):
    """High-level phases the AutoChain pipeline moves through."""

    RECON = "recon"
    VULN_DISCOVERY = "vuln_discovery"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"


# ---------------------------------------------------------------------------
# Core data models
# ---------------------------------------------------------------------------


class ScanPlan(BaseModel):
    """
    Describes the complete automated scan plan for a single target.

    Created at the start of an AutoChain run and updated as each phase
    produces results.
    """

    plan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: str = Field(..., description="IP address, hostname, or URL of the target")
    project_id: Optional[str] = Field(None, description="Associated project ID")
    phases: List[ChainPhase] = Field(
        default_factory=lambda: list(ChainPhase),
        description="Ordered phases to execute",
    )

    # Recon outputs (populated during Phase 1)
    open_ports: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Open ports discovered: [{port, protocol, service, version}]",
    )
    http_services: List[str] = Field(
        default_factory=list,
        description="HTTP/HTTPS base URLs discovered",
    )
    detected_technologies: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Technologies detected via Wappalyzer/httpx",
    )

    # Vuln-discovery outputs (populated during Phase 2)
    vulnerabilities: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Raw vulnerability findings from Nuclei / NVD",
    )
    exploit_candidates: List["ExploitCandidate"] = Field(
        default_factory=list,
        description="Ranked list of exploit candidates",
    )

    # Runtime metadata
    created_at: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )
    auto_approve_risk_level: str = Field(
        "none",
        description=(
            "Maximum risk level auto-approved without human confirmation. "
            "Values: none | low | medium | high | critical"
        ),
    )


class ExploitCandidate(BaseModel):
    """
    A single exploit option ranked by confidence for use against a target service.

    Scoring:
      base_score   — CVSS score (0–10) from NVD / Nuclei
      msf_score    — +2 if a Metasploit module exists for the CVE / service
      final_score  — base_score + msf_score (capped at 10)
    """

    cve_id: Optional[str] = Field(None, description="CVE identifier if known")
    service: str = Field(..., description="Target service name (e.g., 'vsftpd')")
    port: int = Field(..., description="Target port number")
    module_path: Optional[str] = Field(
        None, description="Metasploit module path, if available"
    )
    payload_hint: Optional[str] = Field(
        None, description="Suggested payload (e.g., 'cmd/unix/interact')"
    )
    base_score: float = Field(0.0, ge=0.0, le=10.0, description="CVSS base score")
    msf_available: bool = Field(
        False, description="Whether a Metasploit module is available"
    )
    final_score: float = Field(
        0.0, ge=0.0, le=10.0, description="Composite exploit priority score"
    )
    source: str = Field("nuclei", description="Where the candidate came from")
    risk_level: str = Field("high", description="Risk level: low / medium / high / critical")
    description: str = Field("", description="Human-readable description of the exploit")


class ExploitPlan(BaseModel):
    """
    Ordered list of exploit candidates with fallback support.

    The orchestrator attempts ``candidates[0]`` first; if it fails or the
    session is not opened, it falls back to ``candidates[1]``, etc.
    """

    candidates: List[ExploitCandidate] = Field(default_factory=list)
    current_index: int = Field(0, description="Index of the candidate currently being tried")

    @property
    def current(self) -> Optional[ExploitCandidate]:
        """Return the active candidate, or None if exhausted."""
        if self.current_index < len(self.candidates):
            return self.candidates[self.current_index]
        return None

    def advance(self) -> bool:
        """Move to the next candidate. Returns False when all are exhausted."""
        self.current_index += 1
        return self.current is not None


class ChainStep(BaseModel):
    """
    A single completed step in the AutoChain execution log.

    Steps are appended to ``ChainResult.steps`` as the pipeline progresses
    and streamed in real time via the SSE endpoint.
    """

    step_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    phase: ChainPhase
    name: str = Field(..., description="Short step label")
    description: str = Field("", description="What this step did")
    status: str = Field("pending", description="pending | running | success | failed | skipped")
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    output: str = Field("", description="Raw text output from the step")
    error: Optional[str] = None

    def start(self) -> None:
        self.status = "running"
        self.started_at = datetime.utcnow().isoformat()

    def succeed(self, output: str = "") -> None:
        self.status = "success"
        self.output = output
        self.finished_at = datetime.utcnow().isoformat()

    def fail(self, error: str) -> None:
        self.status = "failed"
        self.error = error
        self.finished_at = datetime.utcnow().isoformat()


class ChainResult(BaseModel):
    """
    The running and final result of an AutoChain execution.

    A ``ChainResult`` is created when the chain starts and updated in place
    as each step completes. It is persisted to the in-memory store and
    exposed via ``GET /api/autochain/{chain_id}``.
    """

    chain_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    plan_id: str = Field(..., description="ID of the ScanPlan being executed")
    target: str = Field(..., description="Target being attacked")
    status: ChainStatus = Field(ChainStatus.PENDING)
    current_phase: Optional[ChainPhase] = None
    steps: List[ChainStep] = Field(default_factory=list)

    # Session information (populated once exploitation succeeds)
    session_id: Optional[int] = Field(
        None, description="Metasploit session ID opened during exploitation"
    )
    session_type: Optional[str] = Field(
        None, description="Session type: meterpreter | shell"
    )
    os_info: Optional[str] = Field(None, description="OS information from sysinfo")

    # Flags captured during post-exploitation
    flags: List[Dict[str, str]] = Field(
        default_factory=list,
        description="[{path, content}] — CTF-style flags captured",
    )

    # Summary metrics
    total_vulns_found: int = 0
    total_exploits_attempted: int = 0
    exploitation_success: bool = False

    started_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    finished_at: Optional[str] = None
    error: Optional[str] = None

    def add_step(self, step: ChainStep) -> None:
        self.steps.append(step)

    def finish(self, status: ChainStatus, error: Optional[str] = None) -> None:
        self.status = status
        self.finished_at = datetime.utcnow().isoformat()
        if error:
            self.error = error
