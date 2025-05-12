"""

Centralized finding storage with:
  - Full CRUD lifecycle (open → confirmed → resolved / false-positive)
  - Evidence attachment (screenshots, request/response pairs, tool output)
  - Triage workflow: assign, annotate, severity override
  - Query / filter interface for the REST API layer
  - Campaign and project association
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class FindingStatus(str, Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    WONT_FIX = "wont_fix"
    DUPLICATE = "duplicate"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def numeric(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]


class FindingSource(str, Enum):
    NUCLEI = "nuclei"
    NMAP = "nmap"
    FFUF = "ffuf"
    SQLMAP = "sqlmap"
    AUTOCHAIN = "autochain"
    MANUAL = "manual"
    AGENT = "agent"
    IMPORT = "import"


class EvidenceType(str, Enum):
    SCREENSHOT = "screenshot"
    REQUEST_RESPONSE = "request_response"
    TOOL_OUTPUT = "tool_output"
    LOG_SNIPPET = "log_snippet"
    CODE_SNIPPET = "code_snippet"
    NETWORK_CAPTURE = "network_capture"
    DESCRIPTION = "description"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class Evidence:
    """Attached evidence for a finding."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: EvidenceType = EvidenceType.DESCRIPTION
    title: str = ""
    content: str = ""          # Base64 for binary, plaintext otherwise
    mime_type: str = "text/plain"
    tool_name: Optional[str] = None
    captured_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "title": self.title,
            "content": self.content,
            "mime_type": self.mime_type,
            "tool_name": self.tool_name,
            "captured_at": self.captured_at.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class TriageAction:
    """Audit log entry for a triage event."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str = ""
    action: str = ""           # status_change / severity_override / assign / annotate
    from_value: str = ""
    to_value: str = ""
    actor: str = "system"
    note: str = ""
    performed_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "action": self.action,
            "from_value": self.from_value,
            "to_value": self.to_value,
            "actor": self.actor,
            "note": self.note,
            "performed_at": self.performed_at.isoformat(),
        }


@dataclass
class Finding:
    """
    A security finding with full triage metadata.

    Fingerprint is computed from (title, affected_component, cwe_id) so that
    identical findings from different tools can be deduplicated.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    # ---- Core ----
    title: str = ""
    description: str = ""
    severity: FindingSeverity = FindingSeverity.INFO
    status: FindingStatus = FindingStatus.OPEN
    source: FindingSource = FindingSource.MANUAL
    # ---- Classification ----
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    cvss_score: float = 0.0
    cvss_vector: Optional[str] = None
    # ---- Scope ----
    affected_component: str = ""
    affected_url: Optional[str] = None
    affected_parameter: Optional[str] = None
    affected_method: str = "GET"
    # ---- Triage ----
    assigned_to: Optional[str] = None
    triage_notes: str = ""
    severity_override: Optional[FindingSeverity] = None
    false_positive_reason: Optional[str] = None
    # ---- Relations ----
    project_id: Optional[str] = None
    campaign_id: Optional[str] = None
    target_id: Optional[str] = None
    scan_id: Optional[str] = None
    # ---- Remediation ----
    remediation: str = ""
    remediation_effort: str = "medium"   # low / medium / high
    references: List[str] = field(default_factory=list)
    # ---- Meta ----
    tool_name: Optional[str] = None
    raw_output: Optional[str] = None
    fingerprint: str = ""
    tags: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    triage_history: List[TriageAction] = field(default_factory=list)
    duplicate_of: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = self._compute_fingerprint()

    # ------------------------------------------------------------------
    def _compute_fingerprint(self) -> str:
        """SHA-256 fingerprint based on stable identifying attributes."""
        parts = "|".join([
            self.title.strip().lower(),
            self.affected_component.strip().lower(),
            (self.cwe_id or "").strip(),
            (self.cve_id or "").strip(),
        ])
        return hashlib.sha256(parts.encode()).hexdigest()[:16]

    # ------------------------------------------------------------------
    @property
    def effective_severity(self) -> FindingSeverity:
        """Return override severity when set, else natural severity."""
        return self.severity_override or self.severity

    @property
    def risk_score(self) -> float:
        """Composite risk score 0–10."""
        base = self.cvss_score if self.cvss_score > 0 else (
            {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
            .get(self.effective_severity.value, 0.0)
        )
        # Status modifier
        if self.status == FindingStatus.CONFIRMED:
            base = min(10.0, base * 1.1)
        return round(base, 2)

    # ------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "effective_severity": self.effective_severity.value,
            "status": self.status.value,
            "source": self.source.value,
            "cve_id": self.cve_id,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "affected_component": self.affected_component,
            "affected_url": self.affected_url,
            "affected_parameter": self.affected_parameter,
            "affected_method": self.affected_method,
            "assigned_to": self.assigned_to,
            "triage_notes": self.triage_notes,
            "severity_override": self.severity_override.value if self.severity_override else None,
            "false_positive_reason": self.false_positive_reason,
            "project_id": self.project_id,
            "campaign_id": self.campaign_id,
            "target_id": self.target_id,
            "scan_id": self.scan_id,
            "remediation": self.remediation,
            "remediation_effort": self.remediation_effort,
            "references": self.references,
            "tool_name": self.tool_name,
            "fingerprint": self.fingerprint,
            "tags": self.tags,
            "duplicate_of": self.duplicate_of,
            "risk_score": self.risk_score,
            "evidence_count": len(self.evidence),
            "evidence": [e.to_dict() for e in self.evidence],
            "triage_history": [t.to_dict() for t in self.triage_history],
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }


# ---------------------------------------------------------------------------
# FindingManager
# ---------------------------------------------------------------------------


class FindingManager:
    """
    In-memory finding store with full lifecycle and triage support.

    In production this would be backed by a PostgreSQL/Prisma model.
    All writes refresh ``updated_at`` and append a TriageAction entry.
    """

    def __init__(self) -> None:
        self._findings: Dict[str, Finding] = {}

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create(
        self,
        title: str,
        severity: FindingSeverity,
        description: str = "",
        source: FindingSource = FindingSource.MANUAL,
        **kwargs: Any,
    ) -> Finding:
        finding = Finding(
            title=title,
            severity=severity,
            description=description,
            source=source,
            **kwargs,
        )
        self._findings[finding.id] = finding
        logger.info("Created finding %s — %s [%s]", finding.id, title, severity.value)
        return finding

    def get(self, finding_id: str) -> Optional[Finding]:
        return self._findings.get(finding_id)

    def get_or_raise(self, finding_id: str) -> Finding:
        f = self.get(finding_id)
        if f is None:
            raise KeyError(f"Finding not found: {finding_id}")
        return f

    def list(
        self,
        status: Optional[FindingStatus] = None,
        severity: Optional[FindingSeverity] = None,
        source: Optional[FindingSource] = None,
        project_id: Optional[str] = None,
        campaign_id: Optional[str] = None,
        target_id: Optional[str] = None,
        owasp_category: Optional[str] = None,
        assigned_to: Optional[str] = None,
        search: Optional[str] = None,
        include_duplicates: bool = False,
        limit: int = 500,
        offset: int = 0,
    ) -> List[Finding]:
        results = list(self._findings.values())

        if not include_duplicates:
            results = [f for f in results if f.status != FindingStatus.DUPLICATE]
        if status:
            results = [f for f in results if f.status == status]
        if severity:
            results = [f for f in results if f.effective_severity == severity]
        if source:
            results = [f for f in results if f.source == source]
        if project_id:
            results = [f for f in results if f.project_id == project_id]
        if campaign_id:
            results = [f for f in results if f.campaign_id == campaign_id]
        if target_id:
            results = [f for f in results if f.target_id == target_id]
        if owasp_category:
            results = [f for f in results if f.owasp_category == owasp_category]
        if assigned_to:
            results = [f for f in results if f.assigned_to == assigned_to]
        if search:
            q = search.lower()
            results = [
                f for f in results
                if q in f.title.lower()
                or q in f.description.lower()
                or q in f.affected_component.lower()
            ]

        results.sort(key=lambda f: (-(f.effective_severity.numeric), f.created_at))
        return results[offset: offset + limit]

    def update(self, finding_id: str, actor: str = "system", **kwargs: Any) -> Finding:
        f = self.get_or_raise(finding_id)
        allowed = {
            "title", "description", "severity", "owasp_category", "cve_id", "cwe_id",
            "cvss_score", "cvss_vector", "affected_component", "affected_url",
            "affected_parameter", "affected_method", "triage_notes", "remediation",
            "remediation_effort", "references", "tags", "raw_output",
        }
        for key, value in kwargs.items():
            if key in allowed:
                setattr(f, key, value)
        f.updated_at = datetime.utcnow()
        return f

    def delete(self, finding_id: str) -> bool:
        return self._findings.pop(finding_id, None) is not None

    # ------------------------------------------------------------------
    # Triage workflow
    # ------------------------------------------------------------------

    def change_status(
        self,
        finding_id: str,
        new_status: FindingStatus,
        actor: str = "system",
        note: str = "",
    ) -> Finding:
        f = self.get_or_raise(finding_id)
        old = f.status.value
        f.status = new_status
        f.updated_at = datetime.utcnow()
        if new_status == FindingStatus.RESOLVED:
            f.resolved_at = datetime.utcnow()
        action = TriageAction(
            finding_id=finding_id,
            action="status_change",
            from_value=old,
            to_value=new_status.value,
            actor=actor,
            note=note,
        )
        f.triage_history.append(action)
        logger.info("Finding %s status %s → %s by %s", finding_id, old, new_status.value, actor)
        return f

    def override_severity(
        self,
        finding_id: str,
        new_severity: FindingSeverity,
        actor: str = "system",
        note: str = "",
    ) -> Finding:
        f = self.get_or_raise(finding_id)
        old = (f.severity_override or f.severity).value
        f.severity_override = new_severity
        f.updated_at = datetime.utcnow()
        action = TriageAction(
            finding_id=finding_id,
            action="severity_override",
            from_value=old,
            to_value=new_severity.value,
            actor=actor,
            note=note,
        )
        f.triage_history.append(action)
        return f

    def assign(
        self,
        finding_id: str,
        assignee: str,
        actor: str = "system",
        note: str = "",
    ) -> Finding:
        f = self.get_or_raise(finding_id)
        old = f.assigned_to or "unassigned"
        f.assigned_to = assignee
        f.updated_at = datetime.utcnow()
        action = TriageAction(
            finding_id=finding_id,
            action="assign",
            from_value=old,
            to_value=assignee,
            actor=actor,
            note=note,
        )
        f.triage_history.append(action)
        return f

    def annotate(
        self,
        finding_id: str,
        note: str,
        actor: str = "system",
    ) -> Finding:
        f = self.get_or_raise(finding_id)
        f.triage_notes = f"{f.triage_notes}\n{note}".strip()
        f.updated_at = datetime.utcnow()
        action = TriageAction(
            finding_id=finding_id,
            action="annotate",
            from_value="",
            to_value=note[:200],
            actor=actor,
            note=note,
        )
        f.triage_history.append(action)
        return f

    def mark_false_positive(
        self,
        finding_id: str,
        reason: str,
        actor: str = "system",
    ) -> Finding:
        f = self.get_or_raise(finding_id)
        f.false_positive_reason = reason
        return self.change_status(finding_id, FindingStatus.FALSE_POSITIVE, actor, reason)

    def mark_duplicate(self, finding_id: str, original_id: str, actor: str = "system") -> Finding:
        f = self.get_or_raise(finding_id)
        f.duplicate_of = original_id
        return self.change_status(finding_id, FindingStatus.DUPLICATE, actor, f"Duplicate of {original_id}")

    # ------------------------------------------------------------------
    # Evidence management
    # ------------------------------------------------------------------

    def attach_evidence(
        self,
        finding_id: str,
        evidence_type: EvidenceType,
        title: str,
        content: str,
        mime_type: str = "text/plain",
        tool_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Evidence:
        f = self.get_or_raise(finding_id)
        ev = Evidence(
            type=evidence_type,
            title=title,
            content=content,
            mime_type=mime_type,
            tool_name=tool_name,
            metadata=metadata or {},
        )
        f.evidence.append(ev)
        f.updated_at = datetime.utcnow()
        logger.debug("Attached evidence %s to finding %s", ev.id, finding_id)
        return ev

    def remove_evidence(self, finding_id: str, evidence_id: str) -> bool:
        f = self.get_or_raise(finding_id)
        before = len(f.evidence)
        f.evidence = [e for e in f.evidence if e.id != evidence_id]
        return len(f.evidence) < before

    # ------------------------------------------------------------------
    # Bulk import (from campaign findings or tool output)
    # ------------------------------------------------------------------

    def bulk_import(self, findings: List[Dict[str, Any]]) -> List[Finding]:
        """Import findings from a list of dicts (tool output, JSON import, etc.)."""
        created = []
        for d in findings:
            try:
                sev = FindingSeverity(d.get("severity", "info").lower())
                src = FindingSource(d.get("source", "import").lower()) if d.get("source") else FindingSource.IMPORT
                f = self.create(
                    title=d.get("title", "Unnamed Finding"),
                    severity=sev,
                    description=d.get("description", ""),
                    source=src,
                    cve_id=d.get("cve_id"),
                    cwe_id=d.get("cwe_id"),
                    owasp_category=d.get("owasp_category"),
                    cvss_score=float(d.get("cvss_score", 0.0)),
                    affected_component=d.get("affected_component", ""),
                    affected_url=d.get("affected_url"),
                    remediation=d.get("remediation", ""),
                    project_id=d.get("project_id"),
                    campaign_id=d.get("campaign_id"),
                    target_id=d.get("target_id"),
                    tool_name=d.get("tool_name"),
                    tags=d.get("tags", []),
                )
                created.append(f)
            except Exception as exc:
                logger.warning("Skipping invalid finding dict: %s — %s", d, exc)
        return created

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def stats(self, campaign_id: Optional[str] = None) -> Dict[str, Any]:
        findings = self.list(campaign_id=campaign_id, limit=10_000, include_duplicates=True)
        by_status: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        by_source: Dict[str, int] = {}
        by_owasp: Dict[str, int] = {}
        for f in findings:
            by_status[f.status.value] = by_status.get(f.status.value, 0) + 1
            by_severity[f.effective_severity.value] = by_severity.get(f.effective_severity.value, 0) + 1
            by_source[f.source.value] = by_source.get(f.source.value, 0) + 1
            if f.owasp_category:
                by_owasp[f.owasp_category] = by_owasp.get(f.owasp_category, 0) + 1

        open_critical = sum(
            1 for f in findings
            if f.status == FindingStatus.OPEN and f.effective_severity == FindingSeverity.CRITICAL
        )
        return {
            "total": len(findings),
            "by_status": by_status,
            "by_severity": by_severity,
            "by_source": by_source,
            "by_owasp": by_owasp,
            "open_critical": open_critical,
            "false_positive_rate": round(
                by_status.get("false_positive", 0) / max(len(findings), 1), 3
            ),
        }
