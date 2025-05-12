"""

Generates professional HTML reports from scan findings using Jinja2 templates.
Supports three report templates:
  - Executive Summary  — high-level, business-focused
  - Technical Report   — full finding details, CVE refs, reproduction steps
  - Compliance Report  — OWASP Top 10 / PCI-DSS / NIST 800-53 mapping

Also provides FindingDeduplicator and FindingRanker helpers.
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

# Template directory relative to this file
_TEMPLATE_DIR = Path(__file__).parent / "templates"


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ReportFormat(str, Enum):
    HTML = "html"
    PDF = "pdf"


class ReportTemplate(str, Enum):
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_REPORT = "technical_report"
    COMPLIANCE_REPORT = "compliance_report"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Represents a single security finding."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    cvss_score: float = 0.0
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    nist_controls: List[str] = field(default_factory=list)
    pci_dss_requirements: List[str] = field(default_factory=list)
    reproduction_steps: List[str] = field(default_factory=list)
    evidence: Optional[str] = None
    remediation: str = ""
    affected_component: str = ""
    likelihood: str = "medium"  # low / medium / high
    business_impact: str = ""
    discovered_at: Optional[datetime] = None

    @property
    def severity_order(self) -> int:
        """Numeric rank for sorting (lower = more severe)."""
        _order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return _order.get(self.severity, 5)

    @property
    def fingerprint(self) -> str:
        """Deterministic hash for deduplication."""
        raw = f"{self.title}|{self.affected_component}|{self.cve_id or ''}".lower()
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class ScanResult:
    """Aggregated results from a single scan run."""
    target: str = ""
    scan_type: str = ""
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    title: str = "Security Assessment Report"
    template: ReportTemplate = ReportTemplate.TECHNICAL_REPORT
    format: ReportFormat = ReportFormat.HTML
    include_charts: bool = True
    include_toc: bool = True
    custom_sections: List[str] = field(default_factory=list)
    logo_base64: Optional[str] = None
    watermark: Optional[str] = None
    confidentiality: str = "CONFIDENTIAL"


@dataclass
class ReportMetadata:
    """Metadata for a generated report."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    project_name: str = "UniVex Assessment"
    author: str = "Security Team"
    generated_at: datetime = field(default_factory=datetime.utcnow)
    version: str = "1.0"
    client_name: Optional[str] = None
    classification: str = "CONFIDENTIAL"


# ---------------------------------------------------------------------------
# Helpers: deduplication and ranking
# ---------------------------------------------------------------------------

class FindingDeduplicator:
    """
    Removes duplicate findings from a list.

    Two findings are considered duplicates when they share the same
    title + affected_component + CVE (case-insensitive).
    """

    def deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """Return a new list with duplicates removed (first occurrence kept)."""
        seen: set = set()
        unique: List[Finding] = []
        for f in findings:
            fp = f.fingerprint
            if fp not in seen:
                seen.add(fp)
                unique.append(f)
        logger.debug(
            "Deduplication: %d → %d findings", len(findings), len(unique)
        )
        return unique


class FindingRanker:
    """
    Ranks findings by priority.

    Primary sort: severity (CRITICAL first).
    Secondary sort: CVSS score (descending).
    Tertiary sort: title (ascending) for deterministic output.
    """

    def rank(self, findings: List[Finding]) -> List[Finding]:
        """Return findings sorted by priority (most critical first)."""
        return sorted(
            findings,
            key=lambda f: (f.severity_order, -f.cvss_score, f.title.lower()),
        )


# ---------------------------------------------------------------------------
# OWASP / PCI-DSS / NIST compliance mappings
# ---------------------------------------------------------------------------

_OWASP_TOP10_2021: Dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

_PCI_DSS_REQUIREMENTS: Dict[str, str] = {
    "1": "Install and Maintain Network Security Controls",
    "2": "Apply Secure Configurations",
    "3": "Protect Stored Account Data",
    "4": "Protect Cardholder Data with Strong Cryptography",
    "5": "Protect All Systems Against Malware",
    "6": "Develop and Maintain Secure Systems",
    "7": "Restrict Access by Business Need to Know",
    "8": "Identify Users and Authenticate Access",
    "9": "Restrict Physical Access",
    "10": "Log and Monitor All Access",
    "11": "Test Security of Systems Regularly",
    "12": "Support Information Security with Organizational Policies",
}

_NIST_800_53_FAMILIES: Dict[str, str] = {
    "AC": "Access Control",
    "AU": "Audit and Accountability",
    "CM": "Configuration Management",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
}


# ---------------------------------------------------------------------------
# Report Engine
# ---------------------------------------------------------------------------

class ReportEngine:
    """
    Renders professional security reports from scan results.

    Usage::

        engine = ReportEngine()
        html = engine.generate(
            scan_results=[scan],
            config=ReportConfig(template=ReportTemplate.TECHNICAL_REPORT),
            metadata=ReportMetadata(project_name="Acme Corp Assessment"),
        )
    """

    def __init__(self, template_dir: Optional[Path] = None) -> None:
        self._template_dir = template_dir or _TEMPLATE_DIR
        self._env = Environment(
            loader=FileSystemLoader(str(self._template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._deduplicator = FindingDeduplicator()
        self._ranker = FindingRanker()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def generate(
        self,
        scan_results: List[ScanResult],
        config: ReportConfig,
        metadata: ReportMetadata,
        chart_images: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Generate an HTML report string.

        Args:
            scan_results: List of scan results to include.
            config: Report configuration (template, format, options).
            metadata: Report metadata (author, project, etc.).
            chart_images: Optional dict of base64-encoded chart images.

        Returns:
            Rendered HTML string.
        """
        # Collect and process all findings
        all_findings = self._collect_findings(scan_results)
        deduped = self._deduplicator.deduplicate(all_findings)
        ranked = self._ranker.rank(deduped)

        context = self._build_context(
            scan_results=scan_results,
            findings=ranked,
            config=config,
            metadata=metadata,
            chart_images=chart_images or {},
        )

        template_map = {
            ReportTemplate.EXECUTIVE_SUMMARY: "executive_summary.html",
            ReportTemplate.TECHNICAL_REPORT: "technical_report.html",
            ReportTemplate.COMPLIANCE_REPORT: "compliance_report.html",
        }
        template_name = template_map[config.template]
        try:
            template = self._env.get_template(template_name)
            return template.render(**context)
        except Exception as exc:
            logger.error("Template rendering failed: %s", exc)
            raise RuntimeError(f"Report generation failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _collect_findings(self, scan_results: List[ScanResult]) -> List[Finding]:
        findings: List[Finding] = []
        for result in scan_results:
            findings.extend(result.findings)
        return findings

    def _build_context(
        self,
        scan_results: List[ScanResult],
        findings: List[Finding],
        config: ReportConfig,
        metadata: ReportMetadata,
        chart_images: Dict[str, str],
    ) -> Dict[str, Any]:
        severity_counts = self._count_by_severity(findings)
        risk_score = self._calculate_risk_score(findings)

        return {
            # Core
            "config": config,
            "metadata": metadata,
            "scan_results": scan_results,
            "findings": findings,
            # Aggregates
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "risk_score": risk_score,
            "risk_level": self._risk_level(risk_score),
            # Compliance mappings
            "owasp_coverage": self._owasp_coverage(findings),
            "owasp_top10": _OWASP_TOP10_2021,
            "pci_dss_requirements": _PCI_DSS_REQUIREMENTS,
            "nist_families": _NIST_800_53_FAMILIES,
            "pci_coverage": self._pci_coverage(findings),
            "nist_coverage": self._nist_coverage(findings),
            # Charts
            "chart_images": chart_images,
            # Helpers
            "now": datetime.utcnow(),
            "Severity": Severity,
        }

    @staticmethod
    def _count_by_severity(findings: List[Finding]) -> Dict[str, int]:
        counts: Dict[str, int] = {s.value: 0 for s in Severity}
        for f in findings:
            counts[f.severity.value] += 1
        return counts

    @staticmethod
    def _calculate_risk_score(findings: List[Finding]) -> float:
        """Weighted risk score 0-10."""
        weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 4.0,
            Severity.LOW: 1.5,
            Severity.INFO: 0.5,
        }
        if not findings:
            return 0.0
        total = sum(weights.get(f.severity, 0) for f in findings)
        # Normalize: cap at 10 once we hit ~20 critical findings
        return min(total / max(len(findings), 1), 10.0)

    @staticmethod
    def _risk_level(score: float) -> str:
        if score >= 7.0:
            return "Critical"
        if score >= 4.0:
            return "High"
        if score >= 2.0:
            return "Medium"
        if score > 0:
            return "Low"
        return "None"

    @staticmethod
    def _owasp_coverage(findings: List[Finding]) -> Dict[str, List[Finding]]:
        coverage: Dict[str, List[Finding]] = {}
        for f in findings:
            cat = f.owasp_category
            if cat:
                coverage.setdefault(cat, []).append(f)
        return coverage

    @staticmethod
    def _pci_coverage(findings: List[Finding]) -> Dict[str, List[Finding]]:
        coverage: Dict[str, List[Finding]] = {}
        for f in findings:
            for req in f.pci_dss_requirements:
                coverage.setdefault(req, []).append(f)
        return coverage

    @staticmethod
    def _nist_coverage(findings: List[Finding]) -> Dict[str, List[Finding]]:
        coverage: Dict[str, List[Finding]] = {}
        for f in findings:
            for ctrl in f.nist_controls:
                family = ctrl.split("-")[0] if "-" in ctrl else ctrl
                coverage.setdefault(family, []).append(f)
        return coverage
