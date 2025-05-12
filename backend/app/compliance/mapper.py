"""

Maps pentest findings to compliance framework controls (OWASP Top 10,
PCI-DSS v4.0, NIST 800-53 Rev 5, CIS Benchmarks).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List

from .frameworks.owasp_top10 import OWASP_TOP10_CONTROLS, map_finding_to_owasp
from .frameworks.pci_dss import PCI_DSS_CONTROLS, map_finding_to_pci_dss
from .frameworks.nist_800_53 import NIST_CONTROLS, map_finding_to_nist
from .frameworks.cis_benchmarks import CIS_BENCHMARKS, map_finding_to_cis


SUPPORTED_FRAMEWORKS = {"owasp", "pci_dss", "nist", "cis"}


@dataclass
class Finding:
    """A pentest finding to be mapped to compliance controls."""
    id: str
    title: str
    description: str
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    category: str = ""
    source: str = ""
    tested: bool = True


@dataclass
class ControlMapping:
    """A single compliance control with its mapped findings."""
    framework: str
    control_id: str
    control_title: str
    severity_impact: str
    mapped_findings: List[str] = field(default_factory=list)


@dataclass
class GapAnalysis:
    """Coverage gap analysis for a compliance framework."""
    framework: str
    total_controls: int
    tested_controls: int
    untested_controls: int
    coverage_percentage: float
    critical_gaps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "framework": self.framework,
            "total_controls": self.total_controls,
            "tested_controls": self.tested_controls,
            "untested_controls": self.untested_controls,
            "coverage_percentage": self.coverage_percentage,
            "critical_gaps": self.critical_gaps,
        }


@dataclass
class ComplianceReport:
    """Full compliance report for a single framework."""
    framework: str
    generated_at: str
    findings: List[Finding]
    mappings: List[ControlMapping]
    gap_analysis: GapAnalysis
    risk_summary: Dict[str, int]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "framework": self.framework,
            "generated_at": self.generated_at,
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity,
                    "category": f.category,
                    "source": f.source,
                    "tested": f.tested,
                }
                for f in self.findings
            ],
            "mappings": [
                {
                    "framework": m.framework,
                    "control_id": m.control_id,
                    "control_title": m.control_title,
                    "severity_impact": m.severity_impact,
                    "mapped_findings": m.mapped_findings,
                }
                for m in self.mappings
            ],
            "gap_analysis": self.gap_analysis.to_dict(),
            "risk_summary": self.risk_summary,
        }


def _severity_impact(mapped_finding_severities: List[str]) -> str:
    """Derive the worst-case severity from mapped findings."""
    order = ["critical", "high", "medium", "low", "info"]
    for level in order:
        if level in mapped_finding_severities:
            return level
    return "info"


def _risk_summary(findings: List[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.severity.lower()
        if sev in counts:
            counts[sev] += 1
    return counts


class ComplianceMapper:
    """Maps pentest findings to compliance framework controls."""

    def map_findings(self, findings: List[Finding], framework: str) -> ComplianceReport:
        """Map findings to the specified framework and return a ComplianceReport."""
        fw = framework.lower()
        if fw not in SUPPORTED_FRAMEWORKS:
            raise ValueError(
                f"Unsupported framework '{framework}'. "
                f"Supported: {sorted(SUPPORTED_FRAMEWORKS)}"
            )

        dispatch = {
            "owasp": self._map_to_owasp,
            "pci_dss": self._map_to_pci_dss,
            "nist": self._map_to_nist,
            "cis": self._map_to_cis,
        }
        mappings = dispatch[fw](findings)
        gap = self._build_gap(fw, mappings)

        return ComplianceReport(
            framework=fw,
            generated_at=datetime.now(tz=timezone.utc).isoformat(),
            findings=findings,
            mappings=mappings,
            gap_analysis=gap,
            risk_summary=_risk_summary(findings),
        )

    def get_gap_analysis(self, findings: List[Finding], framework: str) -> GapAnalysis:
        """Return gap analysis for the specified framework."""
        report = self.map_findings(findings, framework)
        return report.gap_analysis

    def map_all_frameworks(self, findings: List[Finding]) -> Dict[str, ComplianceReport]:
        """Map findings to all supported frameworks."""
        return {fw: self.map_findings(findings, fw) for fw in sorted(SUPPORTED_FRAMEWORKS)}

    # ------------------------------------------------------------------
    # Internal per-framework mapping helpers
    # ------------------------------------------------------------------

    def _map_to_owasp(self, findings: List[Finding]) -> List[ControlMapping]:
        mappings: Dict[str, ControlMapping] = {}
        for control_id, control in OWASP_TOP10_CONTROLS.items():
            mappings[control_id] = ControlMapping(
                framework="owasp",
                control_id=control_id,
                control_title=control.title,
                severity_impact="info",
                mapped_findings=[],
            )

        for finding in findings:
            matched_ids = map_finding_to_owasp(finding.title, finding.description)
            for cid in matched_ids:
                if cid in mappings:
                    mappings[cid].mapped_findings.append(finding.id)

        for cid, mapping in mappings.items():
            if mapping.mapped_findings:
                severities = [
                    f.severity for f in findings if f.id in mapping.mapped_findings
                ]
                mapping.severity_impact = _severity_impact(severities)

        return list(mappings.values())

    def _map_to_pci_dss(self, findings: List[Finding]) -> List[ControlMapping]:
        mappings: Dict[str, ControlMapping] = {}
        for req_id, req in PCI_DSS_CONTROLS.items():
            mappings[req_id] = ControlMapping(
                framework="pci_dss",
                control_id=req_id,
                control_title=req.title,
                severity_impact="info",
                mapped_findings=[],
            )

        for finding in findings:
            matched_ids = map_finding_to_pci_dss(finding.title, finding.description)
            for rid in matched_ids:
                if rid in mappings:
                    mappings[rid].mapped_findings.append(finding.id)

        for rid, mapping in mappings.items():
            if mapping.mapped_findings:
                severities = [
                    f.severity for f in findings if f.id in mapping.mapped_findings
                ]
                mapping.severity_impact = _severity_impact(severities)

        return list(mappings.values())

    def _map_to_nist(self, findings: List[Finding]) -> List[ControlMapping]:
        mappings: Dict[str, ControlMapping] = {}
        for family_id, family in NIST_CONTROLS.items():
            mappings[family_id] = ControlMapping(
                framework="nist",
                control_id=family_id,
                control_title=family.title,
                severity_impact="info",
                mapped_findings=[],
            )

        for finding in findings:
            matched_ids = map_finding_to_nist(finding.title, finding.description)
            for fid in matched_ids:
                if fid in mappings:
                    mappings[fid].mapped_findings.append(finding.id)

        for fid, mapping in mappings.items():
            if mapping.mapped_findings:
                severities = [
                    f.severity for f in findings if f.id in mapping.mapped_findings
                ]
                mapping.severity_impact = _severity_impact(severities)

        return list(mappings.values())

    def _map_to_cis(self, findings: List[Finding]) -> List[ControlMapping]:
        all_section_ids: Dict[str, str] = {}
        for plat_key, benchmark in CIS_BENCHMARKS.items():
            for section in benchmark.sections:
                sid = f"{plat_key}/{section.section_id}"
                all_section_ids[sid] = f"{benchmark.platform.upper()} — {section.title}"

        mappings: Dict[str, ControlMapping] = {
            sid: ControlMapping(
                framework="cis",
                control_id=sid,
                control_title=title,
                severity_impact="info",
                mapped_findings=[],
            )
            for sid, title in all_section_ids.items()
        }

        for finding in findings:
            matched = map_finding_to_cis(finding.title, finding.description)
            for sid in matched:
                if sid in mappings:
                    mappings[sid].mapped_findings.append(finding.id)

        for sid, mapping in mappings.items():
            if mapping.mapped_findings:
                severities = [
                    f.severity for f in findings if f.id in mapping.mapped_findings
                ]
                mapping.severity_impact = _severity_impact(severities)

        return list(mappings.values())

    # ------------------------------------------------------------------
    # Gap analysis
    # ------------------------------------------------------------------

    def _build_gap(self, framework: str, mappings: List[ControlMapping]) -> GapAnalysis:
        total = len(mappings)
        tested = sum(1 for m in mappings if m.mapped_findings)
        untested = total - tested
        coverage = round((tested / total * 100) if total else 0.0, 2)

        # Critical gaps: controls with no mapped findings
        critical_gaps = [m.control_id for m in mappings if not m.mapped_findings]

        return GapAnalysis(
            framework=framework,
            total_controls=total,
            tested_controls=tested,
            untested_controls=untested,
            coverage_percentage=coverage,
            critical_gaps=critical_gaps,
        )
