"""

Aggregates findings across multiple targets in a campaign:
  - Cross-target deduplication (same CVE / fingerprint on multiple hosts)
  - Correlation groups (same vulnerability on N hosts)
  - Campaign-level risk scoring
  - OWASP Top 10 coverage mapping
  - Trend analysis helpers
"""
from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .campaign_engine import Campaign, CampaignFinding, FindingSeverity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

@dataclass
class CorrelationGroup:
    """A group of findings that represent the same vulnerability across targets."""
    id: str
    fingerprint: str
    title: str
    severity: FindingSeverity
    cvss_score: float
    cve_id: Optional[str]
    owasp_category: Optional[str]
    affected_hosts: List[str]  # list of host strings
    finding_ids: List[str]
    first_seen: datetime
    last_seen: datetime
    remediation: str = ""

    @property
    def host_count(self) -> int:
        return len(self.affected_hosts)


@dataclass
class AggregatedReport:
    """Aggregated campaign report with cross-target statistics."""
    campaign_id: str
    campaign_name: str
    total_targets: int
    scanned_targets: int
    total_findings: int
    unique_findings: int
    duplicate_count: int
    correlation_groups: List[CorrelationGroup]
    severity_breakdown: Dict[str, int]
    owasp_coverage: Dict[str, int]       # OWASP category → finding count
    risk_score: float
    risk_level: str
    highest_risk_target: Optional[str]
    most_common_severity: str
    generated_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def deduplication_ratio(self) -> float:
        if self.total_findings == 0:
            return 0.0
        return round((self.duplicate_count / self.total_findings) * 100, 1)


# ---------------------------------------------------------------------------
# CampaignAggregator
# ---------------------------------------------------------------------------

class CampaignAggregator:
    """
    Aggregates and correlates campaign findings across targets.

    Usage::

        agg = CampaignAggregator()
        report = agg.aggregate(campaign)
        groups = agg.correlate(campaign)
    """

    # OWASP Top 10 2021 categories
    OWASP_CATEGORIES = [
        "A01:2021 – Broken Access Control",
        "A02:2021 – Cryptographic Failures",
        "A03:2021 – Injection",
        "A04:2021 – Insecure Design",
        "A05:2021 – Security Misconfiguration",
        "A06:2021 – Vulnerable and Outdated Components",
        "A07:2021 – Identification and Authentication Failures",
        "A08:2021 – Software and Data Integrity Failures",
        "A09:2021 – Security Logging and Monitoring Failures",
        "A10:2021 – Server-Side Request Forgery",
    ]

    # Severity weights for risk calculation
    _SEVERITY_WEIGHTS: Dict[FindingSeverity, float] = {
        FindingSeverity.CRITICAL: 10.0,
        FindingSeverity.HIGH: 7.0,
        FindingSeverity.MEDIUM: 4.0,
        FindingSeverity.LOW: 2.0,
        FindingSeverity.INFO: 0.5,
    }

    def __init__(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Main aggregation
    # ------------------------------------------------------------------

    def aggregate(self, campaign: Campaign) -> AggregatedReport:
        """Produce a full AggregatedReport for a campaign."""
        all_findings = self._collect_all_findings(campaign)

        # Deduplicate
        unique, duplicates = self._deduplicate(all_findings)

        # Correlate
        groups = self._build_correlation_groups(campaign, all_findings)

        # Severity breakdown
        severity_breakdown = self._severity_breakdown(all_findings)

        # OWASP coverage
        owasp_coverage = self._owasp_coverage(all_findings)

        # Risk
        risk_score = self._campaign_risk_score(all_findings)
        risk_level = self._risk_level(risk_score)

        # Highest-risk target
        highest_risk_target = self._highest_risk_target(campaign)

        # Most common severity
        most_common = max(severity_breakdown, key=lambda k: severity_breakdown[k], default="info")

        scanned = sum(
            1 for t in campaign.targets
            if t.status.value in ("completed", "failed")
        )

        return AggregatedReport(
            campaign_id=campaign.id,
            campaign_name=campaign.name,
            total_targets=len(campaign.targets),
            scanned_targets=scanned,
            total_findings=len(all_findings),
            unique_findings=len(unique),
            duplicate_count=len(duplicates),
            correlation_groups=groups,
            severity_breakdown=severity_breakdown,
            owasp_coverage=owasp_coverage,
            risk_score=risk_score,
            risk_level=risk_level,
            highest_risk_target=highest_risk_target,
            most_common_severity=most_common,
        )

    def correlate(self, campaign: Campaign) -> List[CorrelationGroup]:
        """
        Identify findings that appear on multiple targets (cross-target correlation).
        Only returns groups with 2+ affected hosts.
        """
        all_findings = self._collect_all_findings(campaign)
        groups = self._build_correlation_groups(campaign, all_findings)
        return [g for g in groups if g.host_count >= 2]

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def _deduplicate(
        self,
        findings: List[Tuple[CampaignFinding, str]],
    ) -> Tuple[List[Tuple[CampaignFinding, str]], List[Tuple[CampaignFinding, str]]]:
        """
        Deduplicate findings by fingerprint.

        Returns (unique_findings, duplicate_findings).
        """
        seen: Set[str] = set()
        unique: List[Tuple[CampaignFinding, str]] = []
        duplicates: List[Tuple[CampaignFinding, str]] = []
        for finding, host in findings:
            fp = self._fingerprint(finding)
            if fp in seen:
                duplicates.append((finding, host))
            else:
                seen.add(fp)
                unique.append((finding, host))
        return unique, duplicates

    # ------------------------------------------------------------------
    # Correlation
    # ------------------------------------------------------------------

    def _build_correlation_groups(
        self,
        campaign: Campaign,
        all_findings: List[Tuple[CampaignFinding, str]],
    ) -> List[CorrelationGroup]:
        """Build correlation groups from all findings."""
        # Group by fingerprint
        by_fingerprint: Dict[str, List[Tuple[CampaignFinding, str]]] = defaultdict(list)
        for finding, host in all_findings:
            fp = self._fingerprint(finding)
            by_fingerprint[fp].append((finding, host))

        groups: List[CorrelationGroup] = []
        for fp, items in by_fingerprint.items():
            hosts = list(dict.fromkeys(host for _, host in items))  # preserve order, deduplicate
            exemplar = items[0][0]
            timestamps = [f.discovered_at for f, _ in items if f.discovered_at]
            groups.append(
                CorrelationGroup(
                    id=fp[:8],
                    fingerprint=fp,
                    title=exemplar.title,
                    severity=exemplar.severity,
                    cvss_score=exemplar.cvss_score,
                    cve_id=exemplar.cve_id,
                    owasp_category=exemplar.owasp_category,
                    affected_hosts=hosts,
                    finding_ids=[f.id for f, _ in items],
                    first_seen=min(timestamps) if timestamps else datetime.utcnow(),
                    last_seen=max(timestamps) if timestamps else datetime.utcnow(),
                    remediation=exemplar.remediation,
                )
            )

        # Sort: most widespread first, then by severity
        groups.sort(key=lambda g: (-g.host_count, g.severity.value))
        return groups

    # ------------------------------------------------------------------
    # Scoring & coverage
    # ------------------------------------------------------------------

    def _severity_breakdown(
        self, findings: List[Tuple[CampaignFinding, str]]
    ) -> Dict[str, int]:
        breakdown: Dict[str, int] = {s.value: 0 for s in FindingSeverity}
        for finding, _ in findings:
            breakdown[finding.severity.value] += 1
        return breakdown

    def _owasp_coverage(
        self, findings: List[Tuple[CampaignFinding, str]]
    ) -> Dict[str, int]:
        coverage: Dict[str, int] = {cat: 0 for cat in self.OWASP_CATEGORIES}
        for finding, _ in findings:
            if finding.owasp_category and finding.owasp_category in coverage:
                coverage[finding.owasp_category] += 1
        return coverage

    def _campaign_risk_score(
        self, findings: List[Tuple[CampaignFinding, str]]
    ) -> float:
        if not findings:
            return 0.0
        total = sum(
            self._SEVERITY_WEIGHTS.get(f.severity, 0) for f, _ in findings
        )
        return round(min(total / max(len(findings), 1), 10.0), 2)

    @staticmethod
    def _risk_level(score: float) -> str:
        if score >= 8.0:
            return "critical"
        if score >= 6.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score >= 2.0:
            return "low"
        return "informational"

    def _highest_risk_target(self, campaign: Campaign) -> Optional[str]:
        if not campaign.targets:
            return None
        return max(campaign.targets, key=lambda t: t.risk_score).host

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_all_findings(
        campaign: Campaign,
    ) -> List[Tuple[CampaignFinding, str]]:
        """Collect (finding, host) tuples from all targets."""
        result: List[Tuple[CampaignFinding, str]] = []
        for target in campaign.targets:
            for finding in target.findings:
                result.append((finding, target.host))
        return result

    @staticmethod
    def _fingerprint(finding: CampaignFinding) -> str:
        """Deterministic fingerprint for deduplication."""
        if finding.fingerprint:
            return finding.fingerprint
        raw = f"{finding.title}|{finding.cve_id or ''}|{finding.cwe_id or ''}".lower()
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    # ------------------------------------------------------------------
    # Trending / comparison helpers
    # ------------------------------------------------------------------

    def compare_campaigns(
        self, campaign_a: Campaign, campaign_b: Campaign
    ) -> Dict[str, Any]:
        """
        Compare two campaigns — useful for regression tracking.

        Returns a dict with delta stats (positive means A has more).
        """
        findings_a = self._collect_all_findings(campaign_a)
        findings_b = self._collect_all_findings(campaign_b)

        sev_a = self._severity_breakdown(findings_a)
        sev_b = self._severity_breakdown(findings_b)

        delta = {
            sev: sev_a.get(sev, 0) - sev_b.get(sev, 0)
            for sev in (s.value for s in FindingSeverity)
        }
        delta["total"] = len(findings_a) - len(findings_b)

        return {
            "campaign_a": campaign_a.name,
            "campaign_b": campaign_b.name,
            "delta_findings": delta,
            "risk_score_a": self._campaign_risk_score(findings_a),
            "risk_score_b": self._campaign_risk_score(findings_b),
            "risk_delta": round(
                self._campaign_risk_score(findings_a) - self._campaign_risk_score(findings_b), 2
            ),
        }

    def top_findings(
        self,
        campaign: Campaign,
        n: int = 10,
        severity: Optional[FindingSeverity] = None,
    ) -> List[CampaignFinding]:
        """Return the top N most severe findings in the campaign."""
        all_findings = [f for t in campaign.targets for f in t.findings]
        if severity:
            all_findings = [f for f in all_findings if f.severity == severity]
        all_findings.sort(key=lambda f: (f.severity_score, -f.cvss_score))
        return all_findings[:n]
