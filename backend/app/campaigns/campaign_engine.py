"""

Central orchestrator for multi-target pentest campaigns.
Manages campaign lifecycle, coordinates target scanning, tracks status.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class CampaignStatus(str, Enum):
    DRAFT = "draft"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TargetStatus(str, Enum):
    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class CampaignFinding:
    """A finding discovered within a campaign."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str = ""
    title: str = ""
    description: str = ""
    severity: FindingSeverity = FindingSeverity.INFO
    cvss_score: float = 0.0
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    affected_component: str = ""
    remediation: str = ""
    evidence: Optional[str] = None
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    fingerprint: str = ""  # populated by aggregator for deduplication

    @property
    def severity_score(self) -> int:
        """Numeric rank for sorting (lower = more severe)."""
        return {
            FindingSeverity.CRITICAL: 0,
            FindingSeverity.HIGH: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 3,
            FindingSeverity.INFO: 4,
        }.get(self.severity, 5)


@dataclass
class CampaignTarget:
    """A single target within a campaign."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    campaign_id: str = ""
    host: str = ""
    port: Optional[int] = None
    protocol: str = "https"
    scope_notes: str = ""
    tags: List[str] = field(default_factory=list)
    status: TargetStatus = TargetStatus.PENDING
    findings: List[CampaignFinding] = field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def url(self) -> str:
        if self.port:
            return f"{self.protocol}://{self.host}:{self.port}"
        return f"{self.protocol}://{self.host}"

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.HIGH)

    @property
    def risk_score(self) -> float:
        """CVSS-weighted risk score for this target."""
        if not self.findings:
            return 0.0
        weights = {
            FindingSeverity.CRITICAL: 4.0,
            FindingSeverity.HIGH: 3.0,
            FindingSeverity.MEDIUM: 2.0,
            FindingSeverity.LOW: 1.0,
            FindingSeverity.INFO: 0.1,
        }
        total = sum(weights.get(f.severity, 0) for f in self.findings)
        return round(min(total / max(len(self.findings), 1), 10.0), 2)


@dataclass
class CampaignConfig:
    """Configuration parameters for a campaign."""
    max_concurrent_targets: int = 3
    scan_timeout_seconds: int = 3600
    retry_failed_targets: bool = True
    max_retries: int = 2
    enable_correlation: bool = True
    rate_limit_rps: float = 10.0  # requests per second per target
    tags: List[str] = field(default_factory=list)
    custom_wordlists: List[str] = field(default_factory=list)
    scan_profile: str = "standard"  # quick / standard / thorough / stealth


@dataclass
class Campaign:
    """A multi-target pentest campaign."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    status: CampaignStatus = CampaignStatus.DRAFT
    targets: List[CampaignTarget] = field(default_factory=list)
    config: CampaignConfig = field(default_factory=CampaignConfig)
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_by: str = "system"
    scheduled_at: Optional[datetime] = None
    # Aggregated stats (populated after campaign completion)
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0
    risk_score: float = 0.0
    risk_level: str = "informational"
    correlated_findings: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def target_count(self) -> int:
        return len(self.targets)

    @property
    def completed_target_count(self) -> int:
        return sum(1 for t in self.targets if t.status == TargetStatus.COMPLETED)

    @property
    def failed_target_count(self) -> int:
        return sum(1 for t in self.targets if t.status == TargetStatus.FAILED)

    @property
    def progress_percent(self) -> float:
        if not self.targets:
            return 0.0
        done = sum(
            1 for t in self.targets
            if t.status in (TargetStatus.COMPLETED, TargetStatus.FAILED, TargetStatus.SKIPPED)
        )
        return round((done / len(self.targets)) * 100, 1)


# ---------------------------------------------------------------------------
# CampaignEngine
# ---------------------------------------------------------------------------

class CampaignEngine:
    """
    Orchestrates multi-target pentest campaigns.

    Usage::

        engine = CampaignEngine()
        campaign = engine.create_campaign("My Campaign", description="...")
        engine.add_target(campaign.id, host="example.com")
        asyncio.run(engine.run_campaign(campaign.id))
    """

    def __init__(self) -> None:
        self._campaigns: Dict[str, Campaign] = {}
        self._callbacks: Dict[str, List[Callable]] = {}
        logger.info("CampaignEngine initialised")

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create_campaign(
        self,
        name: str,
        description: str = "",
        config: Optional[CampaignConfig] = None,
        created_by: str = "system",
    ) -> Campaign:
        """Create and store a new campaign."""
        campaign = Campaign(
            name=name,
            description=description,
            config=config or CampaignConfig(),
            created_by=created_by,
        )
        self._campaigns[campaign.id] = campaign
        logger.info("Campaign created: id=%s name=%r", campaign.id, name)
        return campaign

    def get_campaign(self, campaign_id: str) -> Optional[Campaign]:
        return self._campaigns.get(campaign_id)

    def list_campaigns(self, status: Optional[CampaignStatus] = None) -> List[Campaign]:
        campaigns = list(self._campaigns.values())
        if status:
            campaigns = [c for c in campaigns if c.status == status]
        return sorted(campaigns, key=lambda c: c.created_at, reverse=True)

    def delete_campaign(self, campaign_id: str) -> bool:
        if campaign_id in self._campaigns:
            del self._campaigns[campaign_id]
            logger.info("Campaign deleted: id=%s", campaign_id)
            return True
        return False

    def update_campaign(self, campaign_id: str, **kwargs: Any) -> Optional[Campaign]:
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return None
        for key, value in kwargs.items():
            if hasattr(campaign, key):
                setattr(campaign, key, value)
        return campaign

    # ------------------------------------------------------------------
    # Target management
    # ------------------------------------------------------------------

    def add_target(
        self,
        campaign_id: str,
        host: str,
        port: Optional[int] = None,
        protocol: str = "https",
        scope_notes: str = "",
        tags: Optional[List[str]] = None,
    ) -> Optional[CampaignTarget]:
        """Add a single target to a campaign."""
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return None
        target = CampaignTarget(
            campaign_id=campaign_id,
            host=host,
            port=port,
            protocol=protocol,
            scope_notes=scope_notes,
            tags=tags or [],
        )
        campaign.targets.append(target)
        logger.info("Target added: campaign=%s host=%s", campaign_id, host)
        return target

    def add_targets_bulk(self, campaign_id: str, targets: List[Dict[str, Any]]) -> int:
        """Bulk-add targets from a list of dicts. Returns the count added."""
        count = 0
        for t in targets:
            result = self.add_target(
                campaign_id=campaign_id,
                host=t.get("host", ""),
                port=t.get("port"),
                protocol=t.get("protocol", "https"),
                scope_notes=t.get("scope_notes", ""),
                tags=t.get("tags", []),
            )
            if result:
                count += 1
        return count

    def remove_target(self, campaign_id: str, target_id: str) -> bool:
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return False
        before = len(campaign.targets)
        campaign.targets = [t for t in campaign.targets if t.id != target_id]
        return len(campaign.targets) < before

    def get_target(self, campaign_id: str, target_id: str) -> Optional[CampaignTarget]:
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return None
        return next((t for t in campaign.targets if t.id == target_id), None)

    # ------------------------------------------------------------------
    # Campaign execution
    # ------------------------------------------------------------------

    async def run_campaign(
        self,
        campaign_id: str,
        scan_fn: Optional[Callable] = None,
    ) -> Campaign:
        """
        Execute a campaign, scanning all targets with configured concurrency.

        Args:
            campaign_id: ID of the campaign to run.
            scan_fn: Async callable ``async (target) -> List[CampaignFinding]``.
                     Defaults to a no-op stub if not provided.
        """
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign {campaign_id!r} not found")

        if campaign.status not in (CampaignStatus.DRAFT, CampaignStatus.SCHEDULED):
            raise RuntimeError(
                f"Campaign {campaign_id!r} cannot be started from status {campaign.status.value!r}"
            )

        campaign.status = CampaignStatus.RUNNING
        campaign.started_at = datetime.utcnow()
        logger.info(
            "Campaign started: id=%s targets=%d concurrency=%d",
            campaign_id, len(campaign.targets), campaign.config.max_concurrent_targets,
        )

        # Default scan function — used when no real scanner is wired in
        if scan_fn is None:
            async def _noop_scan(target: CampaignTarget) -> List[CampaignFinding]:
                await asyncio.sleep(0)  # yield control
                return []
            scan_fn = _noop_scan

        semaphore = asyncio.Semaphore(campaign.config.max_concurrent_targets)

        async def _scan_target(target: CampaignTarget) -> None:
            async with semaphore:
                target.status = TargetStatus.SCANNING
                target.started_at = datetime.utcnow()
                attempt = 0
                max_attempts = (campaign.config.max_retries + 1
                                if campaign.config.retry_failed_targets else 1)
                while attempt < max_attempts:
                    try:
                        findings = await asyncio.wait_for(
                            scan_fn(target),
                            timeout=campaign.config.scan_timeout_seconds,
                        )
                        target.findings = findings or []
                        target.status = TargetStatus.COMPLETED
                        target.completed_at = datetime.utcnow()
                        logger.info(
                            "Target scanned: %s findings=%d",
                            target.host, len(target.findings),
                        )
                        break
                    except asyncio.TimeoutError:
                        attempt += 1
                        target.error_message = "Scan timed out"
                        logger.warning("Target timed out: %s (attempt %d)", target.host, attempt)
                    except Exception as exc:  # noqa: BLE001
                        attempt += 1
                        target.error_message = str(exc)
                        logger.warning("Target error: %s — %s (attempt %d)", target.host, exc, attempt)
                else:
                    target.status = TargetStatus.FAILED
                    target.completed_at = datetime.utcnow()

        # Run all targets concurrently (limited by semaphore)
        tasks = [_scan_target(t) for t in campaign.targets]
        try:
            await asyncio.gather(*tasks)
            campaign.status = CampaignStatus.COMPLETED
        except Exception as exc:  # noqa: BLE001
            campaign.status = CampaignStatus.FAILED
            logger.error("Campaign failed: id=%s — %s", campaign_id, exc)
        finally:
            campaign.completed_at = datetime.utcnow()

        # Update aggregate stats
        self._update_stats(campaign)
        logger.info(
            "Campaign completed: id=%s status=%s findings=%d",
            campaign_id, campaign.status.value, campaign.total_findings,
        )
        return campaign

    def pause_campaign(self, campaign_id: str) -> bool:
        campaign = self._campaigns.get(campaign_id)
        if campaign and campaign.status == CampaignStatus.RUNNING:
            campaign.status = CampaignStatus.PAUSED
            return True
        return False

    def cancel_campaign(self, campaign_id: str) -> bool:
        campaign = self._campaigns.get(campaign_id)
        if campaign and campaign.status in (
            CampaignStatus.RUNNING, CampaignStatus.PAUSED, CampaignStatus.SCHEDULED
        ):
            campaign.status = CampaignStatus.CANCELLED
            campaign.completed_at = datetime.utcnow()
            return True
        return False

    # ------------------------------------------------------------------
    # Reporting helpers
    # ------------------------------------------------------------------

    def _update_stats(self, campaign: Campaign) -> None:
        """Recalculate aggregate finding stats for a campaign."""
        all_findings = [f for t in campaign.targets for f in t.findings]
        campaign.total_findings = len(all_findings)
        campaign.critical_findings = sum(1 for f in all_findings if f.severity == FindingSeverity.CRITICAL)
        campaign.high_findings = sum(1 for f in all_findings if f.severity == FindingSeverity.HIGH)
        campaign.medium_findings = sum(1 for f in all_findings if f.severity == FindingSeverity.MEDIUM)
        campaign.low_findings = sum(1 for f in all_findings if f.severity == FindingSeverity.LOW)
        campaign.info_findings = sum(1 for f in all_findings if f.severity == FindingSeverity.INFO)
        campaign.risk_score = self._calculate_campaign_risk(all_findings)
        campaign.risk_level = self._risk_level(campaign.risk_score)

    @staticmethod
    def _calculate_campaign_risk(findings: List[CampaignFinding]) -> float:
        """Weighted average risk score across all findings."""
        if not findings:
            return 0.0
        weights = {
            FindingSeverity.CRITICAL: 10.0,
            FindingSeverity.HIGH: 7.0,
            FindingSeverity.MEDIUM: 4.0,
            FindingSeverity.LOW: 2.0,
            FindingSeverity.INFO: 0.5,
        }
        total = sum(weights.get(f.severity, 0) for f in findings)
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

    def get_campaign_summary(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return None
        return {
            "id": campaign.id,
            "name": campaign.name,
            "description": campaign.description,
            "status": campaign.status.value,
            "target_count": campaign.target_count,
            "completed_targets": campaign.completed_target_count,
            "failed_targets": campaign.failed_target_count,
            "progress_percent": campaign.progress_percent,
            "total_findings": campaign.total_findings,
            "critical_findings": campaign.critical_findings,
            "high_findings": campaign.high_findings,
            "medium_findings": campaign.medium_findings,
            "low_findings": campaign.low_findings,
            "info_findings": campaign.info_findings,
            "risk_score": campaign.risk_score,
            "risk_level": campaign.risk_level,
            "created_at": campaign.created_at.isoformat(),
            "started_at": campaign.started_at.isoformat() if campaign.started_at else None,
            "completed_at": campaign.completed_at.isoformat() if campaign.completed_at else None,
            "created_by": campaign.created_by,
        }
