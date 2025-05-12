"""

Provides:
  CampaignEngine   — orchestrate multi-target pentest campaigns
  TargetManager    — import/validate targets (CSV, JSON, CIDR)
  CampaignScheduler — schedule scans with concurrency limits
  CampaignAggregator — aggregate & correlate findings across targets
"""
from .campaign_engine import CampaignEngine, Campaign, CampaignStatus, CampaignTarget, TargetStatus
from .target_manager import TargetManager
from .scheduler import CampaignScheduler
from .aggregator import CampaignAggregator

__all__ = [
    "CampaignEngine",
    "Campaign",
    "CampaignStatus",
    "CampaignTarget",
    "TargetStatus",
    "TargetManager",
    "CampaignScheduler",
    "CampaignAggregator",
]
