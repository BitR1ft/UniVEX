"""

Provides:
  FindingManager      — centralized finding storage with full lifecycle management
  Deduplicator        — intelligent cross-tool deduplication via fingerprinting
  SeverityCalculator  — CVSS 3.1 base/temporal/environmental scorer
"""

from .finding_manager import (
    Finding,
    FindingManager,
    FindingStatus,
    FindingSeverity,
    FindingSource,
    EvidenceType,
    Evidence,
    TriageAction,
)
from .deduplicator import Deduplicator, DeduplicationResult, DuplicateGroup
from .severity_calculator import (
    SeverityCalculator,
    CVSSVector,
    CVSSMetric,
    SeverityRating,
    CVSSScore,
)

__all__ = [
    # finding_manager
    "Finding",
    "FindingManager",
    "FindingStatus",
    "FindingSeverity",
    "FindingSource",
    "EvidenceType",
    "Evidence",
    "TriageAction",
    # deduplicator
    "Deduplicator",
    "DeduplicationResult",
    "DuplicateGroup",
    # severity_calculator
    "SeverityCalculator",
    "CVSSVector",
    "CVSSMetric",
    "SeverityRating",
    "CVSSScore",
]
