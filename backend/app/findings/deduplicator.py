"""

Intelligent deduplication of findings across multiple tools and scans.

Algorithm:
  1. Exact-fingerprint match  — same (title, component, cwe) SHA-256 prefix
  2. Fuzzy title similarity   — Jaccard token similarity > 0.75 (same component)
  3. CVE match                — identical CVE IDs regardless of other fields

Returns DuplicateGroup objects for each cluster, designating the highest
confidence / earliest finding as the canonical entry and the rest as
duplicates.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Set

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class DuplicateGroup:
    """A group of findings that are deemed duplicates of each other."""
    canonical_id: str
    duplicate_ids: List[str]
    match_reason: str        # "fingerprint" | "fuzzy_title" | "cve"
    similarity_score: float  # 0.0–1.0

    @property
    def all_ids(self) -> List[str]:
        return [self.canonical_id] + self.duplicate_ids

    def to_dict(self) -> dict:
        return {
            "canonical_id": self.canonical_id,
            "duplicate_ids": self.duplicate_ids,
            "match_reason": self.match_reason,
            "similarity_score": round(self.similarity_score, 3),
            "total_count": len(self.all_ids),
        }


@dataclass
class DeduplicationResult:
    """Aggregate result returned by Deduplicator.run()."""
    groups: List[DuplicateGroup] = field(default_factory=list)
    total_input: int = 0
    unique_count: int = 0
    duplicate_count: int = 0
    dedup_ratio: float = 0.0

    def to_dict(self) -> dict:
        return {
            "groups": [g.to_dict() for g in self.groups],
            "total_input": self.total_input,
            "unique_count": self.unique_count,
            "duplicate_count": self.duplicate_count,
            "dedup_ratio": round(self.dedup_ratio, 3),
        }


# ---------------------------------------------------------------------------
# Deduplicator
# ---------------------------------------------------------------------------


class Deduplicator:
    """
    Three-pass deduplication engine.

    Pass 1 — exact fingerprint (O(n))
    Pass 2 — CVE match (O(n))
    Pass 3 — fuzzy title + component match (O(n²) within same component bucket)
    """

    def __init__(
        self,
        fuzzy_threshold: float = 0.75,
        enable_fuzzy: bool = True,
    ) -> None:
        self.fuzzy_threshold = fuzzy_threshold
        self.enable_fuzzy = enable_fuzzy

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self, findings: List) -> DeduplicationResult:
        """
        Accept a list of Finding objects (duck-typed: need .id, .fingerprint,
        .cve_id, .title, .affected_component) and return a DeduplicationResult.
        """
        if not findings:
            return DeduplicationResult(total_input=0, unique_count=0)

        groups: List[DuplicateGroup] = []
        clustered: Set[str] = set()

        # Pass 1: exact fingerprint
        fp_groups = self._fingerprint_pass(findings, clustered)
        groups.extend(fp_groups)

        # Pass 2: CVE match
        cve_groups = self._cve_pass(findings, clustered)
        groups.extend(cve_groups)

        # Pass 3: fuzzy title
        if self.enable_fuzzy:
            fuzzy_groups = self._fuzzy_pass(findings, clustered)
            groups.extend(fuzzy_groups)

        total = len(findings)
        dup_count = sum(len(g.duplicate_ids) for g in groups)
        unique = total - dup_count

        return DeduplicationResult(
            groups=groups,
            total_input=total,
            unique_count=unique,
            duplicate_count=dup_count,
            dedup_ratio=round(dup_count / total, 3) if total else 0.0,
        )

    def compute_similarity(self, title_a: str, title_b: str) -> float:
        """Jaccard token similarity between two titles (lowercase, tokenised)."""
        tokens_a = set(self._tokenise(title_a))
        tokens_b = set(self._tokenise(title_b))
        if not tokens_a or not tokens_b:
            return 0.0
        intersection = tokens_a & tokens_b
        union = tokens_a | tokens_b
        return len(intersection) / len(union)

    # ------------------------------------------------------------------
    # Internal passes
    # ------------------------------------------------------------------

    def _fingerprint_pass(
        self, findings: List, clustered: Set[str]
    ) -> List[DuplicateGroup]:
        """Group by exact fingerprint match."""
        buckets: Dict[str, List] = {}
        for f in findings:
            fp = getattr(f, "fingerprint", "") or ""
            if fp:
                buckets.setdefault(fp, []).append(f)

        groups = []
        for fp, members in buckets.items():
            if len(members) < 2:
                continue
            # Canonical = earliest created_at
            members_sorted = sorted(members, key=lambda x: getattr(x, "created_at", 0))
            canonical = members_sorted[0]
            dups = members_sorted[1:]
            dup_ids = [d.id for d in dups if d.id not in clustered]
            if not dup_ids:
                continue
            clustered.update(dup_ids)
            groups.append(DuplicateGroup(
                canonical_id=canonical.id,
                duplicate_ids=dup_ids,
                match_reason="fingerprint",
                similarity_score=1.0,
            ))
        return groups

    def _cve_pass(self, findings: List, clustered: Set[str]) -> List[DuplicateGroup]:
        """Group by identical CVE ID."""
        buckets: Dict[str, List] = {}
        for f in findings:
            cve = getattr(f, "cve_id", None) or ""
            if cve and cve.upper().startswith("CVE-"):
                buckets.setdefault(cve.upper(), []).append(f)

        groups = []
        for cve, members in buckets.items():
            unclustered = [m for m in members if m.id not in clustered]
            if len(unclustered) < 2:
                continue
            members_sorted = sorted(unclustered, key=lambda x: getattr(x, "created_at", 0))
            canonical = members_sorted[0]
            dup_ids = [d.id for d in members_sorted[1:]]
            clustered.update(dup_ids)
            groups.append(DuplicateGroup(
                canonical_id=canonical.id,
                duplicate_ids=dup_ids,
                match_reason="cve",
                similarity_score=0.95,
            ))
        return groups

    def _fuzzy_pass(self, findings: List, clustered: Set[str]) -> List[DuplicateGroup]:
        """
        Bucket by affected_component then do O(n²) Jaccard title similarity
        within each bucket.
        """
        # Bucket by normalised component
        comp_buckets: Dict[str, List] = {}
        for f in findings:
            if f.id in clustered:
                continue
            comp = self._normalise_component(getattr(f, "affected_component", "") or "")
            comp_buckets.setdefault(comp, []).append(f)

        groups = []
        for comp, members in comp_buckets.items():
            if len(members) < 2:
                continue
            used: Set[str] = set()
            for i, a in enumerate(members):
                if a.id in clustered or a.id in used:
                    continue
                cluster_dups = []
                for b in members[i + 1:]:
                    if b.id in clustered or b.id in used:
                        continue
                    sim = self.compute_similarity(a.title, b.title)
                    if sim >= self.fuzzy_threshold:
                        cluster_dups.append((b, sim))
                if cluster_dups:
                    dup_ids = [d.id for d, _ in cluster_dups]
                    avg_sim = sum(s for _, s in cluster_dups) / len(cluster_dups)
                    used.update(dup_ids)
                    clustered.update(dup_ids)
                    groups.append(DuplicateGroup(
                        canonical_id=a.id,
                        duplicate_ids=dup_ids,
                        match_reason="fuzzy_title",
                        similarity_score=avg_sim,
                    ))
        return groups

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _tokenise(text: str) -> List[str]:
        """Lowercase, split on non-alphanumeric, remove short tokens."""
        return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) > 2]

    @staticmethod
    def _normalise_component(component: str) -> str:
        """Strip URL scheme/port, lowercase, strip trailing slash."""
        comp = re.sub(r"https?://", "", component.lower()).rstrip("/")
        comp = re.sub(r":\d+", "", comp)
        return comp.strip() or "unknown"
