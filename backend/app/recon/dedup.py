"""
Deduplication Pipeline

Provides three complementary strategies for de-duplicating recon results
produced by different tools:

  1. **Hash-based deduplication** – exact URL/ID normalisation + SHA-256 hash
  2. **Fuzzy matching**           – Levenshtein distance for near-duplicate URLs
  3. **Confidence scoring**       – prefer higher-confidence items when merging

Supports ``Endpoint``, ``Technology``, and ``Finding`` types from the
canonical schema.
"""
from __future__ import annotations

import hashlib
import re
from typing import Dict, List, Sequence, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.recon.canonical_schemas import Endpoint, Finding, Technology


# ---------------------------------------------------------------------------
# URL normalisation helpers
# ---------------------------------------------------------------------------

def _normalise_url(url: str) -> str:
    """
    Normalise a URL for stable hashing / comparison:

    - Lowercase scheme + host
    - Remove default ports (80, 443)
    - Sort query parameters alphabetically
    - Strip trailing slashes from paths (except for "/")
    - Remove URL fragment
    """
    try:
        p = urlparse(url.strip())
        scheme = p.scheme.lower()
        host = p.hostname or ""
        port = p.port

        # Drop default ports
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = None

        netloc = host if port is None else f"{host}:{port}"
        path = re.sub(r"/+$", "", p.path) or "/"
        query = urlencode(sorted(parse_qs(p.query).items()))
        return urlunparse((scheme, netloc, path, "", query, ""))
    except Exception:
        return url.strip().lower()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Levenshtein distance (fast iterative)
# ---------------------------------------------------------------------------

def levenshtein(a: str, b: str) -> int:
    """Return the Levenshtein edit distance between *a* and *b*."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def similarity(a: str, b: str) -> float:
    """
    Return a normalised similarity score in [0, 1].

    1.0 means identical, 0.0 means completely different.
    """
    if not a and not b:
        return 1.0
    max_len = max(len(a), len(b))
    if max_len == 0:
        return 1.0
    return 1.0 - levenshtein(a, b) / max_len


# ---------------------------------------------------------------------------
# Endpoint deduplication
# ---------------------------------------------------------------------------

class EndpointDeduplicator:
    """
    Deduplicates a list of ``Endpoint`` objects using a two-pass approach:

    1. **Exact hash** – URLs that normalise to the same string are merged.
    2. **Fuzzy**      – Remaining URLs with a similarity ≥ ``fuzzy_threshold``
                        (default 0.85) are considered near-duplicates; the
                        higher-confidence item is kept.

    The ``confidence`` field of the surviving item is boosted by the number
    of duplicates it absorbed.
    """

    def __init__(self, fuzzy_threshold: float = 0.85) -> None:
        if not 0.0 <= fuzzy_threshold <= 1.0:
            raise ValueError("fuzzy_threshold must be in [0, 1]")
        self.fuzzy_threshold = fuzzy_threshold

    def deduplicate(self, endpoints: Sequence[Endpoint]) -> List[Endpoint]:
        """
        Return a deduplicated list.  Order is preserved (first occurrence wins
        unless a later item has higher confidence).
        """
        # --- Pass 1: exact hash ---
        seen: Dict[str, Endpoint] = {}
        for ep in endpoints:
            key = _sha256(_normalise_url(ep.url))
            if key not in seen:
                seen[key] = ep
            else:
                # Keep the higher-confidence item; boost confidence slightly
                existing = seen[key]
                if ep.confidence > existing.confidence:
                    seen[key] = ep
                seen[key].confidence = min(
                    1.0, seen[key].confidence + 0.05
                )

        unique = list(seen.values())

        # --- Pass 2: fuzzy matching (group by host to keep O(k²) per host) ---
        # Bucket items by host so we only compare within the same host.
        from collections import defaultdict

        by_host: dict = defaultdict(list)
        for ep in unique:
            host = urlparse(_normalise_url(ep.url)).netloc
            by_host[host].append(ep)

        result: List[Endpoint] = []
        for host_eps in by_host.values():
            deduped: List[Endpoint] = []
            for candidate in host_eps:
                norm_c = _normalise_url(candidate.url)
                merged = False
                for i, existing in enumerate(deduped):
                    if similarity(norm_c, _normalise_url(existing.url)) >= self.fuzzy_threshold:
                        if candidate.confidence > existing.confidence:
                            deduped[i] = candidate
                        deduped[i] = deduped[i].model_copy(
                            update={"confidence": min(1.0, deduped[i].confidence + 0.03)}
                        )
                        merged = True
                        break
                if not merged:
                    deduped.append(candidate)
            result.extend(deduped)

        return result


# ---------------------------------------------------------------------------
# Technology deduplication
# ---------------------------------------------------------------------------

class TechnologyDeduplicator:
    """
    Deduplicates ``Technology`` items by ``(name.lower(), version)`` key.

    If the same technology is detected with and without a version string,
    the versioned entry is preferred.
    """

    def deduplicate(self, technologies: Sequence[Technology]) -> List[Technology]:
        seen: Dict[str, Technology] = {}
        for tech in technologies:
            key = tech.name.lower()
            if key not in seen:
                seen[key] = tech
            else:
                existing = seen[key]
                # Prefer entry with version info or higher confidence
                if (
                    (tech.version and not existing.version)
                    or tech.confidence > existing.confidence
                ):
                    seen[key] = tech
        return list(seen.values())


# ---------------------------------------------------------------------------
# Finding deduplication
# ---------------------------------------------------------------------------

class FindingDeduplicator:
    """
    Deduplicates ``Finding`` items.

    Two findings are considered duplicates if they share the same ``id``
    **or** (same ``name`` + same ``url`` + same ``severity``).
    """

    def deduplicate(self, findings: Sequence[Finding]) -> List[Finding]:
        by_id: Dict[str, Finding] = {}
        by_composite: Dict[Tuple[str, str, str], Finding] = {}

        result: List[Finding] = []

        for finding in findings:
            # Dedup by ID
            if finding.id in by_id:
                continue

            # Dedup by (name, url, severity)
            composite = (
                finding.name.lower(),
                (finding.url or "").lower(),
                finding.severity,
            )
            if composite in by_composite:
                continue

            by_id[finding.id] = finding
            by_composite[composite] = finding
            result.append(finding)

        return result


# ---------------------------------------------------------------------------
# Top-level deduplication service
# ---------------------------------------------------------------------------

class DeduplicationService:
    """
    Orchestrates all three deduplicators.

    Usage::

        svc = DeduplicationService()
        endpoints   = svc.dedup_endpoints(raw_endpoints)
        technologies = svc.dedup_technologies(raw_technologies)
        findings    = svc.dedup_findings(raw_findings)
    """

    def __init__(self, fuzzy_threshold: float = 0.85) -> None:
        self._endpoints = EndpointDeduplicator(fuzzy_threshold)
        self._technologies = TechnologyDeduplicator()
        self._findings = FindingDeduplicator()

    def dedup_endpoints(self, items: Sequence[Endpoint]) -> List[Endpoint]:
        return self._endpoints.deduplicate(items)

    def dedup_technologies(self, items: Sequence[Technology]) -> List[Technology]:
        return self._technologies.deduplicate(items)

    def dedup_findings(self, items: Sequence[Finding]) -> List[Finding]:
        return self._findings.deduplicate(items)
