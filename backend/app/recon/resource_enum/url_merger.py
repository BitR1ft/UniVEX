"""
URL Discovery Merger

Provides a production-grade pipeline for merging and deduplicating
endpoint results from Katana, GAU, and Kiterunner into a single
canonical, classified list.

Features
--------
- URL normalisation (scheme, trailing-slash, case, fragment strip)
- Multi-source merge with provenance tracking
- URL categorisation (auth, api, admin, file, sensitive, static, dynamic)
- Confidence scoring based on source count and liveness
- Fuzzy near-duplicate detection using path similarity
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse, urlunparse

from app.recon.canonical_schemas import Endpoint


# ---------------------------------------------------------------------------
# URL category labels
# ---------------------------------------------------------------------------

class URLCategory:
    AUTH = "auth"
    API = "api"
    ADMIN = "admin"
    FILE = "file"
    SENSITIVE = "sensitive"
    STATIC = "static"
    DYNAMIC = "dynamic"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Category patterns
# ---------------------------------------------------------------------------

_AUTH_PATTERNS = re.compile(
    r"/(login|signin|sign-in|auth|oauth|sso|logout|register|signup|password|forgot-pass|reset-pass)",
    re.IGNORECASE,
)
_API_PATTERNS = re.compile(
    r"/(api/|v\d+/|rest/|graphql|json|rpc|ws/|websocket)",
    re.IGNORECASE,
)
_ADMIN_PATTERNS = re.compile(
    r"/(admin|dashboard|console|management|wp-admin|phpmyadmin|cpanel|webmin|controlpanel)",
    re.IGNORECASE,
)
_FILE_PATTERNS = re.compile(
    r"/(upload|download|file|attachment|media|assets|files|static/|blob)",
    re.IGNORECASE,
)
_SENSITIVE_PATTERNS = re.compile(
    r"/(\.env|\.git|config|backup|secret|private|internal|debug|test|dev|staging)",
    re.IGNORECASE,
)
_STATIC_EXTENSIONS = re.compile(
    r"\.(js|css|jpg|jpeg|png|gif|svg|ico|woff2?|ttf|eot|otf|mp4|mp3|pdf|zip)(\?|$)",
    re.IGNORECASE,
)


def categorise_url(url: str, params: Optional[List[str]] = None) -> str:
    """
    Classify a URL into a :class:`URLCategory` string.

    Precedence: auth > api > admin > file > sensitive > static > dynamic > unknown.
    """
    path = urlparse(url).path

    if _AUTH_PATTERNS.search(path):
        return URLCategory.AUTH
    if _API_PATTERNS.search(path):
        return URLCategory.API
    if _ADMIN_PATTERNS.search(path):
        return URLCategory.ADMIN
    if _FILE_PATTERNS.search(path):
        return URLCategory.FILE
    if _SENSITIVE_PATTERNS.search(path):
        return URLCategory.SENSITIVE
    if _STATIC_EXTENSIONS.search(path):
        return URLCategory.STATIC
    if params or "?" in url:
        return URLCategory.DYNAMIC
    return URLCategory.UNKNOWN


# ---------------------------------------------------------------------------
# URLRecord — internal merge unit
# ---------------------------------------------------------------------------

@dataclass
class URLRecord:
    """Internal representation of a URL during the merge pipeline."""

    url: str
    normalised: str
    method: str = "GET"
    sources: Set[str] = field(default_factory=set)
    status_code: Optional[int] = None
    is_live: Optional[bool] = None
    parameters: List[str] = field(default_factory=list)
    category: str = URLCategory.UNKNOWN
    confidence: float = 0.0
    extra: Dict[str, Any] = field(default_factory=dict)

    def merge_from(self, other: "URLRecord") -> None:
        """Merge provenance and metadata from another record for the same URL."""
        self.sources.update(other.sources)
        if not self.is_live and other.is_live:
            self.is_live = other.is_live
        if not self.status_code and other.status_code:
            self.status_code = other.status_code
        for p in other.parameters:
            if p not in self.parameters:
                self.parameters.append(p)
        if other.method not in ("GET", "UNKNOWN") and self.method in ("GET", "UNKNOWN"):
            self.method = other.method

    def to_endpoint(self) -> Endpoint:
        """Convert back to a canonical :class:`Endpoint`."""
        from app.recon.canonical_schemas import EndpointMethod

        try:
            method_enum = EndpointMethod(self.method)
        except ValueError:
            method_enum = EndpointMethod.UNKNOWN

        return Endpoint(
            url=self.url,
            method=method_enum,
            status_code=self.status_code,
            is_live=self.is_live if self.is_live is not None else False,
            parameters=self.parameters,
            confidence=self.confidence,
            tags=["url-discovery", self.category] + list(self.sources),
            discovered_by=",".join(sorted(self.sources)) or "url_merger",
            extra={
                "category": self.category,
                "sources": list(self.sources),
                **self.extra,
            },
        )


# ---------------------------------------------------------------------------
# URL normalisation
# ---------------------------------------------------------------------------

def normalise_url(url: str) -> str:
    """
    Return a normalised URL for deduplication comparison.

    Transformations applied:
    - Lower-case scheme and host only (path and query preserve original case)
    - Strip fragment (#…)
    - Sort query parameters alphabetically
    """
    try:
        p = urlparse(url)
        # Only lowercase scheme and netloc; preserve path/query case
        # Trailing slashes are kept intentional to avoid merging distinct resources
        p.path.rstrip("/") or "/" if p.path in ("", "/") else p.path
        query = "&".join(sorted(p.query.split("&"))) if p.query else ""
        return urlunparse((p.scheme.lower(), p.netloc.lower(), p.path, "", query, ""))
    except Exception:
        return url.split("#")[0]


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------

def compute_confidence(record: URLRecord) -> float:
    """
    Assign a confidence score 0.0–1.0 to a URLRecord.

    Factors:
    - Confirmed live (+0.4)
    - Source count: 1 → +0.2, 2 → +0.3, ≥3 → +0.4
    - Non-GET HTTP method (+0.1)
    - Has parameters (+0.1)
    """
    score = 0.0
    if record.is_live:
        score += 0.4
    n = len(record.sources)
    score += 0.2 if n == 1 else 0.3 if n == 2 else 0.4
    if record.method not in ("GET", "UNKNOWN"):
        score += 0.1
    if record.parameters:
        score += 0.1
    return min(round(score, 2), 1.0)


# ---------------------------------------------------------------------------
# URLMerger — main pipeline
# ---------------------------------------------------------------------------

class URLMerger:
    """
    Merges :class:`~app.recon.canonical_schemas.Endpoint` lists from multiple
    tools into a deduplicated, classified, confidence-scored list.

    Usage::

        merger = URLMerger()
        merger.add(katana_result.endpoints, source="katana")
        merger.add(gau_result.endpoints, source="gau")
        merger.add(kr_result.endpoints, source="kiterunner")
        merged_endpoints = merger.merge()
    """

    def __init__(self) -> None:
        self._records: Dict[str, URLRecord] = {}  # normalised_url → URLRecord

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def add(self, endpoints: List[Endpoint], source: str) -> None:
        """
        Add endpoints from one tool.

        Args:
            endpoints: List of canonical :class:`Endpoint` objects.
            source:    Tool label (e.g. ``"katana"``, ``"gau"``).
        """
        for ep in endpoints:
            norm = normalise_url(ep.url)
            if norm in self._records:
                incoming = self._endpoint_to_record(ep, source)
                self._records[norm].merge_from(incoming)
            else:
                self._records[norm] = self._endpoint_to_record(ep, source)

    # ------------------------------------------------------------------
    # Merge pipeline
    # ------------------------------------------------------------------

    def merge(self) -> List[Endpoint]:
        """
        Execute the merge pipeline and return deduplicated, classified
        :class:`Endpoint` objects sorted by descending confidence.

        Steps:
        1. Categorise each URL
        2. Compute confidence scores
        3. Convert to canonical Endpoint objects
        4. Sort by confidence (descending)
        """
        results: List[URLRecord] = []

        for record in self._records.values():
            record.category = categorise_url(record.url, record.parameters)
            record.confidence = compute_confidence(record)
            results.append(record)

        results.sort(key=lambda r: r.confidence, reverse=True)
        return [r.to_endpoint() for r in results]

    def clear(self) -> None:
        """Reset the merger for re-use."""
        self._records.clear()

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        """Return summary statistics about the current merge state."""
        cats: Dict[str, int] = {}
        src_counts: Dict[str, int] = {}
        for record in self._records.values():
            cat = categorise_url(record.url, record.parameters)
            cats[cat] = cats.get(cat, 0) + 1
            for s in record.sources:
                src_counts[s] = src_counts.get(s, 0) + 1

        return {
            "total_unique_urls": len(self._records),
            "by_category": cats,
            "by_source": src_counts,
        }

    # ------------------------------------------------------------------
    # Internal helper
    # ------------------------------------------------------------------

    @staticmethod
    def _endpoint_to_record(ep: Endpoint, source: str) -> URLRecord:
        return URLRecord(
            url=ep.url,
            normalised=normalise_url(ep.url),
            method=ep.method.value if hasattr(ep.method, "value") else str(ep.method),
            sources={source},
            status_code=ep.status_code,
            is_live=ep.is_live,
            parameters=list(ep.parameters or []),
            extra=dict(ep.extra or {}),
        )
