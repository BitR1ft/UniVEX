"""
NVD API v2 Client

Implements CVE lookup against the official NIST National Vulnerability
Database (NVD) API v2.  Extracts CVSS v3/v2 scores, CWE IDs, CPE
matches, and reference URLs.

Rate limiting
-------------
The NVD enforces 50 requests per 30 seconds without an API key and
100 requests per 30 seconds with one.  We use a simple token-bucket
limiter to stay within the allowed window.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from app.services.enrichment.enrichment_service import CVSSVector

logger = logging.getLogger(__name__)

_NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Simple token-bucket rate limiter
# ---------------------------------------------------------------------------

class _RateLimiter:
    def __init__(self, calls: int, period: float) -> None:
        self._calls = calls
        self._period = period
        self._tokens = float(calls)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(
                float(self._calls),
                self._tokens + elapsed * (self._calls / self._period),
            )
            self._last_refill = now
            if self._tokens < 1:
                sleep_for = (1 - self._tokens) * (self._period / self._calls)
                await asyncio.sleep(sleep_for)
                self._tokens = 0
            else:
                self._tokens -= 1


# ---------------------------------------------------------------------------
# NVDClient
# ---------------------------------------------------------------------------

class NVDClient:
    """
    Async HTTP client for the NIST NVD API v2.

    Args:
        api_key:   Optional NVD API key (raises rate limit from 50→100/30s).
        timeout:   Per-request timeout in seconds.
        max_retries: Number of automatic retries on transient failures.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: int = 15,
        max_retries: int = 3,
    ) -> None:
        self._api_key = api_key
        self._timeout = timeout
        self._max_retries = max_retries

        # Rate limit: 50 req/30s (no key) or 100 req/30s (with key)
        calls = 100 if api_key else 50
        self._limiter = _RateLimiter(calls=calls, period=30.0)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def fetch(self, cve_id: str) -> Optional[Any]:
        """
        Fetch a single CVE by ID from NVD API v2.

        Returns an :class:`~app.services.enrichment.enrichment_service.EnrichedCVE`
        or ``None`` if the CVE is not found or a network error occurs.

        Args:
            cve_id: CVE identifier, e.g. ``"CVE-2021-44228"``.
        """

        cve_id = cve_id.upper().strip()
        if not _CVE_RE.match(cve_id):
            raise ValueError(f"Invalid CVE ID format: {cve_id!r}")

        await self._limiter.acquire()

        raw = await self._request({"cveId": cve_id})
        if not raw:
            return None

        vulnerabilities = raw.get("vulnerabilities", [])
        if not vulnerabilities:
            return None

        cve_item = vulnerabilities[0].get("cve", {})
        return self._parse_cve_item(cve_id, cve_item)

    # ------------------------------------------------------------------
    # HTTP layer
    # ------------------------------------------------------------------

    async def _request(self, params: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Make a rate-limited, retrying GET request to NVD API."""
        import httpx

        headers: Dict[str, str] = {}
        if self._api_key:
            headers["apiKey"] = self._api_key

        for attempt in range(1, self._max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.get(_NVD_API_BASE, params=params, headers=headers)

                if resp.status_code == 404:
                    return None
                if resp.status_code == 429:
                    # Rate limited – back off
                    retry_after = int(resp.headers.get("Retry-After", "30"))
                    logger.warning("NVD rate limited; sleeping %ds", retry_after)
                    await asyncio.sleep(retry_after)
                    continue
                resp.raise_for_status()
                return resp.json()

            except Exception as exc:
                if attempt == self._max_retries:
                    logger.error("NVD request failed after %d attempts: %s", self._max_retries, exc)
                    return None
                await asyncio.sleep(2 ** attempt)

        return None

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    def _parse_cve_item(self, cve_id: str, item: Dict[str, Any]) -> Any:
        """Convert a NVD CVE JSON object to :class:`EnrichedCVE`."""
        from app.services.enrichment.enrichment_service import EnrichedCVE

        # Description (prefer English)
        description = _pick_en(item.get("descriptions", []))

        # Published / modified timestamps
        published = _parse_date(item.get("published"))
        last_modified = _parse_date(item.get("lastModified"))

        # CVSS v3
        cvss_v3: Optional[CVSSVector] = None
        metrics = item.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key, [])
            if entries:
                cvss_v3 = self._parse_cvss_v3(entries[0].get("cvssData", {}))
                break

        # CVSS v2 score (fallback)
        cvss_v2_score: Optional[float] = None
        v2_entries = metrics.get("cvssMetricV2", [])
        if v2_entries:
            cvss_v2_score = v2_entries[0].get("cvssData", {}).get("baseScore")

        # CWE IDs
        cwe_ids: List[str] = []
        for weakness in item.get("weaknesses", []):
            for desc in weakness.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    cwe_ids.append(val)

        # CPE matches
        cpe_matches: List[str] = []
        for config in item.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpe = cpe_match.get("criteria", "")
                    if cpe and cpe_match.get("vulnerable", False):
                        cpe_matches.append(cpe)

        # References
        references = [
            ref.get("url", "")
            for ref in item.get("references", [])
            if ref.get("url")
        ]

        return EnrichedCVE(
            cve_id=cve_id,
            description=description,
            published=published,
            last_modified=last_modified,
            cvss_v3=cvss_v3,
            cvss_v2_score=cvss_v2_score,
            cwe_ids=list(dict.fromkeys(cwe_ids)),   # dedup, preserve order
            cpe_matches=cpe_matches[:50],            # cap to avoid huge payloads
            sources=["nvd"],
            raw={"references": references, "raw_cve": item},
        )

    @staticmethod
    def _parse_cvss_v3(data: Dict[str, Any]) -> CVSSVector:
        from app.services.enrichment.enrichment_service import CVSSVector
        return CVSSVector(
            version=data.get("version", "3.1"),
            attack_vector=data.get("attackVector"),
            attack_complexity=data.get("attackComplexity"),
            privileges_required=data.get("privilegesRequired"),
            user_interaction=data.get("userInteraction"),
            scope=data.get("scope"),
            confidentiality_impact=data.get("confidentialityImpact"),
            integrity_impact=data.get("integrityImpact"),
            availability_impact=data.get("availabilityImpact"),
            base_score=data.get("baseScore"),
            base_severity=data.get("baseSeverity"),
            vector_string=data.get("vectorString"),
        )


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _pick_en(descriptions: List[Dict[str, str]]) -> Optional[str]:
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value")
    return descriptions[0].get("value") if descriptions else None


def _parse_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    # Try longest format first; slice to format length to avoid partial parse errors
    for fmt, length in (
        ("%Y-%m-%dT%H:%M:%S.%f", 26),
        ("%Y-%m-%dT%H:%M:%S", 19),
        ("%Y-%m-%d", 10),
    ):
        try:
            return datetime.strptime(value[:length], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None
