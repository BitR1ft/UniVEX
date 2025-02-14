"""
CVE Enrichment Service

Provides a unified interface for enriching Finding objects with
full CVE metadata from external sources (NVD, Vulners) and an
in-process cache with configurable expiry.

Architecture
------------
    EnrichmentService
      ├── NVDClient           – official NVD API v2
      ├── VulnersClient       – Vulners API
      ├── CVECache            – SQLite-backed local cache
      └── enrich_findings()   – batch pipeline

Public data model
-----------------
    EnrichedCVE             – full CVE record returned to callers
    ExploitInfo             – exploit availability metadata
    CVSSVector              – parsed CVSS v3.x vector components
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class CVSSVector:
    """
    Parsed CVSS v3.x base metric values.

    Fields match the standard CVSS v3.x metric names.
    """
    version: str = "3.1"
    attack_vector: Optional[str] = None           # N / A / L / P
    attack_complexity: Optional[str] = None       # L / H
    privileges_required: Optional[str] = None     # N / L / H
    user_interaction: Optional[str] = None        # N / R
    scope: Optional[str] = None                   # U / C
    confidentiality_impact: Optional[str] = None  # N / L / H
    integrity_impact: Optional[str] = None        # N / L / H
    availability_impact: Optional[str] = None     # N / L / H
    base_score: Optional[float] = None
    base_severity: Optional[str] = None
    vector_string: Optional[str] = None


@dataclass
class ExploitInfo:
    """
    Exploit availability metadata aggregated from multiple sources.
    """
    exploits_available: bool = False
    exploit_count: int = 0
    exploit_sources: List[str] = field(default_factory=list)
    # Highest maturity level seen: 'proof-of-concept', 'functional', 'weaponised'
    maturity: Optional[str] = None
    references: List[str] = field(default_factory=list)


@dataclass
class EnrichedCVE:
    """
    Full CVE enrichment record produced by :class:`EnrichmentService`.

    Combines data from NVD, Vulners, and the local cache into a single
    canonical structure that callers attach to :class:`~app.recon.canonical_schemas.Finding`
    objects.
    """
    cve_id: str
    description: Optional[str] = None
    published: Optional[datetime] = None
    last_modified: Optional[datetime] = None

    # Scoring
    cvss_v3: Optional[CVSSVector] = None
    cvss_v2_score: Optional[float] = None

    # Classification
    cwe_ids: List[str] = field(default_factory=list)
    capec_ids: List[str] = field(default_factory=list)

    # Exploit intelligence
    exploit_info: ExploitInfo = field(default_factory=ExploitInfo)

    # Affected products
    cpe_matches: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)

    # Provenance
    sources: List[str] = field(default_factory=list)
    fetched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Raw data for debugging / downstream processing
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def base_score(self) -> Optional[float]:
        """Return CVSS v3 base score if available, else v2."""
        if self.cvss_v3 and self.cvss_v3.base_score is not None:
            return self.cvss_v3.base_score
        return self.cvss_v2_score

    @property
    def severity(self) -> str:
        """Derive severity label from base score."""
        score = self.base_score
        if score is None:
            return "unknown"
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0.0:
            return "low"
        return "info"


# ---------------------------------------------------------------------------
# EnrichmentService
# ---------------------------------------------------------------------------

class EnrichmentService:
    """
    Unified CVE enrichment service.

    Assembles NVDClient, VulnersClient, and CVECache into a single
    pipeline.  Both clients are lazily imported so that missing optional
    API keys do not block initialisation.

    Usage::

        svc = EnrichmentService(nvd_api_key="...", vulners_api_key="...")

        # Single CVE lookup
        cve = await svc.get_cve("CVE-2021-44228")

        # Batch enrich a list of Finding objects
        from app.recon.canonical_schemas import Finding
        enriched = await svc.enrich_findings([finding1, finding2])
    """

    def __init__(
        self,
        nvd_api_key: Optional[str] = None,
        vulners_api_key: Optional[str] = None,
        cache_ttl_days: int = 30,
        cache_path: Optional[str] = None,
        batch_size: int = 10,
    ) -> None:
        self._nvd_key = nvd_api_key
        self._vulners_key = vulners_api_key
        self._cache_ttl_days = cache_ttl_days
        self._cache_path = cache_path
        self._batch_size = batch_size

        # Lazy-init; populated on first use
        self._nvd: Optional[Any] = None
        self._vulners: Optional[Any] = None
        self._cache: Optional[Any] = None

    # ------------------------------------------------------------------
    # Lazy accessors
    # ------------------------------------------------------------------

    def _get_nvd(self) -> Any:
        if self._nvd is None:
            from app.services.enrichment.nvd_client import NVDClient
            self._nvd = NVDClient(api_key=self._nvd_key)
        return self._nvd

    def _get_vulners(self) -> Any:
        if self._vulners is None:
            from app.services.enrichment.vulners_client import VulnersClient
            self._vulners = VulnersClient(api_key=self._vulners_key)
        return self._vulners

    def _get_cache(self) -> Any:
        if self._cache is None:
            from app.services.enrichment.cve_cache import CVECache
            self._cache = CVECache(
                ttl_days=self._cache_ttl_days,
                db_path=self._cache_path,
            )
        return self._cache

    # ------------------------------------------------------------------
    # Single CVE lookup
    # ------------------------------------------------------------------

    async def get_cve(self, cve_id: str) -> Optional[EnrichedCVE]:
        """
        Return enriched CVE data for *cve_id*.

        Lookup order:
        1. Local SQLite cache (returns if fresh)
        2. NVD API v2
        3. Vulners API (merges exploit data)

        The merged result is written to the cache before returning.
        """
        cve_id = cve_id.upper().strip()
        cache = self._get_cache()

        # 1. Cache hit
        cached = await cache.get(cve_id)
        if cached:
            logger.debug("Cache hit for %s", cve_id)
            return cached

        # 2. NVD fetch
        result: Optional[EnrichedCVE] = None
        try:
            result = await self._get_nvd().fetch(cve_id)
        except Exception as exc:
            logger.warning("NVD fetch failed for %s: %s", cve_id, exc)

        # 3. Vulners merge (adds exploit intel)
        if result:
            try:
                vulners_data = await self._get_vulners().fetch(cve_id)
                if vulners_data:
                    result = _merge_vulners(result, vulners_data)
            except Exception as exc:
                logger.warning("Vulners fetch failed for %s: %s", cve_id, exc)

        if result:
            await cache.set(cve_id, result)

        return result

    # ------------------------------------------------------------------
    # Batch enrichment pipeline
    # ------------------------------------------------------------------

    async def enrich_findings(self, findings: List[Any]) -> List[Any]:
        """
        Batch-enrich a list of :class:`~app.recon.canonical_schemas.Finding` objects.

        For each finding with non-empty ``cve_ids``, the first CVE is looked
        up and its metadata is merged back into the finding's ``extra`` dict
        and scalar fields (``cvss_score``, ``cwe_ids``, ``references``).

        Returns the same list with fields updated in-place.  Findings without
        CVE IDs are left unchanged.  Network errors for individual CVEs are
        logged and silently skipped (fallback strategy).
        """
        import asyncio

        async def _enrich_one(finding: Any) -> Any:
            if not finding.cve_ids:
                return finding
            cve_id = finding.cve_ids[0]
            try:
                enriched = await self.get_cve(cve_id)
                if enriched:
                    _apply_enrichment(finding, enriched)
            except Exception as exc:
                logger.warning("Enrichment failed for %s: %s", cve_id, exc)
            return finding

        # Process in batches to respect rate limits
        enriched_findings = []
        for i in range(0, len(findings), self._batch_size):
            batch = findings[i: i + self._batch_size]
            results = await asyncio.gather(*[_enrich_one(f) for f in batch])
            enriched_findings.extend(results)

        return enriched_findings


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _merge_vulners(base: EnrichedCVE, vulners_data: Dict[str, Any]) -> EnrichedCVE:
    """Merge Vulners exploit intelligence into an existing EnrichedCVE."""
    exploits = vulners_data.get("exploit_count", 0)
    if exploits > 0:
        base.exploit_info.exploits_available = True
        base.exploit_info.exploit_count = exploits
        base.exploit_info.exploit_sources.append("vulners")
        base.exploit_info.references.extend(vulners_data.get("exploit_refs", []))
        maturity = vulners_data.get("maturity")
        if maturity:
            base.exploit_info.maturity = maturity
    if "vulners" not in base.sources:
        base.sources.append("vulners")
    return base


def _apply_enrichment(finding: Any, enriched: EnrichedCVE) -> None:
    """Apply EnrichedCVE data to a Finding object (mutates in-place)."""
    if enriched.base_score is not None and finding.cvss_score is None:
        finding.cvss_score = enriched.base_score

    if enriched.description and not finding.description:
        finding.description = enriched.description

    for cwe in enriched.cwe_ids:
        if cwe not in finding.cwe_ids:
            finding.cwe_ids.append(cwe)

    for ref in enriched.raw.get("references", []):
        if ref not in finding.references:
            finding.references.append(ref)

    finding.extra.setdefault("cve_enrichment", {})
    finding.extra["cve_enrichment"] = {
        "cvss_v3": {
            "score": enriched.base_score,
            "severity": enriched.severity,
            "vector": enriched.cvss_v3.vector_string if enriched.cvss_v3 else None,
        },
        "exploit_info": {
            "available": enriched.exploit_info.exploits_available,
            "count": enriched.exploit_info.exploit_count,
            "maturity": enriched.exploit_info.maturity,
        },
        "published": enriched.published.isoformat() if enriched.published else None,
        "sources": enriched.sources,
    }
