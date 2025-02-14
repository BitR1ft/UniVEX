"""
CVE Enrichment sub-package.

Provides:
    EnrichmentService  – unified pipeline (NVD + Vulners + cache)
    EnrichedCVE        – canonical enrichment data model
    CVSSVector         – CVSS v3.x metric components
    ExploitInfo        – exploit availability metadata
    NVDClient          – NIST NVD API v2 client
    VulnersClient      – Vulners API client
    CVECache           – SQLite-backed cache with TTL & warm-up
"""
from app.services.enrichment.enrichment_service import (
    EnrichmentService,
    EnrichedCVE,
    CVSSVector,
    ExploitInfo,
)
from app.services.enrichment.nvd_client import NVDClient
from app.services.enrichment.vulners_client import VulnersClient
from app.services.enrichment.cve_cache import CVECache

__all__ = [
    "EnrichmentService",
    "EnrichedCVE",
    "CVSSVector",
    "ExploitInfo",
    "NVDClient",
    "VulnersClient",
    "CVECache",
]
