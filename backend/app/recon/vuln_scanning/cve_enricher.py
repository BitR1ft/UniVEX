"""
CVE Enrichment Module

Enriches vulnerabilities with CVE data from NVD and Vulners APIs.

Author: BitR1FT (BitR1FT)
Developed by: BitR1FT
"""

import re
import json
import logging
import time
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import httpx
from .schemas import CVEInfo, VulnSeverity, CVEEnrichmentConfig

logger = logging.getLogger(__name__)


class CVEEnricher:
    """
    CVE enrichment using NVD and Vulners APIs.
    
    Provides:
    - CVE lookup by ID
    - CVE search by product/version
    - CVSS score extraction
    - Severity classification
    - Result caching
    """
    
    # NVD API endpoints
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    VULNERS_API_BASE = "https://vulners.com/api/v3"
    
    def __init__(self, config: CVEEnrichmentConfig):
        """
        Initialize CVE enricher.
        
        Args:
            config: CVE enrichment configuration
        """
        self.config = config
        self.cache: Dict[str, CVEInfo] = {}
        self.cache_file = Path.home() / ".univex" / "cve_cache.json"
        
        if config.cache_results:
            self._load_cache()
        
        # Rate limiting
        self.last_nvd_request = 0
        self.nvd_rate_limit = 0.6 if config.nvd_api_key else 6.0  # seconds between requests
    
    def _load_cache(self) -> None:
        """Load CVE data from cache file."""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r') as f:
                    cache_data = json.load(f)
                    
                # Convert to CVEInfo objects
                for cve_id, data in cache_data.items():
                    # Check if cache entry is still valid
                    cached_at_str = data.get("_cached_at")
                    if not cached_at_str:
                        logger.warning(f"Cache entry for {cve_id} missing timestamp, skipping")
                        continue
                    
                    cached_at = datetime.fromisoformat(cached_at_str)
                    if datetime.utcnow() - cached_at < timedelta(seconds=self.config.cache_ttl):
                        # Remove cache metadata before creating object
                        data.pop("_cached_at", None)
                        self.cache[cve_id] = CVEInfo(**data)
                
                logger.info(f"Loaded {len(self.cache)} CVE entries from cache")
        except Exception as e:
            logger.warning(f"Failed to load CVE cache: {e}")
    
    def _save_cache(self) -> None:
        """Save CVE data to cache file."""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Convert to dict and add cache timestamp
            cache_data = {}
            for cve_id, cve_info in self.cache.items():
                data = cve_info.model_dump(mode='json')
                data["_cached_at"] = datetime.utcnow().isoformat()
                cache_data[cve_id] = data
            
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            
            logger.debug(f"Saved {len(cache_data)} CVE entries to cache")
        except Exception as e:
            logger.warning(f"Failed to save CVE cache: {e}")
    
    def _rate_limit_nvd(self) -> None:
        """Apply rate limiting for NVD API."""
        elapsed = time.time() - self.last_nvd_request
        if elapsed < self.nvd_rate_limit:
            time.sleep(self.nvd_rate_limit - elapsed)
        self.last_nvd_request = time.time()
    
    def _extract_cvss_severity(self, cvss_score: float) -> VulnSeverity:
        """
        Convert CVSS score to severity level.
        
        Args:
            cvss_score: CVSS v3 score
            
        Returns:
            Severity level
        """
        if cvss_score >= 9.0:
            return VulnSeverity.CRITICAL
        elif cvss_score >= 7.0:
            return VulnSeverity.HIGH
        elif cvss_score >= 4.0:
            return VulnSeverity.MEDIUM
        elif cvss_score > 0.0:
            return VulnSeverity.LOW
        else:
            return VulnSeverity.INFO
    
    def enrich_by_cve_id(self, cve_id: str) -> Optional[CVEInfo]:
        """
        Enrich a vulnerability by CVE ID.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)
            
        Returns:
            CVE information or None if not found
        """
        # Validate CVE ID format
        if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id, re.IGNORECASE):
            logger.warning(f"Invalid CVE ID format: {cve_id}")
            return None
        
        cve_id = cve_id.upper()
        
        # Check cache
        if cve_id in self.cache:
            logger.debug(f"Cache hit for {cve_id}")
            return self.cache[cve_id]
        
        # Try NVD first
        cve_info = self._fetch_from_nvd(cve_id)
        
        # Fallback to Vulners if NVD fails and Vulners is enabled
        if not cve_info and self.config.use_vulners:
            cve_info = self._fetch_from_vulners(cve_id)
        
        # Cache result
        if cve_info and self.config.cache_results:
            self.cache[cve_id] = cve_info
            self._save_cache()
        
        return cve_info
    
    def _fetch_from_nvd(self, cve_id: str) -> Optional[CVEInfo]:
        """
        Fetch CVE data from NVD API.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            CVE information or None
        """
        try:
            self._rate_limit_nvd()
            
            headers = {}
            if self.config.nvd_api_key:
                headers["apiKey"] = self.config.nvd_api_key
            
            url = f"{self.NVD_API_BASE}?cveId={cve_id}"
            
            with httpx.Client(timeout=30.0) as client:
                response = client.get(url, headers=headers)
                response.raise_for_status()
                data = response.json()
            
            # Parse NVD response
            if not data.get("vulnerabilities"):
                logger.warning(f"No data found for {cve_id} in NVD")
                return None
            
            vuln = data["vulnerabilities"][0]["cve"]
            
            # Extract CVSS v3 metrics (prefer v3.1, fallback to v3.0)
            cvss_data = vuln.get("metrics", {}).get("cvssMetricV31", [])
            if not cvss_data:
                cvss_data = vuln.get("metrics", {}).get("cvssMetricV30", [])
            
            cvss_score = None
            cvss_vector = None
            if cvss_data:
                cvss = cvss_data[0]["cvssData"]
                cvss_score = cvss.get("baseScore")
                cvss_vector = cvss.get("vectorString")
            
            # Determine severity
            severity = self._extract_cvss_severity(cvss_score) if cvss_score else VulnSeverity.INFO
            
            # Extract description
            descriptions = vuln.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available"
            )
            
            # Extract references
            references = [
                ref["url"] for ref in vuln.get("references", [])
            ]
            
            # Extract affected products (CPE configurations)
            affected_products = []
            configurations = vuln.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable"):
                            cpe = cpe_match.get("criteria", "")
                            # Extract product name from CPE
                            if cpe:
                                parts = cpe.split(":")
                                if len(parts) >= 5:
                                    product = f"{parts[3]} {parts[4]} {parts[5]}"
                                    affected_products.append(product)
            
            # Parse dates
            published = vuln.get("published")
            modified = vuln.get("lastModified")
            
            cve_info = CVEInfo(
                cve_id=cve_id,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                severity=severity,
                description=description,
                published_date=datetime.fromisoformat(published.replace("Z", "+00:00")) if published else None,
                modified_date=datetime.fromisoformat(modified.replace("Z", "+00:00")) if modified else None,
                affected_products=list(set(affected_products))[:10],  # Limit to 10
                references=references[:5],  # Limit to 5 references
                exploit_available=False,  # NVD doesn't provide this directly
            )
            
            logger.info(f"Enriched {cve_id} from NVD: CVSS {cvss_score}, {severity.value}")
            return cve_info
            
        except httpx.HTTPStatusError as e:
            logger.error(f"NVD API error for {cve_id}: {e.response.status_code}")
            return None
        except Exception as e:
            logger.error(f"Failed to fetch {cve_id} from NVD: {e}")
            return None
    
    def _fetch_from_vulners(self, cve_id: str) -> Optional[CVEInfo]:
        """
        Fetch CVE data from Vulners API.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            CVE information or None
        """
        try:
            url = f"{self.VULNERS_API_BASE}/search/id/"
            
            params = {
                "id": cve_id,
                "fields": ["cvss", "description", "published", "modified", "references"]
            }
            
            if self.config.vulners_api_key:
                params["apiKey"] = self.config.vulners_api_key
            
            with httpx.Client(timeout=30.0) as client:
                response = client.post(url, json=params)
                response.raise_for_status()
                data = response.json()
            
            if data.get("result") != "OK" or not data.get("data", {}).get("documents"):
                logger.warning(f"No data found for {cve_id} in Vulners")
                return None
            
            doc = data["data"]["documents"][cve_id]
            
            # Extract CVSS
            cvss_score = doc.get("cvss", {}).get("score")
            cvss_vector = doc.get("cvss", {}).get("vector")
            
            severity = self._extract_cvss_severity(cvss_score) if cvss_score else VulnSeverity.INFO
            
            cve_info = CVEInfo(
                cve_id=cve_id,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                severity=severity,
                description=doc.get("description", "No description available"),
                published_date=datetime.fromtimestamp(doc["published"]) if doc.get("published") else None,
                modified_date=datetime.fromtimestamp(doc["modified"]) if doc.get("modified") else None,
                references=doc.get("references", [])[:5],
                exploit_available=doc.get("exploitAvailable", False),
            )
            
            logger.info(f"Enriched {cve_id} from Vulners: CVSS {cvss_score}, {severity.value}")
            return cve_info
            
        except Exception as e:
            logger.error(f"Failed to fetch {cve_id} from Vulners: {e}")
            return None
    
    def enrich_by_product(
        self,
        product: str,
        version: Optional[str] = None,
        max_results: int = 10
    ) -> List[CVEInfo]:
        """
        Search for CVEs affecting a specific product/version.
        
        Args:
            product: Product name (e.g., "apache", "nginx")
            version: Optional version number
            max_results: Maximum number of CVEs to return
            
        Returns:
            List of CVE information
        """
        try:
            self._rate_limit_nvd()
            
            headers = {}
            if self.config.nvd_api_key:
                headers["apiKey"] = self.config.nvd_api_key
            
            # Build query
            params = {
                "keywordSearch": product,
                "resultsPerPage": max_results
            }
            
            if version:
                params["versionStart"] = version
                params["versionEnd"] = version
            
            with httpx.Client(timeout=30.0) as client:
                response = client.get(self.NVD_API_BASE, params=params, headers=headers)
                response.raise_for_status()
                data = response.json()
            
            cve_list = []
            for item in data.get("vulnerabilities", [])[:max_results]:
                vuln = item["cve"]
                cve_id = vuln["id"]
                
                # Check if already cached
                if cve_id in self.cache:
                    cve_list.append(self.cache[cve_id])
                    continue
                
                # Extract CVSS
                cvss_data = vuln.get("metrics", {}).get("cvssMetricV31", [])
                if not cvss_data:
                    cvss_data = vuln.get("metrics", {}).get("cvssMetricV30", [])
                
                cvss_score = None
                if cvss_data:
                    cvss_score = cvss_data[0]["cvssData"].get("baseScore")
                
                # Filter by minimum CVSS
                if cvss_score and cvss_score < self.config.min_cvss_score:
                    continue
                
                # Enrich this CVE
                cve_info = self.enrich_by_cve_id(cve_id)
                if cve_info:
                    cve_list.append(cve_info)
            
            logger.info(f"Found {len(cve_list)} CVEs for {product} {version or ''}")
            return cve_list
            
        except Exception as e:
            logger.error(f"Failed to search CVEs for {product}: {e}")
            return []
