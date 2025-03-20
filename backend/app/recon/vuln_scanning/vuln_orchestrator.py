"""
Vulnerability Scan Orchestrator

Orchestrates vulnerability scanning workflow with Nuclei, CVE enrichment,
and MITRE mapping.

Author: BitR1FT (BitR1FT)
Developed by: BitR1FT
"""

import logging
import time
import re
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed

from .schemas import (
    VulnScanRequest,
    VulnScanResult,
    VulnScanStats,
    VulnerabilityInfo,
    ScanMode,
    VulnSeverity,
    VulnCategory,
    CVEInfo,
)
from .nuclei_wrapper import NucleiWrapper
from .cve_enricher import CVEEnricher
from .mitre_mapper import MITREMapper

logger = logging.getLogger(__name__)


class VulnScanOrchestrator:
    """
    Orchestrator for vulnerability scanning pipeline.
    
    Workflow:
    1. Nuclei scan for vulnerabilities
    2. CVE enrichment for discovered vulnerabilities
    3. MITRE CWE/CAPEC mapping
    4. Result aggregation and statistics
    """
    
    def __init__(self, request: VulnScanRequest):
        """
        Initialize vulnerability scan orchestrator.
        
        Args:
            request: Vulnerability scan request configuration
        """
        self.request = request
        self.errors: List[str] = []
        self.warnings: List[str] = []
        
        # Initialize components based on mode
        self.nuclei = None
        self.cve_enricher = None
        self.mitre_mapper = None
        
        if self._should_run_nuclei():
            try:
                self.nuclei = NucleiWrapper(request.nuclei_config)
            except Exception as e:
                error_msg = f"Failed to initialize Nuclei: {e}"
                logger.error(error_msg)
                self.errors.append(error_msg)
                self.warnings.append("Nuclei scanning will be skipped")
        
        if request.cve_enrichment.enabled:
            try:
                self.cve_enricher = CVEEnricher(request.cve_enrichment)
            except Exception as e:
                error_msg = f"Failed to initialize CVE enricher: {e}"
                logger.error(error_msg)
                self.errors.append(error_msg)
                self.warnings.append("CVE enrichment will be skipped")
        
        if request.mitre_mapping.enabled:
            try:
                self.mitre_mapper = MITREMapper(request.mitre_mapping)
            except Exception as e:
                error_msg = f"Failed to initialize MITRE mapper: {e}"
                logger.error(error_msg)
                self.errors.append(error_msg)
                self.warnings.append("MITRE mapping will be skipped")
    
    def _should_run_nuclei(self) -> bool:
        """Determine if Nuclei should run based on scan mode."""
        return self.request.mode != ScanMode.CVE_ONLY
    
    async def run(self) -> VulnScanResult:
        """
        Execute complete vulnerability scanning workflow.
        
        Returns:
            Complete vulnerability scan result
        """
        logger.info(f"Starting vulnerability scan in {self.request.mode.value} mode")
        logger.info(f"Targets: {len(self.request.targets)}")
        
        start_time = time.time()
        vulnerabilities: List[VulnerabilityInfo] = []
        
        # Step 1: Nuclei Scanning
        nuclei_time = 0.0
        if self.nuclei and self._should_run_nuclei():
            nuclei_start = time.time()
            try:
                nuclei_vulns = self.nuclei.scan(self.request.targets)
                vulnerabilities.extend(nuclei_vulns)
                logger.info(f"Nuclei found {len(nuclei_vulns)} vulnerabilities")
            except Exception as e:
                error_msg = f"Nuclei scan failed: {e}"
                logger.error(error_msg)
                self.errors.append(error_msg)
            nuclei_time = time.time() - nuclei_start
        
        # Step 2: CVE Enrichment
        enrichment_time = 0.0
        if self.cve_enricher:
            enrichment_start = time.time()
            
            # Enrich based on detected technologies (if mode is CVE_ONLY or FULL)
            if self.request.mode in [ScanMode.CVE_ONLY, ScanMode.FULL]:
                tech_cves = self._enrich_from_technologies()
                vulnerabilities.extend(tech_cves)
            
            # Enrich existing vulnerabilities
            if self.request.parallel_execution:
                vulnerabilities = self._enrich_vulnerabilities_parallel(vulnerabilities)
            else:
                vulnerabilities = self._enrich_vulnerabilities_sequential(vulnerabilities)
            
            enrichment_time = time.time() - enrichment_start
        
        # Step 3: MITRE Mapping
        mitre_time = 0.0
        if self.mitre_mapper:
            mitre_start = time.time()
            
            if self.request.parallel_execution:
                vulnerabilities = self._map_mitre_parallel(vulnerabilities)
            else:
                vulnerabilities = self._map_mitre_sequential(vulnerabilities)
            
            mitre_time = time.time() - mitre_start
        
        # Step 4: Deduplicate and categorize
        vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)
        
        # Calculate statistics
        total_time = time.time() - start_time
        stats = self._calculate_stats(
            vulnerabilities,
            total_time,
            nuclei_time,
            enrichment_time,
            mitre_time
        )
        
        result = VulnScanResult(
            request=self.request,
            vulnerabilities=vulnerabilities,
            stats=stats,
            errors=self.errors,
            warnings=self.warnings,
            success=len(vulnerabilities) > 0 or len(self.errors) == 0
        )
        
        logger.info(f"Vulnerability scan completed in {total_time:.2f}s")
        logger.info(f"Total vulnerabilities: {stats.total_vulnerabilities}")
        logger.info(f"By severity: {stats.by_severity}")
        
        return result
    
    def _extract_cves_from_vulns(self, vulns: List[VulnerabilityInfo]) -> List[str]:
        """Extract CVE IDs from vulnerability titles and template IDs."""
        cves = []
        for vuln in vulns:
            # Check if template ID is a CVE
            if vuln.template_id and vuln.template_id.upper().startswith("CVE-"):
                cves.append(vuln.template_id.upper())
            # Check title for CVE references
            if "CVE-" in vuln.title.upper():
                cve_matches = re.findall(r'CVE-\d{4}-\d{4,}', vuln.title.upper())
                cves.extend(cve_matches)
        return list(set(cves))
    
    def _enrich_from_technologies(self) -> List[VulnerabilityInfo]:
        """
        Enrich CVEs based on detected technologies.
        
        Returns:
            List of vulnerabilities from CVE enrichment
        """
        tech_vulns = []
        
        for tech in self.request.detected_technologies:
            product = tech.get("name", "")
            version = tech.get("version", "")
            
            if not product:
                continue
            
            try:
                cves = self.cve_enricher.enrich_by_product(
                    product=product,
                    version=version,
                    max_results=5  # Limit per technology
                )
                
                for cve in cves:
                    # Create vulnerability from CVE
                    vuln = VulnerabilityInfo(
                        id=f"cve-{cve.cve_id}",
                        title=f"{cve.cve_id} in {product} {version}",
                        description=cve.description,
                        severity=cve.severity,
                        category=VulnCategory.CVE,
                        source="cve_enrichment",
                        cve=cve,
                        tags=[product, version] if version else [product]
                    )
                    tech_vulns.append(vuln)
                
            except Exception as e:
                logger.warning(f"Failed to enrich {product}: {e}")
        
        logger.info(f"Found {len(tech_vulns)} CVEs from {len(self.request.detected_technologies)} technologies")
        return tech_vulns
    
    def _enrich_vulnerabilities_parallel(
        self,
        vulns: List[VulnerabilityInfo]
    ) -> List[VulnerabilityInfo]:
        """Enrich vulnerabilities with CVE data in parallel."""
        enriched = []
        
        with ThreadPoolExecutor(max_workers=self.request.max_workers) as executor:
            futures = {
                executor.submit(self._enrich_single_vuln, vuln): vuln
                for vuln in vulns
            }
            
            for future in as_completed(futures):
                try:
                    enriched_vuln = future.result()
                    enriched.append(enriched_vuln)
                except Exception as e:
                    original_vuln = futures[future]
                    logger.error(f"Failed to enrich {original_vuln.id}: {e}")
                    enriched.append(original_vuln)  # Keep original
        
        return enriched
    
    def _enrich_vulnerabilities_sequential(
        self,
        vulns: List[VulnerabilityInfo]
    ) -> List[VulnerabilityInfo]:
        """Enrich vulnerabilities with CVE data sequentially."""
        enriched = []
        
        for vuln in vulns:
            try:
                enriched_vuln = self._enrich_single_vuln(vuln)
                enriched.append(enriched_vuln)
            except Exception as e:
                logger.error(f"Failed to enrich {vuln.id}: {e}")
                enriched.append(vuln)  # Keep original
        
        return enriched
    
    def _enrich_single_vuln(self, vuln: VulnerabilityInfo) -> VulnerabilityInfo:
        """Enrich a single vulnerability with CVE data."""
        # Skip if already has CVE data
        if vuln.cve:
            return vuln
        
        # Extract CVE ID from template or title
        cve_id = None
        if vuln.template_id and vuln.template_id.upper().startswith("CVE-"):
            cve_id = vuln.template_id.upper()
        elif "CVE-" in vuln.title.upper():
            matches = re.findall(r'CVE-\d{4}-\d{4,}', vuln.title.upper())
            if matches:
                cve_id = matches[0]
        
        if not cve_id:
            return vuln
        
        # Enrich from CVE database
        cve_info = self.cve_enricher.enrich_by_cve_id(cve_id)
        if cve_info:
            vuln.cve = cve_info
            # Update severity if CVE has higher severity
            if cve_info.cvss_score and cve_info.cvss_score > 0:
                vuln.severity = cve_info.severity
        
        return vuln
    
    def _map_mitre_parallel(
        self,
        vulns: List[VulnerabilityInfo]
    ) -> List[VulnerabilityInfo]:
        """Map vulnerabilities to MITRE framework in parallel."""
        mapped = []
        
        with ThreadPoolExecutor(max_workers=self.request.max_workers) as executor:
            futures = {
                executor.submit(self._map_single_mitre, vuln): vuln
                for vuln in vulns
            }
            
            for future in as_completed(futures):
                try:
                    mapped_vuln = future.result()
                    mapped.append(mapped_vuln)
                except Exception as e:
                    original_vuln = futures[future]
                    logger.error(f"Failed to map MITRE for {original_vuln.id}: {e}")
                    mapped.append(original_vuln)  # Keep original
        
        return mapped
    
    def _map_mitre_sequential(
        self,
        vulns: List[VulnerabilityInfo]
    ) -> List[VulnerabilityInfo]:
        """Map vulnerabilities to MITRE framework sequentially."""
        mapped = []
        
        for vuln in vulns:
            try:
                mapped_vuln = self._map_single_mitre(vuln)
                mapped.append(mapped_vuln)
            except Exception as e:
                logger.error(f"Failed to map MITRE for {vuln.id}: {e}")
                mapped.append(vuln)  # Keep original
        
        return mapped
    
    def _map_single_mitre(self, vuln: VulnerabilityInfo) -> VulnerabilityInfo:
        """Map a single vulnerability to MITRE framework."""
        # Skip if CVE already has MITRE data
        if vuln.cve and vuln.cve.mitre:
            return vuln
        
        # Get CWE IDs from category or CVE
        cwe_ids = None
        if vuln.category != VulnCategory.UNKNOWN:
            cwe_ids = self.mitre_mapper.get_cwe_by_category(vuln.category.value)
        
        # Map to MITRE
        mitre_data = None
        if vuln.cve:
            mitre_data = self.mitre_mapper.map_cve_to_mitre(vuln.cve.cve_id, cwe_ids)
            if mitre_data and vuln.cve:
                vuln.cve.mitre = mitre_data
        elif cwe_ids:
            # Map based on inferred CWE
            mitre_data = self.mitre_mapper.map_cve_to_mitre("", cwe_ids)
            # Create stub CVE with MITRE data
            if mitre_data and not vuln.cve:
                vuln.cve = CVEInfo(
                    cve_id="N/A",
                    severity=vuln.severity,
                    description=vuln.description,
                    mitre=mitre_data
                )
        
        return vuln
    
    def _deduplicate_vulnerabilities(
        self,
        vulns: List[VulnerabilityInfo]
    ) -> List[VulnerabilityInfo]:
        """
        Deduplicate vulnerabilities by ID and matched_at.
        Merge metadata from duplicates.
        """
        seen = {}
        deduplicated = []
        
        for vuln in vulns:
            # Create dedup key
            key = f"{vuln.id}:{vuln.matched_at or 'unknown'}"
            
            if key in seen:
                # Merge with existing
                existing = seen[key]
                # Merge tags
                existing.tags = list(set(existing.tags + vuln.tags))
                # Merge references
                existing.references = list(set(existing.references + vuln.references))
            else:
                seen[key] = vuln
                deduplicated.append(vuln)
        
        logger.info(f"Deduplicated {len(vulns)} to {len(deduplicated)} vulnerabilities")
        return deduplicated
    
    def _calculate_stats(
        self,
        vulns: List[VulnerabilityInfo],
        total_time: float,
        nuclei_time: float,
        enrichment_time: float,
        mitre_time: float
    ) -> VulnScanStats:
        """Calculate vulnerability scan statistics."""
        # Count by severity
        by_severity = {}
        for severity in VulnSeverity:
            count = sum(1 for v in vulns if v.severity == severity)
            if count > 0:
                by_severity[severity.value] = count
        
        # Count by category
        by_category = {}
        for category in VulnCategory:
            count = sum(1 for v in vulns if v.category == category)
            if count > 0:
                by_category[category.value] = count
        
        # Count by source
        by_source = {}
        for vuln in vulns:
            by_source[vuln.source] = by_source.get(vuln.source, 0) + 1
        
        # CVE and MITRE stats
        cves_enriched = sum(1 for v in vulns if v.cve is not None)
        cwes_mapped = sum(1 for v in vulns if v.cve and v.cve.mitre and v.cve.mitre.cwe)
        capecs_mapped = sum(
            len(v.cve.mitre.capec)
            for v in vulns
            if v.cve and v.cve.mitre and v.cve.mitre.capec
        )
        
        # Nuclei stats
        templates_executed = 0
        if self.nuclei:
            templates_executed = self.nuclei.get_templates_count()
        
        return VulnScanStats(
            total_vulnerabilities=len(vulns),
            by_severity=by_severity,
            by_category=by_category,
            by_source=by_source,
            nuclei_scanned=len(self.request.targets) if self.nuclei else 0,
            templates_executed=templates_executed,
            cves_enriched=cves_enriched,
            cwes_mapped=cwes_mapped,
            capecs_mapped=capecs_mapped,
            execution_time=total_time,
            nuclei_time=nuclei_time,
            enrichment_time=enrichment_time,
            mitre_time=mitre_time
        )
