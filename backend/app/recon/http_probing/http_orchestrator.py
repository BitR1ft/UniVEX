"""
HTTP Probe Orchestrator - Month 5

Coordinates HTTP probing workflow:
1. HTTP probing with httpx
2. TLS/SSL inspection
3. Technology detection (httpx + Wappalyzer)
4. Favicon hashing
5. Result aggregation
"""

import asyncio
from typing import List
from datetime import datetime
import logging

from .http_probe import HttpProbe
from .tls_inspector import TLSInspector
from .tech_detector import TechDetector
from .wappalyzer_wrapper import WappalyzerWrapper
from .favicon_hasher import FaviconHasher
from .schemas import (
    HttpProbeRequest,
    HttpProbeResult,
    BaseURLInfo,
    HttpProbeStats
)

logger = logging.getLogger(__name__)


class HttpProbeOrchestrator:
    """
    Orchestrates comprehensive HTTP probing workflow.
    
    Combines multiple tools and techniques:
    - httpx for HTTP probing
    - TLS inspection for certificates
    - Technology detection (httpx + Wappalyzer)
    - Favicon hashing
    - Security header analysis
    """
    
    def __init__(self, request: HttpProbeRequest):
        """
        Initialize orchestrator.
        
        Args:
            request: HTTP probe request configuration
        """
        self.request = request
        
        # Initialize components
        self.http_probe = HttpProbe(
            timeout=request.timeout,
            follow_redirects=request.follow_redirects,
            max_redirects=request.max_redirects,
            threads=request.threads
        )
        
        self.tls_inspector = TLSInspector(timeout=request.timeout)
        self.tech_detector = TechDetector()
        self.wappalyzer = WappalyzerWrapper(timeout=request.timeout)
        self.favicon_hasher = FaviconHasher(timeout=request.timeout)
    
    async def run(self) -> HttpProbeResult:
        """
        Execute complete HTTP probing workflow.
        
        Returns:
            HttpProbeResult with all findings
        """
        start_time = datetime.utcnow()
        logger.info(f"Starting HTTP probe for {len(self.request.targets)} targets")
        
        try:
            # Step 1: HTTP probing (parallelized)
            logger.info("Step 1: HTTP probing...")
            results = await self._probe_all_targets()
            
            # Step 2: Enrich with TLS inspection (if enabled and HTTPS)
            if self.request.tls_inspection:
                logger.info("Step 2: TLS inspection...")
                results = await self._enrich_with_tls(results)
            
            # Step 3: Enrich with technology detection
            if self.request.tech_detection:
                logger.info("Step 3: Technology detection...")
                results = await self._enrich_with_tech_detection(results)
            
            # Step 4: Favicon hashing (if enabled)
            if self.request.favicon_hash:
                logger.info("Step 4: Favicon hashing...")
                results = await self._enrich_with_favicon(results)
            
            # Calculate statistics
            stats = self._calculate_stats(results, start_time)
            
            completed_time = datetime.utcnow()
            
            return HttpProbeResult(
                request=self.request,
                results=results,
                stats=stats,
                started_at=start_time,
                completed_at=completed_time
            )
            
        except Exception as e:
            logger.error(f"HTTP probe orchestration failed: {e}")
            raise
    
    async def _probe_all_targets(self) -> List[BaseURLInfo]:
        """Probe all target URLs with httpx"""
        results = []
        
        # Ensure URLs have scheme
        targets = [self._normalize_url(url) for url in self.request.targets]
        
        # Use httpx bulk probing for efficiency
        results = await self.http_probe.probe_urls(targets)
        
        return results
    
    def _normalize_url(self, url: str) -> str:
        """Ensure URL has a scheme"""
        if not url.startswith(('http://', 'https://')):
            # Default to https
            return f'https://{url}'
        return url
    
    async def _enrich_with_tls(self, results: List[BaseURLInfo]) -> List[BaseURLInfo]:
        """Add TLS certificate information to HTTPS results"""
        tasks = []
        
        for result in results:
            if result.scheme == 'https' and result.success:
                task = self._inspect_tls_for_result(result)
                tasks.append(task)
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        return results
    
    async def _inspect_tls_for_result(self, result: BaseURLInfo):
        """Inspect TLS for a single result"""
        try:
            tls_info = await self.tls_inspector.inspect_tls(result.host, result.port)
            if tls_info:
                result.tls = tls_info
        except Exception as e:
            logger.debug(f"TLS inspection failed for {result.host}: {e}")
    
    async def _enrich_with_tech_detection(self, results: List[BaseURLInfo]) -> List[BaseURLInfo]:
        """Add technology detection to results"""
        for result in results:
            if not result.success:
                continue
            
            try:
                # Get technologies from httpx (already in result)
                httpx_techs = result.technologies or []
                
                # Get technologies from Wappalyzer (if enabled)
                wappalyzer_techs = []
                if self.request.wappalyzer:
                    wappalyzer_techs = await self.wappalyzer.detect(result.url)
                
                # Merge technologies
                result.technologies = self.tech_detector.merge_technologies(
                    httpx_techs,
                    wappalyzer_techs
                )
                
            except Exception as e:
                logger.debug(f"Technology detection failed for {result.url}: {e}")
        
        return results
    
    async def _enrich_with_favicon(self, results: List[BaseURLInfo]) -> List[BaseURLInfo]:
        """Add favicon hashes to results"""
        tasks = []
        
        for result in results:
            if result.success:
                task = self._hash_favicon_for_result(result)
                tasks.append(task)
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        return results
    
    async def _hash_favicon_for_result(self, result: BaseURLInfo):
        """Hash favicon for a single result"""
        try:
            favicon_info = await self.favicon_hasher.hash_favicon(result.url)
            if favicon_info:
                result.favicon = favicon_info
        except Exception as e:
            logger.debug(f"Favicon hashing failed for {result.url}: {e}")
    
    def _calculate_stats(self, results: List[BaseURLInfo], start_time: datetime) -> HttpProbeStats:
        """Calculate statistics from results"""
        total = len(results)
        successful = sum(1 for r in results if r.success)
        failed = total - successful
        
        https_count = sum(1 for r in results if r.scheme == 'https')
        http_count = sum(1 for r in results if r.scheme == 'http')
        
        redirect_count = sum(r.redirect_count for r in results)
        
        # Count unique technologies
        all_technologies = set()
        tech_count = 0
        for r in results:
            for tech in r.technologies:
                all_technologies.add(tech.name)
                tech_count += 1
        
        # Count CDN detections
        cdn_count = sum(1 for r in results if r.cdn_detected)
        
        # Count TLS
        tls_count = sum(1 for r in results if r.tls is not None)
        
        # Calculate average response time
        response_times = [r.response_time_ms for r in results if r.response_time_ms]
        avg_response_time = sum(response_times) / len(response_times) if response_times else None
        
        # Calculate duration
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        return HttpProbeStats(
            total_targets=total,
            successful_probes=successful,
            failed_probes=failed,
            https_count=https_count,
            http_count=http_count,
            redirect_count=redirect_count,
            technologies_found=tech_count,
            unique_technologies=len(all_technologies),
            cdn_count=cdn_count,
            tls_count=tls_count,
            avg_response_time_ms=avg_response_time,
            duration_seconds=duration
        )

# Backward-compatible alias
HttpOrchestrator = HttpProbeOrchestrator
