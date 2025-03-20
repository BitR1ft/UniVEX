"""
Port Scan Orchestrator

Main workflow coordinator for port scanning that integrates:
- Active scanning (Naabu)
- Passive scanning (Shodan)
- Service detection (Nmap + IANA)
- Banner grabbing
- CDN detection
"""
import asyncio
import logging
from typing import List, Dict, Optional
from datetime import datetime
import json

from .schemas import (
    PortScanRequest,
    PortScanResult,
    IPPortScan,
    ScanMode
)
from .port_scan import PortScanner
from .service_detection import ServiceDetector
from .banner_grabber import BannerGrabber
from .cdn_detector import CDNDetector
from .shodan_integration import ShodanScanner

logger = logging.getLogger(__name__)


class PortScanOrchestrator:
    """
    Orchestrates the complete port scanning workflow
    """
    
    def __init__(self, request: PortScanRequest):
        """
        Initialize orchestrator with scan request
        
        Args:
            request: PortScanRequest configuration
        """
        self.request = request
        self.results: List[IPPortScan] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        
        # Initialize components
        self.port_scanner = PortScanner(
            scan_type=request.scan_type,
            top_ports=request.top_ports,
            custom_ports=request.custom_ports,
            port_range=request.port_range,
            rate_limit=request.rate_limit,
            threads=request.threads,
            timeout=request.timeout
        )
        
        self.service_detector = ServiceDetector()
        self.banner_grabber = BannerGrabber(timeout=5)
        self.cdn_detector = CDNDetector()
        self.shodan_scanner = ShodanScanner(api_key=request.shodan_api_key)
    
    async def run(self) -> PortScanResult:
        """
        Execute complete port scanning workflow
        
        Returns:
            PortScanResult with comprehensive scan data
        """
        self.start_time = datetime.now()
        logger.info(f"Starting port scan for {len(self.request.targets)} targets")
        
        try:
            # Step 1: Filter CDN IPs if requested
            targets = await self._filter_cdn_targets()
            
            # Step 2: Perform port scanning based on mode
            if self.request.mode == ScanMode.ACTIVE:
                scan_results = await self._active_scan(targets)
            elif self.request.mode == ScanMode.PASSIVE:
                scan_results = await self._passive_scan(targets)
            else:  # HYBRID
                scan_results = await self._hybrid_scan(targets)
            
            # Step 3: Service detection
            if self.request.service_detection:
                scan_results = await self._detect_services(scan_results)
            
            # Step 4: Banner grabbing
            if self.request.banner_grab:
                scan_results = await self._grab_banners(scan_results)
            
            # Step 5: CDN detection for all IPs
            scan_results = await self._detect_cdn(scan_results)
            
            self.results = scan_results
            self.end_time = datetime.now()
            
            # Build final result
            return self._build_result()
            
        except Exception as e:
            logger.error(f"Error in port scan orchestration: {str(e)}")
            self.end_time = datetime.now()
            return self._build_result()
    
    async def _filter_cdn_targets(self) -> List[str]:
        """Filter out CDN IPs if requested"""
        if not self.request.exclude_cdn:
            return self.request.targets
        
        filtered = []
        for target in self.request.targets:
            if not self.cdn_detector.should_exclude_ip(target, True):
                filtered.append(target)
            else:
                logger.info(f"Excluding CDN IP: {target}")
        
        logger.info(f"Filtered {len(self.request.targets) - len(filtered)} CDN IPs")
        return filtered
    
    async def _active_scan(self, targets: List[str]) -> List[IPPortScan]:
        """Perform active port scanning with Naabu"""
        logger.info(f"Performing active scan on {len(targets)} targets")
        return await self.port_scanner.scan_multiple_hosts(targets, parallel=True)
    
    async def _passive_scan(self, targets: List[str]) -> List[IPPortScan]:
        """Perform passive port scanning with Shodan"""
        logger.info(f"Performing passive scan on {len(targets)} targets")
        return await self.shodan_scanner.scan_multiple_hosts(targets)
    
    async def _hybrid_scan(self, targets: List[str]) -> List[IPPortScan]:
        """Perform both active and passive scanning and merge results"""
        logger.info(f"Performing hybrid scan on {len(targets)} targets")
        
        # Run both scans concurrently
        active_results, passive_results = await asyncio.gather(
            self._active_scan(targets),
            self._passive_scan(targets)
        )
        
        # Merge results
        return self._merge_scan_results(active_results, passive_results)
    
    def _merge_scan_results(
        self,
        active: List[IPPortScan],
        passive: List[IPPortScan]
    ) -> List[IPPortScan]:
        """Merge active and passive scan results"""
        # Create IP lookup for passive results
        passive_lookup = {r.ip: r for r in passive}
        
        merged = []
        
        for active_scan in active:
            ip = active_scan.ip
            
            # Merge with passive data if available
            if ip in passive_lookup:
                passive_scan = passive_lookup[ip]
                
                # Combine ports, avoiding duplicates
                port_map = {p.port: p for p in active_scan.ports}
                
                for passive_port in passive_scan.ports:
                    if passive_port.port not in port_map:
                        port_map[passive_port.port] = passive_port
                
                active_scan.ports = list(port_map.values())
            
            merged.append(active_scan)
        
        return merged
    
    async def _detect_services(
        self,
        scan_results: List[IPPortScan]
    ) -> List[IPPortScan]:
        """Perform service detection on all scanned ports"""
        logger.info("Performing service detection")
        
        for result in scan_results:
            if result.ports:
                result.ports = await self.service_detector.enrich_ports_with_services(
                    result.ip,
                    result.ports
                )
        
        return scan_results
    
    async def _grab_banners(
        self,
        scan_results: List[IPPortScan]
    ) -> List[IPPortScan]:
        """Grab banners for all services"""
        logger.info("Grabbing service banners")
        
        for result in scan_results:
            if not result.ports:
                continue
            
            # Get banners for all ports
            port_numbers = [p.port for p in result.ports]
            banners = await self.banner_grabber.grab_banners_for_host(
                result.ip,
                port_numbers
            )
            
            # Enrich services with banner data
            for port_info in result.ports:
                if port_info.port in banners and port_info.service:
                    self.banner_grabber.enrich_service_with_banner(
                        port_info.service,
                        banners[port_info.port]
                    )
        
        return scan_results
    
    async def _detect_cdn(
        self,
        scan_results: List[IPPortScan]
    ) -> List[IPPortScan]:
        """Detect CDN for all scanned IPs"""
        logger.info("Detecting CDN providers")
        
        for result in scan_results:
            cdn_info = self.cdn_detector.detect_by_ip(result.ip)
            result.cdn_info = cdn_info
        
        return scan_results
    
    def _build_result(self) -> PortScanResult:
        """Build final PortScanResult"""
        total_ports = sum(len(r.ports) for r in self.results)
        total_services = sum(
            1 for r in self.results
            for p in r.ports
            if p.service and p.service.service_name
        )
        cdn_count = sum(1 for r in self.results if r.cdn_info and r.cdn_info.is_cdn)
        
        duration = 0
        if self.start_time and self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
        
        stats = {
            'targets_scanned': len(self.results),
            'total_ports_found': total_ports,
            'services_identified': total_services,
            'cdn_ips': cdn_count,
            'scan_mode': self.request.mode.value,
        }
        
        return PortScanResult(
            targets=self.results,
            total_ips_scanned=len(self.results),
            total_ports_found=total_ports,
            total_services_identified=total_services,
            cdn_ips_found=cdn_count,
            scan_mode=self.request.mode,
            scan_duration=duration,
            timestamp=self.start_time.isoformat() if self.start_time else datetime.now().isoformat(),
            statistics=stats
        )
    
    def export_json(self, filepath: str):
        """Export results to JSON file"""
        result = self._build_result()
        
        with open(filepath, 'w') as f:
            json.dump(result.model_dump(), f, indent=2)
        
        logger.info(f"Exported results to {filepath}")
    
    def get_summary(self) -> Dict:
        """Get scan summary"""
        result = self._build_result()
        
        return {
            'total_ips_scanned': result.total_ips_scanned,
            'total_ports_found': result.total_ports_found,
            'services_identified': result.total_services_identified,
            'cdn_ips_found': result.cdn_ips_found,
            'scan_duration': f"{result.scan_duration:.2f}s",
            'scan_mode': result.scan_mode.value,
        }
