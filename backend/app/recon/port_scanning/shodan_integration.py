"""
Shodan Integration Module

Provides passive port scanning using Shodan InternetDB API.
InternetDB is free and doesn't require an API key.
"""
import asyncio
import logging
from typing import List, Optional
import httpx

from .schemas import ShodanHostInfo, PortInfo, IPPortScan

logger = logging.getLogger(__name__)


class ShodanScanner:
    """
    Shodan InternetDB integration for passive port scanning
    """
    
    INTERNETDB_URL = "https://internetdb.shodan.io"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Shodan scanner
        
        Args:
            api_key: Shodan API key (optional, not needed for InternetDB)
        """
        self.api_key = api_key
    
    async def query_internetdb(self, ip: str) -> Optional[ShodanHostInfo]:
        """
        Query Shodan InternetDB for an IP address
        
        Args:
            ip: IP address to query
            
        Returns:
            ShodanHostInfo object or None if no data
        """
        url = f"{self.INTERNETDB_URL}/{ip}"
        
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(url)
                
                if response.status_code == 404:
                    logger.debug(f"No Shodan data for {ip}")
                    return None
                
                if response.status_code != 200:
                    logger.warning(f"Shodan API returned status {response.status_code} for {ip}")
                    return None
                
                data = response.json()
                
                host_info = ShodanHostInfo(
                    ip=ip,
                    ports=data.get('ports', []),
                    cpes=data.get('cpes', []),
                    hostnames=data.get('hostnames', []),
                    tags=data.get('tags', []),
                    vulns=data.get('vulns', [])
                )
                
                logger.info(f"Found {len(host_info.ports)} ports for {ip} via Shodan")
                return host_info
                
        except httpx.TimeoutException:
            logger.warning(f"Timeout querying Shodan for {ip}")
            return None
        except Exception as e:
            logger.error(f"Error querying Shodan for {ip}: {str(e)}")
            return None
    
    async def scan_host(self, ip: str) -> IPPortScan:
        """
        Perform passive scan using Shodan InternetDB
        
        Args:
            ip: IP address to scan
            
        Returns:
            IPPortScan object with results
        """
        host_info = await self.query_internetdb(ip)
        
        if not host_info:
            return IPPortScan(
                ip=ip,
                ports=[],
                timestamp=None
            )
        
        # Convert Shodan ports to PortInfo objects
        ports = [
            PortInfo(
                port=port,
                protocol="tcp",
                state="open",
                source="shodan"
            )
            for port in host_info.ports
        ]
        
        return IPPortScan(
            ip=ip,
            ports=ports,
            timestamp=None
        )
    
    async def scan_multiple_hosts(
        self,
        ips: List[str],
        max_concurrent: int = 5
    ) -> List[IPPortScan]:
        """
        Scan multiple hosts using Shodan
        
        Args:
            ips: List of IP addresses
            max_concurrent: Maximum concurrent requests
            
        Returns:
            List of IPPortScan results
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_with_semaphore(ip: str):
            async with semaphore:
                return await self.scan_host(ip)
        
        tasks = [scan_with_semaphore(ip) for ip in ips]
        results = await asyncio.gather(*tasks)
        
        return results
    
    def get_cpes_for_ip(self, host_info: ShodanHostInfo) -> List[str]:
        """
        Get CPEs (Common Platform Enumerations) for a host
        
        Args:
            host_info: Shodan host information
            
        Returns:
            List of CPE identifiers
        """
        return host_info.cpes
    
    def get_vulns_for_ip(self, host_info: ShodanHostInfo) -> List[str]:
        """
        Get known vulnerabilities for a host
        
        Args:
            host_info: Shodan host information
            
        Returns:
            List of CVE identifiers
        """
        return host_info.vulns
