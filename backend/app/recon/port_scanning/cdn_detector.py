"""
CDN/WAF Detection Module

Detects CDN and WAF providers using:
1. IP range matching (Cloudflare, Akamai, etc.)
2. CNAME-based detection
3. HTTP header analysis
"""
import logging
import ipaddress
from typing import Optional, List, Dict
import httpx

from .schemas import CDNInfo

logger = logging.getLogger(__name__)


class CDNDetector:
    """
    CDN and WAF detection
    """
    
    # CDN IP ranges (simplified - in production, would load from external source)
    CDN_RANGES = {
        'cloudflare': [
            '173.245.48.0/20',
            '103.21.244.0/22',
            '103.22.200.0/22',
            '103.31.4.0/22',
            '141.101.64.0/18',
            '108.162.192.0/18',
            '190.93.240.0/20',
            '188.114.96.0/20',
            '197.234.240.0/22',
            '198.41.128.0/17',
            '162.158.0.0/15',
            '104.16.0.0/13',
            '104.24.0.0/14',
            '172.64.0.0/13',
            '131.0.72.0/22',
        ],
        'akamai': [
            '23.0.0.0/8',
            '104.64.0.0/10',
            '184.24.0.0/13',
            '2.16.0.0/13',
        ],
        'fastly': [
            '151.101.0.0/16',
            '199.232.0.0/16',
        ],
        'incapsula': [
            '45.60.0.0/16',
            '185.11.124.0/22',
        ],
    }
    
    # CNAME patterns for CDN detection
    CNAME_PATTERNS = {
        'cloudflare': ['.cloudflare.com', '.cloudflare.net'],
        'akamai': ['.akamai.net', '.akamaiedge.net', '.edgekey.net'],
        'fastly': ['.fastly.net'],
        'cloudfront': ['.cloudfront.net'],
        'incapsula': ['.incapdns.net'],
        'sucuri': ['.sucuri.net'],
    }
    
    def __init__(self):
        """Initialize CDN detector"""
        self._compile_ip_ranges()
    
    def _compile_ip_ranges(self):
        """Compile IP ranges into network objects"""
        self.compiled_ranges: Dict[str, List[ipaddress.IPv4Network]] = {}
        
        for provider, ranges in self.CDN_RANGES.items():
            networks = []
            for cidr in ranges:
                try:
                    networks.append(ipaddress.ip_network(cidr))
                except ValueError as e:
                    logger.warning(f"Invalid CIDR {cidr} for {provider}: {e}")
            self.compiled_ranges[provider] = networks
    
    def detect_by_ip(self, ip: str) -> Optional[CDNInfo]:
        """
        Detect CDN by IP address range
        
        Args:
            ip: IP address to check
            
        Returns:
            CDNInfo if CDN detected, None otherwise
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            for provider, networks in self.compiled_ranges.items():
                for network in networks:
                    if ip_obj in network:
                        logger.info(f"Detected {provider} CDN for IP {ip}")
                        return CDNInfo(
                            is_cdn=True,
                            provider=provider,
                            detection_method="ip_range",
                            metadata={'ip_range': str(network)}
                        )
            
            return CDNInfo(is_cdn=False)
            
        except ValueError:
            logger.warning(f"Invalid IP address: {ip}")
            return CDNInfo(is_cdn=False)
    
    def detect_by_cname(self, cname: str) -> Optional[CDNInfo]:
        """
        Detect CDN by CNAME record
        
        Args:
            cname: CNAME record value
            
        Returns:
            CDNInfo if CDN detected, None otherwise
        """
        if not cname:
            return CDNInfo(is_cdn=False)
        
        cname_lower = cname.lower()
        
        for provider, patterns in self.CNAME_PATTERNS.items():
            for pattern in patterns:
                if pattern in cname_lower:
                    logger.info(f"Detected {provider} CDN via CNAME: {cname}")
                    return CDNInfo(
                        is_cdn=True,
                        provider=provider,
                        detection_method="cname",
                        metadata={'cname': cname}
                    )
        
        return CDNInfo(is_cdn=False)
    
    async def detect_by_headers(
        self,
        url: str,
        timeout: int = 5
    ) -> Optional[CDNInfo]:
        """
        Detect CDN/WAF by HTTP headers
        
        Args:
            url: URL to check
            timeout: Request timeout
            
        Returns:
            CDNInfo if CDN/WAF detected, None otherwise
        """
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                response = await client.get(url)
                headers = response.headers
                
                # Check for CDN/WAF headers
                cdn_headers = {
                    'cf-ray': 'cloudflare',
                    'x-cdn': 'generic_cdn',
                    'x-amz-cf-id': 'cloudfront',
                    'x-akamai-transformed': 'akamai',
                    'x-cache': 'fastly',
                    'x-sucuri-id': 'sucuri',
                    'x-sucuri-cache': 'sucuri',
                }
                
                for header, provider in cdn_headers.items():
                    if header in headers:
                        logger.info(f"Detected {provider} via header: {header}")
                        return CDNInfo(
                            is_cdn=True,
                            provider=provider,
                            detection_method="header",
                            metadata={'header': header, 'value': headers[header]}
                        )
                
                # Check Server header
                server = headers.get('server', '').lower()
                if 'cloudflare' in server:
                    return CDNInfo(
                        is_cdn=True,
                        provider='cloudflare',
                        detection_method="header",
                        metadata={'header': 'server', 'value': headers.get('server')}
                    )
                
                return CDNInfo(is_cdn=False)
                
        except Exception as e:
            logger.debug(f"Failed to detect CDN via headers for {url}: {str(e)}")
            return CDNInfo(is_cdn=False)
    
    async def detect_comprehensive(
        self,
        ip: str,
        cname: Optional[str] = None,
        url: Optional[str] = None
    ) -> CDNInfo:
        """
        Comprehensive CDN detection using all methods
        
        Args:
            ip: IP address
            cname: CNAME record (optional)
            url: URL for header-based detection (optional)
            
        Returns:
            CDNInfo with detection results
        """
        # Try IP-based detection first (fastest)
        cdn_info = self.detect_by_ip(ip)
        if cdn_info.is_cdn:
            return cdn_info
        
        # Try CNAME-based detection
        if cname:
            cdn_info = self.detect_by_cname(cname)
            if cdn_info.is_cdn:
                return cdn_info
        
        # Try header-based detection
        if url:
            cdn_info = await self.detect_by_headers(url)
            if cdn_info.is_cdn:
                return cdn_info
        
        return CDNInfo(is_cdn=False)
    
    def should_exclude_ip(
        self,
        ip: str,
        exclude_cdn: bool = False
    ) -> bool:
        """
        Determine if an IP should be excluded from scanning
        
        Args:
            ip: IP address
            exclude_cdn: Whether to exclude CDN IPs
            
        Returns:
            True if IP should be excluded
        """
        if not exclude_cdn:
            return False
        
        cdn_info = self.detect_by_ip(ip)
        return cdn_info.is_cdn
