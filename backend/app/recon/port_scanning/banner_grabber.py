"""
Banner Grabber Module

Extracts service banners using raw socket connections
to identify service versions and product information.
"""
import asyncio
import logging
import ssl
from typing import Optional, Dict, List

from .schemas import ServiceInfo

logger = logging.getLogger(__name__)


class BannerGrabber:
    """
    Service banner grabbing using raw sockets
    """
    
    # Protocol-specific probes
    PROBES = {
        21: b"",  # FTP - server sends banner first
        22: b"",  # SSH - server sends banner first
        23: b"",  # Telnet - server sends banner first
        25: b"EHLO banner-grabber\r\n",  # SMTP
        80: b"GET / HTTP/1.0\r\n\r\n",  # HTTP
        110: b"",  # POP3 - server sends banner first
        143: b"",  # IMAP - server sends banner first
        443: b"GET / HTTP/1.0\r\n\r\n",  # HTTPS
        3306: b"",  # MySQL - server sends banner first
        5432: b"",  # PostgreSQL
        6379: b"INFO\r\n",  # Redis
    }
    
    def __init__(self, timeout: int = 5):
        """
        Initialize banner grabber
        
        Args:
            timeout: Socket timeout in seconds
        """
        self.timeout = timeout
    
    async def grab_banner(
        self,
        host: str,
        port: int,
        use_ssl: bool = False
    ) -> Optional[str]:
        """
        Grab banner from a service
        
        Args:
            host: Target host
            port: Target port
            use_ssl: Whether to use SSL/TLS
            
        Returns:
            Banner string or None if failed
        """
        try:
            # Get protocol-specific probe
            probe = self.PROBES.get(port, b"")
            
            # Create connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            # Wrap in SSL if needed
            if use_ssl:
                try:
                    # Create SSL context with minimum TLS 1.2
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2  # Require TLS 1.2 or higher
                    
                    # Get the underlying socket
                    sock = writer.get_extra_info('socket')
                    ssl_context.wrap_socket(
                        sock,
                        server_hostname=host
                    )
                    
                except Exception as e:
                    logger.warning(f"SSL handshake failed for {host}:{port}: {str(e)}")
                    writer.close()
                    await writer.wait_closed()
                    return None
            
            # Send probe if needed
            if probe:
                writer.write(probe)
                await writer.drain()
            
            # Read response
            banner = await asyncio.wait_for(
                reader.read(1024),
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            # Decode banner
            try:
                banner_str = banner.decode('utf-8', errors='ignore').strip()
                if banner_str:
                    logger.info(f"Grabbed banner from {host}:{port}: {banner_str[:100]}")
                    return banner_str
            except Exception as e:
                logger.error(f"Failed to decode banner: {str(e)}")
            
            return None
            
        except asyncio.TimeoutError:
            logger.debug(f"Timeout grabbing banner from {host}:{port}")
            return None
        except ConnectionRefusedError:
            logger.debug(f"Connection refused to {host}:{port}")
            return None
        except Exception as e:
            logger.debug(f"Error grabbing banner from {host}:{port}: {str(e)}")
            return None
    
    async def grab_banners_for_host(
        self,
        host: str,
        ports: List[int]
    ) -> Dict[int, str]:
        """
        Grab banners for multiple ports on a host
        
        Args:
            host: Target host
            ports: List of ports
            
        Returns:
            Dictionary mapping port to banner
        """
        tasks = []
        
        for port in ports:
            # Determine if SSL should be used
            use_ssl = port in [443, 465, 993, 995, 8443]
            tasks.append(self.grab_banner(host, port, use_ssl))
        
        results = await asyncio.gather(*tasks)
        
        # Build port-to-banner mapping
        banner_map = {}
        for port, banner in zip(ports, results):
            if banner:
                banner_map[port] = banner
        
        return banner_map
    
    def extract_version_from_banner(self, banner: str) -> Optional[Dict[str, str]]:
        """
        Extract version information from banner
        
        Args:
            banner: Service banner string
            
        Returns:
            Dictionary with product and version info
        """
        if not banner:
            return None
        
        # Common patterns for version extraction
        patterns = {
            'ssh': r'SSH-([\d.]+)-([^\s]+)',
            'ftp': r'([\w-]+)\s+([\d.]+)',
            'http': r'Server:\s*([^\s/]+)/([\d.]+)',
            'smtp': r'(\w+)\s+ESMTP\s+([^\s]+)',
            'mysql': r'([\d.]+)-MariaDB',
            'redis': r'redis_version:([\d.]+)',
        }
        
        import re
        
        for service, pattern in patterns.items():
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                groups = match.groups()
                if len(groups) >= 2:
                    return {
                        'product': groups[0] if service != 'mysql' else 'MariaDB',
                        'version': groups[1] if service != 'mysql' else groups[0]
                    }
                elif len(groups) == 1:
                    return {
                        'product': service.upper(),
                        'version': groups[0]
                    }
        
        return None
    
    def enrich_service_with_banner(
        self,
        service: ServiceInfo,
        banner: str
    ) -> ServiceInfo:
        """
        Enrich service info with banner data
        
        Args:
            service: ServiceInfo object
            banner: Banner string
            
        Returns:
            Enriched ServiceInfo
        """
        service.banner = banner
        
        # Extract version if not already present
        if not service.version or not service.product:
            version_info = self.extract_version_from_banner(banner)
            if version_info:
                if not service.product:
                    service.product = version_info.get('product')
                if not service.version:
                    service.version = version_info.get('version')
        
        return service
