"""
Favicon Hasher Module - Month 5

Generates hashes of website favicons for fingerprinting.
Supports MD5, SHA256, and Shodan's MurmurHash3 (mmh3).
"""

import hashlib
from typing import Optional
import logging
import httpx
from urllib.parse import urljoin, urlparse

from .schemas import FaviconInfo

logger = logging.getLogger(__name__)


# Try to import mmh3 for Shodan-compatible hashing
try:
    import mmh3
    MMH3_AVAILABLE = True
except ImportError:
    MMH3_AVAILABLE = False
    logger.warning("mmh3 not available. Install with: pip install mmh3")


class FaviconHasher:
    """
    Favicon hash generator for website fingerprinting.
    
    Generates multiple hash types:
    - MD5: Fast, widely used
    - SHA256: More secure
    - MurmurHash3: Compatible with Shodan favicon search
    """
    
    def __init__(self, timeout: int = 10):
        """
        Initialize favicon hasher.
        
        Args:
            timeout: Download timeout in seconds
        """
        self.timeout = timeout
    
    async def hash_favicon(self, url: str) -> Optional[FaviconInfo]:
        """
        Download and hash favicon for a URL.
        
        Args:
            url: Base URL of the website
            
        Returns:
            FaviconInfo with hash values
        """
        try:
            # Try common favicon locations
            favicon_urls = self._get_favicon_urls(url)
            
            for favicon_url in favicon_urls:
                favicon_data = await self._download_favicon(favicon_url)
                
                if favicon_data:
                    return self._generate_hashes(favicon_url, favicon_data)
            
            logger.debug(f"No favicon found for {url}")
            return None
            
        except Exception as e:
            logger.error(f"Favicon hashing failed for {url}: {e}")
            return None
    
    def _get_favicon_urls(self, base_url: str) -> list:
        """
        Generate list of common favicon URLs to try.
        
        Args:
            base_url: Base website URL
            
        Returns:
            List of potential favicon URLs
        """
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        return [
            urljoin(base, '/favicon.ico'),
            urljoin(base, '/favicon.png'),
            urljoin(base, '/apple-touch-icon.png'),
            urljoin(base, '/apple-touch-icon-precomposed.png'),
        ]
    
    async def _download_favicon(self, url: str) -> Optional[bytes]:
        """
        Download favicon from URL.
        
        Args:
            url: Favicon URL
            
        Returns:
            Favicon binary data or None
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                response = await client.get(url)
                
                # Check for successful response
                if response.status_code == 200:
                    content_type = response.headers.get('content-type', '')
                    
                    # Verify it's an image
                    if 'image' in content_type or url.endswith(('.ico', '.png', '.jpg', '.jpeg', '.gif')):
                        return response.content
                
                return None
                
        except Exception as e:
            logger.debug(f"Failed to download favicon from {url}: {e}")
            return None
    
    def _generate_hashes(self, url: str, data: bytes) -> FaviconInfo:
        """
        Generate hash values for favicon data.
        
        Args:
            url: Favicon URL
            data: Favicon binary data
            
        Returns:
            FaviconInfo with hash values
        """
        # Calculate MD5
        md5_hash = hashlib.md5(data, usedforsecurity=False).hexdigest()
        
        # Calculate SHA256
        sha256_hash = hashlib.sha256(data).hexdigest()
        
        # Calculate MurmurHash3 (Shodan format)
        mmh3_hash = None
        if MMH3_AVAILABLE:
            try:
                # Shodan uses base64-encoded favicon with mmh3
                import base64
                b64_data = base64.b64encode(data)
                mmh3_hash = mmh3.hash(b64_data)
            except Exception as e:
                logger.debug(f"MMH3 hashing failed: {e}")
        
        return FaviconInfo(
            url=url,
            md5=md5_hash,
            sha256=sha256_hash,
            mmh3=mmh3_hash,
            size_bytes=len(data)
        )
    
    def search_shodan_by_favicon(self, mmh3_hash: int) -> str:
        """
        Generate Shodan search query for favicon hash.
        
        Args:
            mmh3_hash: MurmurHash3 hash value
            
        Returns:
            Shodan search query string
        """
        return f"http.favicon.hash:{mmh3_hash}"
