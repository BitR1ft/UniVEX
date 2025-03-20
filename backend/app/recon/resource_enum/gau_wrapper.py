"""
GAU (Get All URLs) Wrapper

Python wrapper for GAU to fetch historical URLs from multiple providers.

Author: BitR1FT (BitR1FT)
Developed by: BitR1FT
"""

import subprocess
import logging
import asyncio
from typing import List, Optional
from urllib.parse import urlparse, parse_qs
import httpx

from .schemas import EndpointInfo, ParameterInfo, EndpointCategory, ParameterType

logger = logging.getLogger(__name__)


class GAUWrapper:
    """
    Wrapper for GAU (Get All URLs) tool.
    
    GAU fetches known URLs from multiple sources:
    - Wayback Machine
    - Common Crawl
    - AlienVault OTX
    - URLScan.io
    """
    
    def __init__(
        self,
        providers: Optional[List[str]] = None,
        max_urls: int = 1000,
        verify_urls: bool = True,
        timeout: int = 300
    ):
        """
        Initialize GAU wrapper.
        
        Args:
            providers: List of providers to use (wayback, commoncrawl, otx, urlscan)
            max_urls: Maximum number of URLs to fetch
            verify_urls: Verify URL liveness with httpx
            timeout: Timeout in seconds
        """
        self.providers = providers or ["wayback", "commoncrawl", "otx", "urlscan"]
        self.max_urls = max_urls
        self.verify_urls = verify_urls
        self.timeout = timeout
        
        # Verify GAU is installed
        self._verify_installation()
    
    def _verify_installation(self) -> None:
        """Verify that GAU is installed and accessible."""
        try:
            result = subprocess.run(
                ["gau", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"GAU version: {result.stdout.strip()}")
            else:
                logger.warning("GAU not found or not working properly")
        except FileNotFoundError:
            logger.error("GAU is not installed or not in PATH")
        except Exception as e:
            logger.error(f"Error verifying GAU installation: {e}")
    
    async def fetch_urls(self, domains: List[str]) -> List[EndpointInfo]:
        """
        Fetch historical URLs using GAU.
        
        Args:
            domains: List of domains to query
            
        Returns:
            List of discovered endpoints
        """
        logger.info(f"Fetching URLs from GAU for {len(domains)} domain(s)")
        
        endpoints = []
        
        for domain in domains[:10]:  # Limit to 10 domains
            domain_endpoints = await self._fetch_domain_urls(domain)
            endpoints.extend(domain_endpoints)
            
            if len(endpoints) >= self.max_urls:
                break
        
        # Limit to max_urls
        endpoints = endpoints[:self.max_urls]
        
        # Verify URLs if requested
        if self.verify_urls and endpoints:
            endpoints = await self._verify_endpoint_liveness(endpoints)
        
        logger.info(f"GAU discovered {len(endpoints)} endpoints")
        return endpoints
    
    async def _fetch_domain_urls(self, domain: str) -> List[EndpointInfo]:
        """
        Fetch URLs for a single domain.
        
        Args:
            domain: Domain to query
            
        Returns:
            List of endpoints
        """
        # Build GAU command
        cmd = self._build_command(domain)
        
        try:
            # Execute GAU
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout
            )
            
            if process.returncode != 0:
                logger.error(f"GAU failed for {domain}: {stderr.decode()}")
                return []
            
            # Parse output
            endpoints = self._parse_output(stdout.decode())
            
            logger.debug(f"GAU found {len(endpoints)} URLs for {domain}")
            return endpoints
            
        except asyncio.TimeoutError:
            logger.error(f"GAU timeout for {domain} after {self.timeout}s")
            return []
        except Exception as e:
            logger.error(f"GAU execution error for {domain}: {e}")
            return []
    
    def _build_command(self, domain: str) -> List[str]:
        """
        Build GAU command.
        
        Args:
            domain: Domain to query
            
        Returns:
            Command as list of arguments
        """
        cmd = ["gau"]
        
        # Add providers
        if "wayback" not in self.providers:
            cmd.append("--blacklist")
            cmd.append("wayback")
        if "commoncrawl" not in self.providers:
            cmd.append("--blacklist")
            cmd.append("commoncrawl")
        if "otx" not in self.providers:
            cmd.append("--blacklist")
            cmd.append("otx")
        if "urlscan" not in self.providers:
            cmd.append("--blacklist")
            cmd.append("urlscan")
        
        # Configuration
        cmd.extend([
            "--threads", "5",
            "--subs",  # Include subdomains
            "--o", "-",  # Output to stdout
        ])
        
        # Add domain
        cmd.append(domain)
        
        logger.debug(f"GAU command: {' '.join(cmd)}")
        return cmd
    
    def _parse_output(self, output: str) -> List[EndpointInfo]:
        """
        Parse GAU output.
        
        Args:
            output: Raw GAU output
            
        Returns:
            List of parsed endpoints
        """
        endpoints = []
        seen_urls = set()
        
        for line in output.strip().split('\n'):
            url = line.strip()
            
            if not url or url in seen_urls or not url.startswith('http'):
                continue
            
            seen_urls.add(url)
            
            try:
                # Extract parameters
                parameters = self._extract_parameters(url)
                
                # Create endpoint info
                endpoint = EndpointInfo(
                    url=url,
                    path=self._extract_path(url),
                    method="GET",  # GAU only provides GET URLs
                    parameters=parameters,
                    source="gau",
                    category=EndpointCategory.UNKNOWN  # Will be classified later
                )
                
                endpoints.append(endpoint)
                
                if len(endpoints) >= self.max_urls:
                    break
                    
            except Exception as e:
                logger.debug(f"Error parsing URL: {e}")
                continue
        
        return endpoints
    
    def _extract_path(self, url: str) -> str:
        """Extract path from URL."""
        try:
            parsed = urlparse(url)
            path = parsed.path
            if parsed.query:
                path += f"?{parsed.query}"
            return path or "/"
        except Exception:
            return "/"
    
    def _extract_parameters(self, url: str) -> List[ParameterInfo]:
        """
        Extract query parameters from URL.
        
        Args:
            url: URL to parse
            
        Returns:
            List of parameters
        """
        parameters = []
        
        try:
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query, keep_blank_values=True)
                for name, values in params.items():
                    value = values[0] if values else None
                    
                    param = ParameterInfo(
                        name=name,
                        type=ParameterType.UNKNOWN,  # Will be inferred later
                        location="query",
                        value=value
                    )
                    parameters.append(param)
        except Exception as e:
            logger.debug(f"Error extracting parameters: {e}")
        
        return parameters
    
    async def _verify_endpoint_liveness(self, endpoints: List[EndpointInfo]) -> List[EndpointInfo]:
        """
        Verify endpoint liveness using httpx.
        
        Args:
            endpoints: List of endpoints to verify
            
        Returns:
            List of live endpoints with status codes
        """
        logger.info(f"Verifying liveness of {len(endpoints)} endpoints")
        
        live_endpoints = []
        
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            tasks = []
            for endpoint in endpoints[:100]:  # Limit verification to 100
                tasks.append(self._check_endpoint(client, endpoint))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, EndpointInfo) and result.is_live:
                    live_endpoints.append(result)
        
        # Add remaining unverified endpoints
        if len(endpoints) > 100:
            live_endpoints.extend(endpoints[100:])
        
        logger.info(f"Found {len(live_endpoints)} live endpoints")
        return live_endpoints
    
    async def _check_endpoint(self, client: httpx.AsyncClient, endpoint: EndpointInfo) -> EndpointInfo:
        """
        Check if a single endpoint is live.
        
        Args:
            client: HTTP client
            endpoint: Endpoint to check
            
        Returns:
            Updated endpoint with liveness info
        """
        try:
            response = await client.head(endpoint.url, timeout=5)
            endpoint.is_live = response.status_code < 500
            endpoint.status_code = response.status_code
            
            # Try to get content length
            content_length = response.headers.get('content-length')
            if content_length:
                endpoint.content_length = int(content_length)
                
        except Exception as e:
            logger.debug(f"Error checking {endpoint.url}: {e}")
            endpoint.is_live = False
        
        return endpoint
    
    async def detect_http_methods(self, endpoints: List[EndpointInfo]) -> List[EndpointInfo]:
        """
        Detect available HTTP methods using OPTIONS requests.
        
        Args:
            endpoints: List of endpoints
            
        Returns:
            Endpoints with detected methods
        """
        logger.info(f"Detecting HTTP methods for {len(endpoints)} endpoints")
        
        async with httpx.AsyncClient(timeout=10) as client:
            for endpoint in endpoints[:50]:  # Limit to 50 endpoints
                try:
                    response = await client.options(endpoint.url, timeout=5)
                    allow_header = response.headers.get('allow', '')
                    
                    if allow_header:
                        methods = [m.strip() for m in allow_header.split(',')]
                        # Use the first non-GET method if available
                        for method in methods:
                            if method != 'GET' and method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                                endpoint.method = method
                                break
                                
                except Exception as e:
                    logger.debug(f"Error detecting methods for {endpoint.url}: {e}")
        
        return endpoints
