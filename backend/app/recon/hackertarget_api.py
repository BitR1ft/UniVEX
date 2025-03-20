"""
HackerTarget API Integration Module

Performs passive subdomain discovery using HackerTarget API.
Implements rate limiting and API error handling.
"""

import asyncio
import logging
from typing import Set
import httpx

logger = logging.getLogger(__name__)


class HackerTargetAPI:
    """HackerTarget API client for passive subdomain discovery."""

    def __init__(self, api_key: str = None, timeout: float = 30.0, rate_limit_delay: float = 1.0):
        """
        Initialize HackerTarget API client.

        Args:
            api_key: Optional API key for increased rate limits
            timeout: HTTP request timeout in seconds
            rate_limit_delay: Delay between requests to respect rate limits
        """
        self.api_key = api_key
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self.base_url = "https://api.hackertarget.com"

    async def discover_subdomains(self, domain: str) -> Set[str]:
        """
        Discover subdomains using HackerTarget API.

        Args:
            domain: Target domain

        Returns:
            Set of discovered subdomains
        """
        subdomains = set()

        try:
            logger.info(f"Querying HackerTarget API for {domain}")
            
            # Build API endpoint
            endpoint = f"{self.base_url}/hostsearch/"
            params = {"q": domain}
            
            if self.api_key:
                params["apikey"] = self.api_key

            # Rate limiting
            await asyncio.sleep(self.rate_limit_delay)

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(endpoint, params=params)
                
                if response.status_code == 200:
                    text = response.text.strip()
                    
                    # Check for error messages
                    if "error" in text.lower():
                        logger.warning(f"HackerTarget API error: {text}")
                        return subdomains
                    
                    # Parse response (format: subdomain,ip)
                    lines = text.split("\n")
                    for line in lines:
                        if line and "," in line:
                            subdomain = line.split(",")[0].strip().lower()
                            if subdomain and subdomain.endswith(domain):
                                subdomains.add(subdomain)
                    
                    logger.info(f"Discovered {len(subdomains)} subdomains from HackerTarget")
                    
                elif response.status_code == 429:
                    logger.warning(f"HackerTarget rate limit exceeded for {domain}")
                else:
                    logger.error(f"HackerTarget API returned status {response.status_code}")

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error querying HackerTarget for {domain}: {e.response.status_code}")
        except httpx.RequestError as e:
            logger.error(f"Request error querying HackerTarget for {domain}: {str(e)}")
        except Exception as e:
            logger.error(f"Error querying HackerTarget for {domain}: {str(e)}")

        return subdomains

    async def reverse_dns_lookup(self, ip_address: str) -> Set[str]:
        """
        Perform reverse DNS lookup using HackerTarget.

        Args:
            ip_address: IP address to lookup

        Returns:
            Set of hostnames associated with the IP
        """
        hostnames = set()

        try:
            logger.info(f"Reverse DNS lookup for {ip_address}")
            
            endpoint = f"{self.base_url}/reversedns/"
            params = {"q": ip_address}
            
            if self.api_key:
                params["apikey"] = self.api_key

            await asyncio.sleep(self.rate_limit_delay)

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(endpoint, params=params)
                
                if response.status_code == 200:
                    text = response.text.strip()
                    
                    if "error" not in text.lower():
                        lines = text.split("\n")
                        for line in lines:
                            hostname = line.strip().lower()
                            if hostname:
                                hostnames.add(hostname)
                        
                        logger.info(f"Found {len(hostnames)} hostnames for IP {ip_address}")

        except Exception as e:
            logger.error(f"Error in reverse DNS lookup for {ip_address}: {str(e)}")

        return hostnames
