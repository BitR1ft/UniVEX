"""
Certificate Transparency Logs Module

Queries Certificate Transparency logs (crt.sh) to discover subdomains.
Parses CT log responses and extracts unique subdomains.
"""

import logging
from typing import Set
import httpx

logger = logging.getLogger(__name__)


class CertificateTransparency:
    """Certificate Transparency log parser for subdomain discovery."""

    def __init__(self, timeout: float = 30.0):
        """
        Initialize Certificate Transparency module.

        Args:
            timeout: HTTP request timeout in seconds
        """
        self.timeout = timeout
        self.ct_url = "https://crt.sh/"

    async def discover_subdomains(self, domain: str) -> Set[str]:
        """
        Discover subdomains via Certificate Transparency logs.

        Args:
            domain: Target domain

        Returns:
            Set of discovered subdomains
        """
        subdomains = set()

        try:
            logger.info(f"Querying Certificate Transparency logs for {domain}")
            
            # Query crt.sh API
            params = {
                "q": f"%.{domain}",
                "output": "json"
            }

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(self.ct_url, params=params)
                response.raise_for_status()

                ct_data = response.json()
                logger.info(f"Retrieved {len(ct_data)} certificate entries for {domain}")

                # Extract subdomains from certificates
                for entry in ct_data:
                    if "name_value" in entry:
                        names = entry["name_value"].split("\n")
                        for name in names:
                            name = name.strip().lower()
                            
                            # Filter out wildcards and invalid entries
                            if name and not name.startswith("*") and name.endswith(domain):
                                subdomains.add(name)

                logger.info(f"Discovered {len(subdomains)} unique subdomains from CT logs")

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error querying CT logs for {domain}: {e.response.status_code}")
        except httpx.RequestError as e:
            logger.error(f"Request error querying CT logs for {domain}: {str(e)}")
        except Exception as e:
            logger.error(f"Error processing CT logs for {domain}: {str(e)}")

        return subdomains

    async def discover_with_wildcard_filter(self, domain: str, include_wildcards: bool = False) -> Set[str]:
        """
        Discover subdomains with optional wildcard inclusion.

        Args:
            domain: Target domain
            include_wildcards: Whether to include wildcard entries

        Returns:
            Set of discovered subdomains
        """
        subdomains = set()

        try:
            logger.info(f"Querying CT logs for {domain} (wildcards: {include_wildcards})")
            
            params = {
                "q": f"%.{domain}",
                "output": "json"
            }

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(self.ct_url, params=params)
                response.raise_for_status()

                ct_data = response.json()

                for entry in ct_data:
                    if "name_value" in entry:
                        names = entry["name_value"].split("\n")
                        for name in names:
                            name = name.strip().lower()
                            
                            if include_wildcards:
                                # Include wildcards but process them
                                if name.startswith("*."):
                                    name = name[2:]  # Remove *.
                                    
                            else:
                                # Skip wildcards
                                if name.startswith("*"):
                                    continue
                            
                            if name and name.endswith(domain):
                                subdomains.add(name)

                logger.info(f"Discovered {len(subdomains)} subdomains from CT logs")

        except Exception as e:
            logger.error(f"Error in CT log discovery for {domain}: {str(e)}")

        return subdomains
