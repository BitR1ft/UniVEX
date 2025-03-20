"""
Domain Discovery Orchestrator

Main module that coordinates all reconnaissance activities:
- WHOIS lookup
- Certificate Transparency
- HackerTarget API
- Subdomain merging and deduplication
- DNS resolution
"""

import asyncio
import logging
from typing import Dict, Optional, Any
from datetime import datetime
import json

from .whois_recon import WhoisRecon
from .ct_logs import CertificateTransparency
from .hackertarget_api import HackerTargetAPI
from .subdomain_merger import SubdomainMerger
from .dns_resolver import DNSResolver

logger = logging.getLogger(__name__)


class DomainDiscovery:
    """
    Orchestrates complete domain discovery workflow.
    
    Performs WHOIS lookup, subdomain enumeration from multiple sources,
    deduplication, and comprehensive DNS resolution.
    """

    def __init__(
        self,
        domain: str,
        hackertarget_api_key: Optional[str] = None,
        dns_nameservers: Optional[list] = None
    ):
        """
        Initialize domain discovery.

        Args:
            domain: Target domain
            hackertarget_api_key: Optional HackerTarget API key
            dns_nameservers: Optional list of DNS nameservers
        """
        self.domain = domain.lower().strip()
        
        # Initialize modules
        self.whois = WhoisRecon()
        self.ct_logs = CertificateTransparency()
        self.hackertarget = HackerTargetAPI(api_key=hackertarget_api_key)
        self.merger = SubdomainMerger(target_domain=self.domain)
        self.dns_resolver = DNSResolver(nameservers=dns_nameservers)
        
        # Results storage
        self.results = {
            "domain": self.domain,
            "timestamp": None,
            "whois": None,
            "subdomains": [],
            "dns_records": {},
            "ip_mapping": {},
            "statistics": {},
            "duration": 0
        }

    async def run(self) -> Dict[str, Any]:
        """
        Execute complete domain discovery workflow.

        Returns:
            Dictionary containing all discovery results
        """
        start_time = datetime.now()
        self.results["timestamp"] = start_time.isoformat()
        
        logger.info(f"Starting domain discovery for {self.domain}")

        try:
            # Step 1: WHOIS lookup
            await self._whois_lookup()

            # Step 2: Subdomain discovery
            await self._discover_subdomains()

            # Step 3: DNS resolution
            await self._resolve_dns()

            # Step 4: IP organization
            self._organize_ips()

            # Calculate statistics
            self._calculate_statistics()

        except Exception as e:
            logger.error(f"Error in domain discovery for {self.domain}: {str(e)}")
            self.results["error"] = str(e)

        # Calculate duration
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        self.results["duration"] = duration

        logger.info(f"Domain discovery completed in {duration:.2f} seconds")
        return self.results

    async def _whois_lookup(self):
        """Perform WHOIS lookup."""
        logger.info("Step 1: WHOIS lookup")
        
        try:
            whois_data = await self.whois.lookup(self.domain)
            self.results["whois"] = whois_data
            
            if whois_data:
                logger.info(f"WHOIS data retrieved for {self.domain}")
            else:
                logger.warning(f"WHOIS lookup failed for {self.domain}")
                
        except Exception as e:
            logger.error(f"WHOIS lookup error: {str(e)}")
            self.results["whois"] = {"error": str(e)}

    async def _discover_subdomains(self):
        """Discover subdomains from multiple sources."""
        logger.info("Step 2: Subdomain discovery")

        # Run all discovery methods concurrently
        tasks = [
            self.ct_logs.discover_subdomains(self.domain),
            self.hackertarget.discover_subdomains(self.domain),
        ]

        # Add the main domain to results
        subdomains_from_sources = [
            {self.domain}  # Always include the main domain
        ]

        try:
            # Wait for all discovery tasks
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Subdomain discovery error: {str(result)}")
                elif isinstance(result, set):
                    subdomains_from_sources.append(result)

            # Merge and deduplicate
            all_subdomains = self.merger.merge(*subdomains_from_sources)
            
            # Sort subdomains
            sorted_subdomains = self.merger.sort_subdomains(all_subdomains)
            self.results["subdomains"] = sorted_subdomains
            
            logger.info(f"Discovered {len(sorted_subdomains)} unique subdomains")

        except Exception as e:
            logger.error(f"Subdomain discovery error: {str(e)}")
            self.results["subdomains"] = [self.domain]

    async def _resolve_dns(self):
        """Resolve DNS records for all discovered subdomains."""
        logger.info("Step 3: DNS resolution")

        try:
            subdomains_set = set(self.results["subdomains"])
            dns_results = await self.dns_resolver.resolve_subdomains(subdomains_set)
            self.results["dns_records"] = dns_results
            
            logger.info(f"DNS resolution completed for {len(dns_results)} subdomains")

        except Exception as e:
            logger.error(f"DNS resolution error: {str(e)}")
            self.results["dns_records"] = {}

    def _organize_ips(self):
        """Organize IP addresses and create IP-to-subdomain mapping."""
        logger.info("Step 4: IP organization")

        try:
            ip_mapping = self.dns_resolver.organize_ips(self.results["dns_records"])
            self.results["ip_mapping"] = ip_mapping
            
            logger.info(f"Organized {len(ip_mapping)} unique IP addresses")

        except Exception as e:
            logger.error(f"IP organization error: {str(e)}")
            self.results["ip_mapping"] = {}

    def _calculate_statistics(self):
        """Calculate discovery statistics."""
        try:
            stats = {
                "total_subdomains": len(self.results["subdomains"]),
                "resolved_subdomains": len([d for d in self.results["dns_records"].values() if "ips" in d]),
                "total_ips": len(self.results["ip_mapping"]),
                "ipv4_count": 0,
                "ipv6_count": 0,
                "record_types": {}
            }

            # Count IP versions
            for subdomain, data in self.results["dns_records"].items():
                if "ips" in data:
                    stats["ipv4_count"] += len(data["ips"].get("ipv4", []))
                    stats["ipv6_count"] += len(data["ips"].get("ipv6", []))

            # Count record types
            for subdomain, data in self.results["dns_records"].items():
                if "records" in data:
                    for record_type in data["records"]:
                        stats["record_types"][record_type] = stats["record_types"].get(record_type, 0) + 1

            self.results["statistics"] = stats
            logger.info(f"Statistics: {stats}")

        except Exception as e:
            logger.error(f"Error calculating statistics: {str(e)}")

    def export_json(self, filepath: str):
        """
        Export results to JSON file.

        Args:
            filepath: Path to output JSON file
        """
        try:
            with open(filepath, 'w') as f:
                json.dump(self.results, f, indent=2)
            
            logger.info(f"Results exported to {filepath}")

        except Exception as e:
            logger.error(f"Error exporting results to JSON: {str(e)}")

    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of discovery results.

        Returns:
            Dictionary containing summary information
        """
        return {
            "domain": self.domain,
            "timestamp": self.results.get("timestamp"),
            "duration": self.results.get("duration"),
            "statistics": self.results.get("statistics", {}),
            "whois_available": self.results.get("whois") is not None,
        }

# Backward-compatible alias
DomainDiscoveryOrchestrator = DomainDiscovery
