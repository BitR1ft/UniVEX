"""
DNS Resolution Module

Comprehensive DNS resolver supporting all major record types:
A, AAAA, MX, NS, TXT, CNAME, SOA records.
Implements timeout handling, error recovery, and IP organization.
"""

import asyncio
import logging
from typing import Dict, List, Set, Optional, Any
import dns.resolver
import dns.exception
from collections import defaultdict

logger = logging.getLogger(__name__)


class DNSResolver:
    """Comprehensive DNS resolver with support for all major record types."""

    # DNS record types to query
    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    def __init__(self, timeout: float = 5.0, retries: int = 2, nameservers: List[str] = None):
        """
        Initialize DNS resolver.

        Args:
            timeout: DNS query timeout in seconds
            retries: Number of retry attempts
            nameservers: Optional list of DNS nameservers to use
        """
        self.timeout = timeout
        self.retries = retries
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout * (retries + 1)
        
        if nameservers:
            self.resolver.nameservers = nameservers

    async def resolve_all(self, domain: str) -> Dict[str, Any]:
        """
        Resolve all DNS record types for a domain.

        Args:
            domain: Domain name to resolve

        Returns:
            Dictionary containing all DNS records
        """
        logger.info(f"Resolving all DNS records for {domain}")

        results = {
            "domain": domain,
            "records": {},
            "ips": {
                "ipv4": [],
                "ipv6": []
            },
            "errors": []
        }

        # Resolve each record type concurrently
        tasks = []
        for record_type in self.RECORD_TYPES:
            task = self._resolve_record_type(domain, record_type)
            tasks.append(task)

        # Wait for all queries to complete
        records = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for record_type, data in zip(self.RECORD_TYPES, records):
            if isinstance(data, Exception):
                logger.debug(f"Error resolving {record_type} for {domain}: {str(data)}")
                results["errors"].append(f"{record_type}: {str(data)}")
            elif data:
                results["records"][record_type] = data
                
                # Extract IPs
                if record_type == "A" and data:
                    results["ips"]["ipv4"].extend(data)
                elif record_type == "AAAA" and data:
                    results["ips"]["ipv6"].extend(data)

        logger.info(f"Resolved {len(results['records'])} record types for {domain}")
        return results

    async def _resolve_record_type(self, domain: str, record_type: str) -> Optional[List[str]]:
        """
        Resolve a specific DNS record type.

        Args:
            domain: Domain name
            record_type: DNS record type (A, AAAA, MX, etc.)

        Returns:
            List of record values or None if failed
        """
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                self._query_dns,
                domain,
                record_type
            )

            if answers:
                records = self._parse_records(answers, record_type)
                if records:
                    logger.debug(f"{record_type} records for {domain}: {len(records)} found")
                    return records

        except dns.resolver.NXDOMAIN:
            logger.debug(f"Domain {domain} does not exist (NXDOMAIN)")
        except dns.resolver.NoAnswer:
            logger.debug(f"No {record_type} records for {domain}")
        except dns.resolver.Timeout:
            logger.warning(f"DNS timeout resolving {record_type} for {domain}")
        except Exception as e:
            logger.debug(f"Error resolving {record_type} for {domain}: {str(e)}")

        return None

    def _query_dns(self, domain: str, record_type: str):
        """
        Perform DNS query (blocking operation).

        Args:
            domain: Domain name
            record_type: DNS record type

        Returns:
            DNS answer object
        """
        return self.resolver.resolve(domain, record_type)

    def _parse_records(self, answers, record_type: str) -> List[str]:
        """
        Parse DNS answers based on record type.

        Args:
            answers: DNS answer object
            record_type: Type of DNS record

        Returns:
            List of parsed record values
        """
        records = []

        try:
            if record_type == "A":
                records = [str(rdata) for rdata in answers]
            
            elif record_type == "AAAA":
                records = [str(rdata) for rdata in answers]
            
            elif record_type == "MX":
                records = [f"{rdata.preference} {rdata.exchange}" for rdata in answers]
            
            elif record_type == "NS":
                records = [str(rdata) for rdata in answers]
            
            elif record_type == "TXT":
                records = [str(rdata) for rdata in answers]
            
            elif record_type == "CNAME":
                records = [str(rdata) for rdata in answers]
            
            elif record_type == "SOA":
                for rdata in answers:
                    soa_str = f"mname={rdata.mname} rname={rdata.rname} serial={rdata.serial}"
                    records.append(soa_str)

        except Exception as e:
            logger.error(f"Error parsing {record_type} records: {str(e)}")

        return records

    async def resolve_subdomains(self, subdomains: Set[str]) -> Dict[str, Dict[str, Any]]:
        """
        Resolve DNS records for multiple subdomains concurrently.

        Args:
            subdomains: Set of subdomains to resolve

        Returns:
            Dictionary mapping subdomains to their DNS records
        """
        logger.info(f"Resolving DNS for {len(subdomains)} subdomains")

        results = {}
        tasks = []
        subdomain_list = list(subdomains)

        # Create tasks for all subdomains
        for subdomain in subdomain_list:
            task = self.resolve_all(subdomain)
            tasks.append(task)

        # Resolve concurrently with progress logging
        batch_size = 50
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            batch_subdomains = subdomain_list[i:i + batch_size]
            
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            
            for subdomain, result in zip(batch_subdomains, batch_results):
                if isinstance(result, Exception):
                    logger.error(f"Error resolving {subdomain}: {str(result)}")
                    results[subdomain] = {"error": str(result)}
                else:
                    results[subdomain] = result
            
            logger.info(f"Resolved {min(i + batch_size, len(tasks))}/{len(tasks)} subdomains")

        return results

    def organize_ips(self, dns_results: Dict[str, Dict[str, Any]]) -> Dict[str, List[str]]:
        """
        Organize IP addresses and map them to subdomains.

        Args:
            dns_results: DNS resolution results

        Returns:
            Dictionary mapping IPs to list of subdomains
        """
        ip_mapping = defaultdict(list)

        for subdomain, data in dns_results.items():
            if "ips" in data:
                # Map IPv4 addresses
                for ip in data["ips"].get("ipv4", []):
                    ip_mapping[ip].append(subdomain)
                
                # Map IPv6 addresses
                for ip in data["ips"].get("ipv6", []):
                    ip_mapping[ip].append(subdomain)

        logger.info(f"Organized {len(ip_mapping)} unique IP addresses")
        return dict(ip_mapping)

    async def resolve_single_type(self, domain: str, record_type: str) -> Optional[List[str]]:
        """
        Resolve a single DNS record type for a domain.

        Args:
            domain: Domain name
            record_type: DNS record type

        Returns:
            List of record values or None
        """
        return await self._resolve_record_type(domain, record_type)
