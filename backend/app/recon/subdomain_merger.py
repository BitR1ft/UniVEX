"""
Subdomain Merger and Deduplication Module

Merges subdomains from multiple sources and handles deduplication.
Filters wildcard DNS entries and normalizes subdomain names.
"""

import logging
from typing import Set, List
import re

logger = logging.getLogger(__name__)


class SubdomainMerger:
    """Merge and deduplicate subdomains from multiple sources."""

    def __init__(self, target_domain: str):
        """
        Initialize subdomain merger.

        Args:
            target_domain: The target domain for validation
        """
        self.target_domain = target_domain.lower().strip()

    def merge(self, *subdomain_sets: Set[str]) -> Set[str]:
        """
        Merge multiple sets of subdomains and deduplicate.

        Args:
            *subdomain_sets: Variable number of subdomain sets

        Returns:
            Merged and deduplicated set of subdomains
        """
        merged = set()

        for subdomain_set in subdomain_sets:
            if subdomain_set:
                merged.update(subdomain_set)

        # Filter and normalize
        validated = self._validate_subdomains(merged)
        
        logger.info(f"Merged {len(merged)} subdomains into {len(validated)} unique valid subdomains")
        return validated

    def _validate_subdomains(self, subdomains: Set[str]) -> Set[str]:
        """
        Validate and normalize subdomains.

        Args:
            subdomains: Set of subdomains to validate

        Returns:
            Set of valid, normalized subdomains
        """
        validated = set()

        for subdomain in subdomains:
            # Normalize
            subdomain = subdomain.lower().strip()
            
            # Remove trailing dots
            if subdomain.endswith("."):
                subdomain = subdomain[:-1]
            
            # Skip empty strings
            if not subdomain:
                continue
            
            # Skip wildcard entries
            if subdomain.startswith("*"):
                continue
            
            # Validate domain format
            if not self._is_valid_domain(subdomain):
                logger.debug(f"Invalid subdomain format: {subdomain}")
                continue
            
            # Must end with target domain
            if not subdomain.endswith(self.target_domain):
                logger.debug(f"Subdomain doesn't match target domain: {subdomain}")
                continue
            
            validated.add(subdomain)

        return validated

    def _is_valid_domain(self, domain: str) -> bool:
        """
        Validate domain name format.

        Args:
            domain: Domain name to validate

        Returns:
            True if valid, False otherwise
        """
        # Basic domain regex pattern
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        
        if not re.match(pattern, domain):
            return False
        
        # Check length constraints
        if len(domain) > 253:
            return False
        
        # Check label lengths
        labels = domain.split(".")
        for label in labels:
            if len(label) > 63 or len(label) == 0:
                return False
        
        return True

    def filter_wildcards(self, subdomains: Set[str], wildcard_domains: List[str]) -> Set[str]:
        """
        Filter out subdomains that match wildcard patterns.

        Args:
            subdomains: Set of subdomains
            wildcard_domains: List of domains with wildcard DNS

        Returns:
            Filtered set of subdomains
        """
        if not wildcard_domains:
            return subdomains

        filtered = set()

        for subdomain in subdomains:
            is_wildcard = False
            
            for wildcard_domain in wildcard_domains:
                # Check if subdomain matches wildcard pattern
                if subdomain.endswith(wildcard_domain):
                    # Count dots to determine subdomain depth
                    subdomain_depth = subdomain.count(".")
                    wildcard_depth = wildcard_domain.count(".")
                    
                    # If it's one level deeper, it might be a wildcard match
                    if subdomain_depth == wildcard_depth + 1:
                        is_wildcard = True
                        logger.debug(f"Filtered wildcard subdomain: {subdomain}")
                        break
            
            if not is_wildcard:
                filtered.add(subdomain)

        logger.info(f"Filtered {len(subdomains) - len(filtered)} wildcard subdomains")
        return filtered

    def sort_subdomains(self, subdomains: Set[str]) -> List[str]:
        """
        Sort subdomains by depth and alphabetically.

        Args:
            subdomains: Set of subdomains

        Returns:
            Sorted list of subdomains
        """
        # Sort by number of dots (depth) first, then alphabetically
        return sorted(subdomains, key=lambda x: (x.count("."), x))

    def get_root_domains(self, subdomains: Set[str]) -> Set[str]:
        """
        Extract root domains from subdomains.

        Args:
            subdomains: Set of subdomains

        Returns:
            Set of root domains
        """
        root_domains = set()

        for subdomain in subdomains:
            # Get the root domain (last two parts)
            parts = subdomain.split(".")
            if len(parts) >= 2:
                root = ".".join(parts[-2:])
                root_domains.add(root)

        return root_domains
