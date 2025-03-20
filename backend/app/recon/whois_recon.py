"""
WHOIS Reconnaissance Module

Performs WHOIS lookups with retry logic and exponential backoff.
Extracts registrar information, creation/expiration dates, and name servers.
"""

import asyncio
import logging
from typing import Dict, Optional, Any
from datetime import datetime
import whois

logger = logging.getLogger(__name__)


class WhoisRecon:
    """WHOIS lookup with retry logic and comprehensive data parsing."""

    def __init__(self, max_retries: int = 3, retry_delay: float = 2.0):
        """
        Initialize WHOIS reconnaissance module.

        Args:
            max_retries: Maximum number of retry attempts
            retry_delay: Initial delay between retries (exponential backoff)
        """
        self.max_retries = max_retries
        self.retry_delay = retry_delay

    async def lookup(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Perform WHOIS lookup for a domain with retry logic.

        Args:
            domain: Domain name to look up

        Returns:
            Dictionary containing WHOIS information or None if failed
        """
        for attempt in range(self.max_retries):
            try:
                logger.info(f"WHOIS lookup for {domain} (attempt {attempt + 1}/{self.max_retries})")
                
                # Perform WHOIS lookup in executor to avoid blocking
                loop = asyncio.get_event_loop()
                whois_data = await loop.run_in_executor(None, whois.whois, domain)
                
                if whois_data:
                    parsed_data = self._parse_whois_data(whois_data, domain)
                    logger.info(f"WHOIS lookup successful for {domain}")
                    return parsed_data
                else:
                    logger.warning(f"WHOIS lookup returned empty data for {domain}")
                    
            except Exception as e:
                logger.error(f"WHOIS lookup failed for {domain} (attempt {attempt + 1}): {str(e)}")
                
                if attempt < self.max_retries - 1:
                    # Exponential backoff
                    delay = self.retry_delay * (2 ** attempt)
                    logger.info(f"Retrying in {delay} seconds...")
                    await asyncio.sleep(delay)
                else:
                    logger.error(f"WHOIS lookup failed for {domain} after {self.max_retries} attempts")
                    return None

        return None

    def _parse_whois_data(self, whois_data: Any, domain: str) -> Dict[str, Any]:
        """
        Parse WHOIS data into a structured format.

        Args:
            whois_data: Raw WHOIS data object
            domain: Domain name

        Returns:
            Dictionary containing parsed WHOIS information
        """
        result = {
            "domain": domain,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "name_servers": [],
            "status": [],
            "emails": [],
            "org": None,
            "country": None,
        }

        try:
            # Parse registrar
            if hasattr(whois_data, 'registrar'):
                result["registrar"] = whois_data.registrar

            # Parse dates
            result["creation_date"] = self._parse_date(whois_data.creation_date)
            result["expiration_date"] = self._parse_date(whois_data.expiration_date)
            result["updated_date"] = self._parse_date(whois_data.updated_date)

            # Parse name servers
            if hasattr(whois_data, 'name_servers') and whois_data.name_servers:
                name_servers = whois_data.name_servers
                if isinstance(name_servers, list):
                    result["name_servers"] = [ns.lower() for ns in name_servers if ns]
                elif isinstance(name_servers, str):
                    result["name_servers"] = [name_servers.lower()]

            # Parse status
            if hasattr(whois_data, 'status') and whois_data.status:
                status = whois_data.status
                if isinstance(status, list):
                    result["status"] = status
                elif isinstance(status, str):
                    result["status"] = [status]

            # Parse emails
            if hasattr(whois_data, 'emails') and whois_data.emails:
                emails = whois_data.emails
                if isinstance(emails, list):
                    result["emails"] = emails
                elif isinstance(emails, str):
                    result["emails"] = [emails]

            # Parse organization
            if hasattr(whois_data, 'org'):
                result["org"] = whois_data.org

            # Parse country
            if hasattr(whois_data, 'country'):
                result["country"] = whois_data.country

        except Exception as e:
            logger.error(f"Error parsing WHOIS data for {domain}: {str(e)}")

        return result

    def _parse_date(self, date_value: Any) -> Optional[str]:
        """
        Parse date value to ISO format string.

        Args:
            date_value: Date value from WHOIS data

        Returns:
            ISO formatted date string or None
        """
        if not date_value:
            return None

        try:
            # Handle list of dates (take the first one)
            if isinstance(date_value, list):
                date_value = date_value[0] if date_value else None

            # Convert datetime to ISO string
            if isinstance(date_value, datetime):
                return date_value.isoformat()
            elif isinstance(date_value, str):
                return date_value

        except Exception as e:
            logger.debug(f"Error parsing date {date_value}: {str(e)}")

        return None
