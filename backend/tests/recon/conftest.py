"""
Test configuration and fixtures for reconnaissance module tests.
"""

import pytest
import asyncio
from typing import Set, Dict, Any


@pytest.fixture
def sample_domain():
    """Sample domain for testing."""
    return "example.com"


@pytest.fixture
def sample_subdomains() -> Set[str]:
    """Sample set of subdomains for testing."""
    return {
        "example.com",
        "www.example.com",
        "mail.example.com",
        "ftp.example.com",
        "api.example.com"
    }


@pytest.fixture
def sample_whois_data() -> Dict[str, Any]:
    """Sample WHOIS data for testing."""
    return {
        "domain": "example.com",
        "registrar": "Example Registrar Inc.",
        "creation_date": "2020-01-01T00:00:00",
        "expiration_date": "2025-01-01T00:00:00",
        "updated_date": "2024-01-01T00:00:00",
        "name_servers": ["ns1.example.com", "ns2.example.com"],
        "status": ["clientTransferProhibited"],
        "emails": ["admin@example.com"],
        "org": "Example Organization",
        "country": "US"
    }


@pytest.fixture
def sample_dns_results() -> Dict[str, Any]:
    """Sample DNS resolution results for testing."""
    return {
        "domain": "example.com",
        "records": {
            "A": ["93.184.216.34"],
            "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
            "MX": ["10 mail.example.com"],
            "NS": ["ns1.example.com", "ns2.example.com"],
            "TXT": ["v=spf1 -all"]
        },
        "ips": {
            "ipv4": ["93.184.216.34"],
            "ipv6": ["2606:2800:220:1:248:1893:25c8:1946"]
        },
        "errors": []
    }


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for the entire test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()
