"""
Test configuration and fixtures for vulnerability scanning tests.

Author: BitR1FT (BitR1FT)
Developed by: BitR1FT
Project: UniVex - Month 7
"""

import pytest
from datetime import datetime
from typing import List

from app.recon.vuln_scanning.schemas import (
    VulnScanRequest,
    VulnerabilityInfo,
    CVEInfo,
    CWEInfo,
    CAPECInfo,
    MITREData,
    ScanMode,
    VulnSeverity,
    VulnCategory,
    NucleiConfig,
    CVEEnrichmentConfig,
    MITREConfig,
)


@pytest.fixture
def sample_targets() -> List[str]:
    """Sample target URLs for testing."""
    return [
        "https://example.com",
        "https://test.example.com",
        "http://api.example.com"
    ]


@pytest.fixture
def basic_nuclei_config() -> NucleiConfig:
    """Basic Nuclei configuration for testing."""
    return NucleiConfig(
        severity_filter=[VulnSeverity.CRITICAL, VulnSeverity.HIGH],
        include_tags=["cve", "xss"],
        exclude_tags=["dos"],
        rate_limit=50,
        concurrency=10,
        timeout=5,
        auto_update_templates=False  # Don't update during tests
    )


@pytest.fixture
def sample_vulnerability() -> VulnerabilityInfo:
    """Sample vulnerability information."""
    return VulnerabilityInfo(
        id="nuclei-CVE-2024-1234",
        title="SQL Injection in Login Form",
        description="SQL injection vulnerability allows unauthorized database access",
        severity=VulnSeverity.HIGH,
        category=VulnCategory.SQLI,
        source="nuclei",
        template_id="CVE-2024-1234",
        matched_at="https://example.com/login",
        http_method="POST",
        tags=["sqli", "injection", "database"],
        references=["https://example.com/advisory"],
        remediation="Use parameterized queries"
    )
