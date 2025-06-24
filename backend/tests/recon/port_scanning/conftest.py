"""
Test fixtures for port scanning tests
"""
import pytest
from app.recon.port_scanning.schemas import (
    PortScanRequest,
    ScanMode,
    ScanType,
    PortInfo,
    ServiceInfo,
    CDNInfo
)


@pytest.fixture
def sample_port_scan_request():
    """Sample port scan request"""
    return PortScanRequest(
        targets=["192.168.1.1", "192.168.1.2"],
        mode=ScanMode.ACTIVE,
        scan_type=ScanType.SYN,
        top_ports=100,
        service_detection=True,
        banner_grab=True
    )


@pytest.fixture
def sample_port_info():
    """Sample port information"""
    return PortInfo(
        port=80,
        protocol="tcp",
        state="open",
        source="naabu"
    )


@pytest.fixture
def sample_service_info():
    """Sample service information"""
    return ServiceInfo(
        port=80,
        protocol="tcp",
        service_name="http",
        product="nginx",
        version="1.18.0"
    )


@pytest.fixture
def sample_cdn_info():
    """Sample CDN information"""
    return CDNInfo(
        is_cdn=True,
        provider="cloudflare",
        detection_method="ip_range"
    )
