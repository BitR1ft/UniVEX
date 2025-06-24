"""
Tests for Port Scanning Schemas
"""
import pytest
from pydantic import ValidationError
from app.recon.port_scanning.schemas import (
    PortScanRequest,
    ScanMode,
    ScanType,
    PortInfo,
    ServiceInfo,
    CDNInfo,
    IPPortScan,
    PortScanResult
)


class TestSchemas:
    """Test Pydantic schemas"""
    
    def test_scan_mode_enum(self):
        """Test ScanMode enum values"""
        assert ScanMode.ACTIVE.value == "active"
        assert ScanMode.PASSIVE.value == "passive"
        assert ScanMode.HYBRID.value == "hybrid"
    
    def test_scan_type_enum(self):
        """Test ScanType enum values"""
        assert ScanType.SYN.value == "syn"
        assert ScanType.CONNECT.value == "connect"
    
    def test_port_scan_request_valid(self):
        """Test valid PortScanRequest"""
        request = PortScanRequest(
            targets=["192.168.1.1"],
            mode=ScanMode.ACTIVE,
            scan_type=ScanType.SYN,
            top_ports=1000
        )
        
        assert request.targets == ["192.168.1.1"]
        assert request.mode == ScanMode.ACTIVE
        assert request.scan_type == ScanType.SYN
        assert request.top_ports == 1000
    
    def test_port_scan_request_defaults(self):
        """Test PortScanRequest default values"""
        request = PortScanRequest(
            targets=["example.com"]
        )
        
        assert request.mode == ScanMode.ACTIVE
        assert request.scan_type == ScanType.SYN
        assert request.top_ports == 1000
        assert request.rate_limit == 1000
        assert request.threads == 25
        assert request.timeout == 10
        assert request.exclude_cdn is False
        assert request.service_detection is True
        assert request.banner_grab is True
    
    def test_port_scan_request_invalid_top_ports(self):
        """Test PortScanRequest with invalid top_ports"""
        with pytest.raises(ValidationError):
            PortScanRequest(
                targets=["192.168.1.1"],
                top_ports=99999  # Too high
            )
    
    def test_port_scan_request_invalid_threads(self):
        """Test PortScanRequest with invalid threads"""
        with pytest.raises(ValidationError):
            PortScanRequest(
                targets=["192.168.1.1"],
                threads=999  # Too high
            )
    
    def test_service_info(self):
        """Test ServiceInfo schema"""
        service = ServiceInfo(
            port=80,
            protocol="tcp",
            service_name="http",
            product="nginx",
            version="1.18.0"
        )
        
        assert service.port == 80
        assert service.protocol == "tcp"
        assert service.service_name == "http"
        assert service.product == "nginx"
        assert service.version == "1.18.0"
    
    def test_cdn_info(self):
        """Test CDNInfo schema"""
        cdn = CDNInfo(
            is_cdn=True,
            provider="cloudflare",
            detection_method="ip_range"
        )
        
        assert cdn.is_cdn is True
        assert cdn.provider == "cloudflare"
        assert cdn.detection_method == "ip_range"
    
    def test_port_info(self):
        """Test PortInfo schema"""
        port = PortInfo(
            port=443,
            protocol="tcp",
            state="open",
            source="naabu"
        )
        
        assert port.port == 443
        assert port.protocol == "tcp"
        assert port.state == "open"
        assert port.source == "naabu"
    
    def test_ip_port_scan(self):
        """Test IPPortScan schema"""
        scan = IPPortScan(
            ip="192.168.1.1",
            ports=[
                PortInfo(port=80, protocol="tcp", state="open", source="naabu"),
                PortInfo(port=443, protocol="tcp", state="open", source="naabu")
            ]
        )
        
        assert scan.ip == "192.168.1.1"
        assert len(scan.ports) == 2
        assert scan.ports[0].port == 80
    
    def test_port_scan_result(self):
        """Test PortScanResult schema"""
        result = PortScanResult(
            targets=[],
            total_ips_scanned=5,
            total_ports_found=25,
            total_services_identified=20,
            cdn_ips_found=2,
            scan_mode=ScanMode.ACTIVE,
            scan_duration=45.5,
            timestamp="2024-01-01T00:00:00"
        )
        
        assert result.total_ips_scanned == 5
        assert result.total_ports_found == 25
        assert result.scan_mode == ScanMode.ACTIVE
        assert result.scan_duration == 45.5
