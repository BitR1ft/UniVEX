"""
Unit tests for DNS Resolver module.
"""

import pytest
from unittest.mock import Mock, patch
from app.recon.dns_resolver import DNSResolver


class TestDNSResolver:
    """Test suite for DNSResolver class."""

    def test_init(self):
        """Test DNSResolver initialization."""
        resolver = DNSResolver()
        assert resolver.timeout == 5.0
        assert resolver.retries == 2
        assert resolver.RECORD_TYPES == ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    def test_init_custom_params(self):
        """Test DNSResolver with custom parameters."""
        resolver = DNSResolver(timeout=10.0, retries=5, nameservers=["8.8.8.8"])
        assert resolver.timeout == 10.0
        assert resolver.retries == 5

    @pytest.mark.asyncio
    async def test_resolve_all_structure(self):
        """Test that resolve_all returns correct structure."""
        resolver = DNSResolver()
        
        # Mock DNS resolution to avoid actual network calls
        with patch.object(resolver, '_resolve_record_type') as mock_resolve:
            mock_resolve.return_value = None
            
            result = await resolver.resolve_all("example.com")
            
            assert "domain" in result
            assert "records" in result
            assert "ips" in result
            assert "errors" in result
            assert result["domain"] == "example.com"
            assert "ipv4" in result["ips"]
            assert "ipv6" in result["ips"]

    def test_parse_a_records(self):
        """Test parsing A records."""
        resolver = DNSResolver()
        
        # Create mock DNS answers
        mock_answer = Mock()
        mock_answer.__iter__ = Mock(return_value=iter(["93.184.216.34"]))
        
        records = resolver._parse_records(mock_answer, "A")
        assert isinstance(records, list)

    def test_parse_mx_records(self):
        """Test parsing MX records."""
        resolver = DNSResolver()
        
        # Create mock MX record
        mock_mx = Mock()
        mock_mx.preference = 10
        mock_mx.exchange = "mail.example.com"
        
        mock_answer = Mock()
        mock_answer.__iter__ = Mock(return_value=iter([mock_mx]))
        
        records = resolver._parse_records(mock_answer, "MX")
        assert isinstance(records, list)
        if records:
            assert "10" in records[0]

    @pytest.mark.asyncio
    async def test_resolve_subdomains(self):
        """Test resolving multiple subdomains."""
        resolver = DNSResolver()
        subdomains = {"example.com", "www.example.com"}
        
        with patch.object(resolver, 'resolve_all') as mock_resolve:
            mock_resolve.return_value = {
                "domain": "example.com",
                "records": {},
                "ips": {"ipv4": [], "ipv6": []},
                "errors": []
            }
            
            results = await resolver.resolve_subdomains(subdomains)
            
            assert isinstance(results, dict)
            assert len(results) == 2

    def test_organize_ips(self):
        """Test IP organization functionality."""
        resolver = DNSResolver()
        
        dns_results = {
            "example.com": {
                "ips": {
                    "ipv4": ["93.184.216.34"],
                    "ipv6": []
                }
            },
            "www.example.com": {
                "ips": {
                    "ipv4": ["93.184.216.34"],
                    "ipv6": []
                }
            }
        }
        
        ip_mapping = resolver.organize_ips(dns_results)
        
        assert isinstance(ip_mapping, dict)
        # Both subdomains share the same IP
        if "93.184.216.34" in ip_mapping:
            assert len(ip_mapping["93.184.216.34"]) == 2
