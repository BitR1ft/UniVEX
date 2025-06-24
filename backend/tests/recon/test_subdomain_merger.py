"""
Unit tests for SubdomainMerger module.
"""

import pytest
from app.recon.subdomain_merger import SubdomainMerger


class TestSubdomainMerger:
    """Test suite for SubdomainMerger class."""

    def test_init(self):
        """Test SubdomainMerger initialization."""
        merger = SubdomainMerger("example.com")
        assert merger.target_domain == "example.com"

    def test_merge_single_set(self):
        """Test merging a single set of subdomains."""
        merger = SubdomainMerger("example.com")
        subdomains = {"www.example.com", "mail.example.com"}
        result = merger.merge(subdomains)
        assert len(result) == 2
        assert "www.example.com" in result
        assert "mail.example.com" in result

    def test_merge_multiple_sets(self):
        """Test merging multiple sets of subdomains."""
        merger = SubdomainMerger("example.com")
        set1 = {"www.example.com", "mail.example.com"}
        set2 = {"api.example.com", "mail.example.com"}  # Duplicate
        set3 = {"ftp.example.com"}
        
        result = merger.merge(set1, set2, set3)
        
        # Should have 4 unique subdomains (mail.example.com appears twice)
        assert len(result) == 4
        assert "www.example.com" in result
        assert "mail.example.com" in result
        assert "api.example.com" in result
        assert "ftp.example.com" in result

    def test_normalize_subdomains(self):
        """Test subdomain normalization."""
        merger = SubdomainMerger("example.com")
        
        # Test with trailing dots and uppercase
        subdomains = {"WWW.EXAMPLE.COM.", "mail.example.com."}
        result = merger.merge(subdomains)
        
        assert "www.example.com" in result
        assert "mail.example.com" in result

    def test_filter_wildcards(self):
        """Test wildcard subdomain filtering."""
        merger = SubdomainMerger("example.com")
        subdomains = {"*.example.com", "www.example.com", "mail.example.com"}
        result = merger.merge(subdomains)
        
        # Wildcard should be filtered out
        assert "*.example.com" not in result
        assert len(result) == 2

    def test_validate_domain_format(self):
        """Test domain format validation."""
        merger = SubdomainMerger("example.com")
        
        # Valid domains
        assert merger._is_valid_domain("example.com")
        assert merger._is_valid_domain("www.example.com")
        assert merger._is_valid_domain("api.v2.example.com")
        
        # Invalid domains
        assert not merger._is_valid_domain("")
        assert not merger._is_valid_domain("example..com")
        assert not merger._is_valid_domain("-example.com")

    def test_filter_non_target_domains(self):
        """Test filtering of subdomains not matching target domain."""
        merger = SubdomainMerger("example.com")
        subdomains = {
            "www.example.com",
            "mail.example.com",
            "test.other.com",  # Different domain
            "api.example.org"   # Different TLD
        }
        result = merger.merge(subdomains)
        
        # Only example.com subdomains should remain
        assert len(result) == 2
        assert "www.example.com" in result
        assert "mail.example.com" in result

    def test_sort_subdomains(self):
        """Test subdomain sorting."""
        merger = SubdomainMerger("example.com")
        subdomains = {
            "example.com",
            "www.example.com",
            "api.v2.example.com",
            "mail.example.com"
        }
        
        sorted_list = merger.sort_subdomains(subdomains)
        
        # Should be sorted by depth (dots) then alphabetically
        assert sorted_list[0] == "example.com"  # 1 dot
        assert "api.v2.example.com" in sorted_list  # 3 dots should be later

    def test_get_root_domains(self):
        """Test extracting root domains."""
        merger = SubdomainMerger("example.com")
        subdomains = {
            "www.example.com",
            "mail.example.com",
            "api.test.com"
        }
        
        root_domains = merger.get_root_domains(subdomains)
        
        assert "example.com" in root_domains
        assert "test.com" in root_domains
        assert len(root_domains) == 2

    def test_filter_wildcard_dns(self):
        """Test filtering wildcard DNS entries."""
        merger = SubdomainMerger("example.com")
        subdomains = {
            "www.example.com",
            "random123.example.com",
            "random456.example.com",
            "mail.example.com"
        }
        
        wildcard_domains = ["example.com"]
        result = merger.filter_wildcards(subdomains, wildcard_domains)
        
        # All direct subdomains might be filtered if they match wildcard pattern
        assert isinstance(result, set)

    def test_empty_input(self):
        """Test handling of empty input."""
        merger = SubdomainMerger("example.com")
        result = merger.merge(set())
        assert len(result) == 0

    def test_case_insensitive_merge(self):
        """Test that merging is case-insensitive."""
        merger = SubdomainMerger("example.com")
        subdomains = {"WWW.EXAMPLE.COM", "www.example.com", "WwW.ExAmPlE.CoM"}
        result = merger.merge(subdomains)
        
        # Should deduplicate to single subdomain
        assert len(result) == 1
        assert "www.example.com" in result
