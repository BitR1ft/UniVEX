"""
Tests for graph data ingestion.
"""

import pytest
from app.graph.ingestion import GraphIngestion


class TestDomainDiscoveryIngestion:
    """Tests for domain discovery data ingestion."""
    
    def test_ingest_domain_discovery(self, mock_neo4j_client, sample_domain_data):
        """Test ingesting domain discovery data."""
        ingestion = GraphIngestion(mock_neo4j_client)
        
        stats = ingestion.ingest_domain_discovery(
            sample_domain_data,
            user_id='user123',
            project_id='proj456'
        )
        
        # Verify statistics
        assert stats['domains'] == 1
        assert stats['subdomains'] == 2
        assert stats['ips'] == 3  # 2 from www, 1 from api
        assert stats['dns_records'] > 0
        assert stats['relationships'] > 0
        
        # Verify node creation calls
        assert mock_neo4j_client.create_node.call_count > 0
    
    def test_ingest_domain_discovery_no_domain(self, mock_neo4j_client):
        """Test ingesting domain discovery data without domain name."""
        ingestion = GraphIngestion(mock_neo4j_client)
        
        stats = ingestion.ingest_domain_discovery(
            {'timestamp': '2024-01-01'},
            user_id='user123',
            project_id='proj456'
        )
        
        # Should return empty stats
        assert stats['domains'] == 0
        assert stats['subdomains'] == 0


class TestPortScanIngestion:
    """Tests for port scan data ingestion."""
    
    def test_ingest_port_scan(self, mock_neo4j_client, sample_port_scan_data):
        """Test ingesting port scan data."""
        ingestion = GraphIngestion(mock_neo4j_client)
        
        stats = ingestion.ingest_port_scan(
            sample_port_scan_data,
            user_id='user123',
            project_id='proj456'
        )
        
        # Verify statistics
        assert stats['ips'] == 1
        assert stats['ports'] == 2
        assert stats['services'] == 2
        assert stats['relationships'] > 0
    
    def test_ingest_port_scan_empty(self, mock_neo4j_client):
        """Test ingesting empty port scan data."""
        ingestion = GraphIngestion(mock_neo4j_client)
        
        stats = ingestion.ingest_port_scan(
            {'scanned_ips': []},
            user_id='user123',
            project_id='proj456'
        )
        
        assert stats['ips'] == 0
        assert stats['ports'] == 0


class TestHttpProbeIngestion:
    """Tests for HTTP probe data ingestion."""
    
    def test_ingest_http_probe(self, mock_neo4j_client, sample_http_probe_data):
        """Test ingesting HTTP probe data."""
        ingestion = GraphIngestion(mock_neo4j_client)
        
        stats = ingestion.ingest_http_probe(
            sample_http_probe_data,
            user_id='user123',
            project_id='proj456'
        )
        
        # Verify statistics
        assert stats['base_urls'] == 1
        assert stats['technologies'] == 2
        assert stats['headers'] == 3
        assert stats['certificates'] == 1
        assert stats['relationships'] > 0
    
    def test_ingest_http_probe_no_tls(self, mock_neo4j_client):
        """Test ingesting HTTP probe data without TLS certificate."""
        ingestion = GraphIngestion(mock_neo4j_client)
        
        data = {
            'probed_urls': [
                {
                    'url': 'http://example.com',
                    'status_code': 200,
                    'technologies': [],
                    'headers': {}
                }
            ]
        }
        
        stats = ingestion.ingest_http_probe(
            data,
            user_id='user123',
            project_id='proj456'
        )
        
        assert stats['base_urls'] == 1
        assert stats['certificates'] == 0


class TestResourceEnumerationIngestion:
    """Tests for resource enumeration data ingestion."""
    
    def test_ingest_resource_enumeration(self, mock_neo4j_client, sample_resource_enum_data):
        """Test ingesting resource enumeration data."""
        ingestion = GraphIngestion(mock_neo4j_client)
        
        stats = ingestion.ingest_resource_enumeration(
            sample_resource_enum_data,
            user_id='user123',
            project_id='proj456'
        )
        
        # Verify statistics
        assert stats['endpoints'] == 2
        assert stats['parameters'] == 3
        assert stats['relationships'] > 0
    
    def test_ingest_resource_enumeration_empty(self, mock_neo4j_client):
        """Test ingesting empty resource enumeration data."""
        ingestion = GraphIngestion(mock_neo4j_client)
        
        stats = ingestion.ingest_resource_enumeration(
            {'endpoints': []},
            user_id='user123',
            project_id='proj456'
        )
        
        assert stats['endpoints'] == 0
        assert stats['parameters'] == 0


class TestVulnerabilityScanIngestion:
    """Tests for vulnerability scan data ingestion."""
    
    def test_ingest_vulnerability_scan(self, mock_neo4j_client, sample_vulnerability_data):
        """Test ingesting vulnerability scan data."""
        ingestion = GraphIngestion(mock_neo4j_client)
        
        stats = ingestion.ingest_vulnerability_scan(
            sample_vulnerability_data,
            user_id='user123',
            project_id='proj456'
        )
        
        # Verify statistics
        assert stats['vulnerabilities'] == 2
        assert stats['cves'] == 1
        assert stats['relationships'] > 0
    
    def test_ingest_vulnerability_scan_no_cves(self, mock_neo4j_client):
        """Test ingesting vulnerability scan data without CVEs."""
        ingestion = GraphIngestion(mock_neo4j_client)
        
        data = {
            'vulnerabilities': [
                {
                    'name': 'Test Vuln',
                    'severity': 'low',
                    'source': 'nuclei',
                    'cve_ids': []
                }
            ]
        }
        
        stats = ingestion.ingest_vulnerability_scan(
            data,
            user_id='user123',
            project_id='proj456'
        )
        
        assert stats['vulnerabilities'] == 1
        assert stats['cves'] == 0


class TestMitreDataIngestion:
    """Tests for MITRE data ingestion."""
    
    def test_ingest_mitre_data(self, mock_neo4j_client, sample_mitre_data):
        """Test ingesting MITRE data."""
        ingestion = GraphIngestion(mock_neo4j_client)
        
        stats = ingestion.ingest_mitre_data(
            sample_mitre_data,
            user_id='user123',
            project_id='proj456'
        )
        
        # Verify statistics
        assert stats['cwe'] == 1
        assert stats['capec'] == 1
        assert stats['relationships'] > 0
    
    def test_ingest_mitre_data_empty(self, mock_neo4j_client):
        """Test ingesting empty MITRE data."""
        ingestion = GraphIngestion(mock_neo4j_client)
        
        stats = ingestion.ingest_mitre_data(
            {'cwe_mappings': []},
            user_id='user123',
            project_id='proj456'
        )
        
        assert stats['cwe'] == 0
        assert stats['capec'] == 0


class TestIngestionErrorHandling:
    """Tests for ingestion error handling."""
    
    def test_ingest_with_exception(self, mock_neo4j_client):
        """Test ingestion with exceptions."""
        # Make create_node raise an exception
        mock_neo4j_client.create_node.side_effect = Exception("Test error")
        
        ingestion = GraphIngestion(mock_neo4j_client)
        
        # Should not raise exception, just return empty stats
        stats = ingestion.ingest_domain_discovery(
            {'domain': 'example.com'},
            user_id='user123',
            project_id='proj456'
        )
        
        # Stats should be zero due to error
        assert stats['domains'] == 0
