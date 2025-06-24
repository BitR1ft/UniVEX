"""
Tests for graph node creation.
"""

import pytest
from app.graph.nodes import (
    DomainNode, SubdomainNode, IPNode, PortNode, ServiceNode,
    BaseURLNode, EndpointNode, ParameterNode, TechnologyNode,
    HeaderNode, CertificateNode, DNSRecordNode, VulnerabilityNode,
    CVENode, MitreDataNode, CapecNode, ExploitNode
)


class TestDomainNode:
    """Tests for DomainNode."""
    
    def test_create_domain(self, mock_neo4j_client):
        """Test creating a Domain node."""
        node = DomainNode(mock_neo4j_client)
        
        whois_data = {
            'registrar': 'Test Registrar',
            'creation_date': '2000-01-01',
            'org': 'Test Org'
        }
        
        result = node.create(
            name='example.com',
            whois_data=whois_data,
            user_id='user123',
            project_id='proj456'
        )
        
        assert result['name'] == 'example.com'
        assert result['registrar'] == 'Test Registrar'
        assert result['user_id'] == 'user123'
        assert result['project_id'] == 'proj456'
        assert 'discovered_at' in result
        
        mock_neo4j_client.create_node.assert_called_once()
        call_args = mock_neo4j_client.create_node.call_args
        assert call_args[0][0] == 'Domain'


class TestSubdomainNode:
    """Tests for SubdomainNode."""
    
    def test_create_subdomain(self, mock_neo4j_client):
        """Test creating a Subdomain node."""
        node = SubdomainNode(mock_neo4j_client)
        
        result = node.create(
            name='www.example.com',
            parent_domain='example.com',
            user_id='user123',
            project_id='proj456'
        )
        
        assert result['name'] == 'www.example.com'
        assert result['parent_domain'] == 'example.com'
        assert result['user_id'] == 'user123'
        assert 'discovered_at' in result


class TestIPNode:
    """Tests for IPNode."""
    
    def test_create_ip_with_cdn(self, mock_neo4j_client):
        """Test creating an IP node with CDN info."""
        node = IPNode(mock_neo4j_client)
        
        cdn_info = {
            'is_cdn': True,
            'cdn_name': 'Cloudflare'
        }
        
        asn_info = {
            'asn': 'AS12345',
            'org': 'Test ISP',
            'country': 'US'
        }
        
        result = node.create(
            address='192.0.2.1',
            cdn_info=cdn_info,
            asn_info=asn_info,
            user_id='user123',
            project_id='proj456'
        )
        
        assert result['address'] == '192.0.2.1'
        assert result['is_cdn'] is True
        assert result['cdn_name'] == 'Cloudflare'
        assert result['asn'] == 'AS12345'


class TestPortNode:
    """Tests for PortNode."""
    
    def test_create_port(self, mock_neo4j_client):
        """Test creating a Port node."""
        node = PortNode(mock_neo4j_client)
        
        result = node.create(
            ip='192.0.2.1',
            number=80,
            protocol='tcp',
            state='open',
            user_id='user123',
            project_id='proj456'
        )
        
        assert result['ip'] == '192.0.2.1'
        assert result['number'] == 80
        assert result['protocol'] == 'tcp'
        assert result['state'] == 'open'
        assert result['id'] == '192.0.2.1:80/tcp'


class TestServiceNode:
    """Tests for ServiceNode."""
    
    def test_create_service(self, mock_neo4j_client):
        """Test creating a Service node."""
        node = ServiceNode(mock_neo4j_client)
        
        result = node.create(
            name='http',
            version='2.4.41',
            banner='Apache/2.4.41 (Ubuntu)',
            user_id='user123',
            project_id='proj456'
        )
        
        assert result['name'] == 'http'
        assert result['version'] == '2.4.41'
        assert result['banner'] == 'Apache/2.4.41 (Ubuntu)'
        assert result['id'] == 'http:2.4.41'


class TestBaseURLNode:
    """Tests for BaseURLNode."""
    
    def test_create_baseurl(self, mock_neo4j_client):
        """Test creating a BaseURL node."""
        node = BaseURLNode(mock_neo4j_client)
        
        http_metadata = {
            'status_code': 200,
            'content_type': 'text/html',
            'server': 'Apache/2.4.41'
        }
        
        result = node.create(
            url='https://example.com',
            http_metadata=http_metadata,
            user_id='user123',
            project_id='proj456'
        )
        
        assert result['url'] == 'https://example.com'
        assert result['status_code'] == 200
        assert result['content_type'] == 'text/html'


class TestEndpointNode:
    """Tests for EndpointNode."""
    
    def test_create_endpoint(self, mock_neo4j_client):
        """Test creating an Endpoint node."""
        node = EndpointNode(mock_neo4j_client)
        
        result = node.create(
            path='/api/users',
            method='GET',
            base_url='https://example.com',
            user_id='user123',
            project_id='proj456'
        )
        
        assert result['path'] == '/api/users'
        assert result['method'] == 'GET'
        assert result['id'] == 'GET:/api/users'


class TestParameterNode:
    """Tests for ParameterNode."""
    
    def test_create_parameter(self, mock_neo4j_client):
        """Test creating a Parameter node."""
        node = ParameterNode(mock_neo4j_client)
        
        result = node.create(
            name='user_id',
            param_type='query',
            example_value='123',
            user_id='user123',
            project_id='proj456'
        )
        
        assert result['name'] == 'user_id'
        assert result['type'] == 'query'
        assert result['example_value'] == '123'
        assert result['id'] == 'user_id:query'


class TestTechnologyNode:
    """Tests for TechnologyNode."""
    
    def test_create_technology(self, mock_neo4j_client):
        """Test creating a Technology node."""
        node = TechnologyNode(mock_neo4j_client)
        
        result = node.create(
            name='Apache',
            version='2.4.41',
            confidence=100.0,
            categories=['Web servers'],
            user_id='user123',
            project_id='proj456'
        )
        
        assert result['name'] == 'Apache'
        assert result['version'] == '2.4.41'
        assert result['confidence'] == 100.0
        assert result['categories'] == ['Web servers']


class TestHeaderNode:
    """Tests for HeaderNode."""
    
    def test_create_header(self, mock_neo4j_client):
        """Test creating a Header node."""
        node = HeaderNode(mock_neo4j_client)
        
        result = node.create(
            name='Server',
            value='Apache/2.4.41',
            user_id='user123',
            project_id='proj456'
        )
        
        assert result['name'] == 'Server'
        assert result['value'] == 'Apache/2.4.41'
        assert result['id'] == 'Server:Apache/2.4.41'


class TestCertificateNode:
    """Tests for CertificateNode."""
    
    def test_create_certificate(self, mock_neo4j_client):
        """Test creating a Certificate node."""
        node = CertificateNode(mock_neo4j_client)
        
        result = node.create(
            subject='CN=example.com',
            issuer='CN=Let\'s Encrypt',
            valid_from='2024-01-01',
            valid_to='2024-04-01',
            serial_number='0123456789',
            user_id='user123',
            project_id='proj456'
        )
        
        assert result['subject'] == 'CN=example.com'
        assert result['issuer'] == 'CN=Let\'s Encrypt'
        assert result['serial_number'] == '0123456789'


class TestDNSRecordNode:
    """Tests for DNSRecordNode."""
    
    def test_create_dns_record(self, mock_neo4j_client):
        """Test creating a DNSRecord node."""
        node = DNSRecordNode(mock_neo4j_client)
        
        result = node.create(
            record_type='A',
            value='192.0.2.1',
            subdomain='www.example.com',
            user_id='user123',
            project_id='proj456'
        )
        
        assert result['type'] == 'A'
        assert result['value'] == '192.0.2.1'
        assert result['subdomain'] == 'www.example.com'
        assert result['id'] == 'A:192.0.2.1'


class TestVulnerabilityNode:
    """Tests for VulnerabilityNode."""
    
    def test_create_vulnerability(self, mock_neo4j_client):
        """Test creating a Vulnerability node."""
        node = VulnerabilityNode(mock_neo4j_client)
        
        result = node.create(
            name='XSS Vulnerability',
            severity='high',
            category='injection',
            source='nuclei',
            description='Cross-site scripting',
            user_id='user123',
            project_id='proj456'
        )
        
        assert result['name'] == 'XSS Vulnerability'
        assert result['severity'] == 'high'
        assert result['category'] == 'injection'
        assert result['source'] == 'nuclei'
        assert 'id' in result


class TestCVENode:
    """Tests for CVENode."""
    
    def test_create_cve(self, mock_neo4j_client):
        """Test creating a CVE node."""
        node = CVENode(mock_neo4j_client)
        
        result = node.create(
            cve_id='CVE-2021-12345',
            cvss_score=7.5,
            severity='high',
            description='Example CVE',
            published_date='2021-01-01',
            user_id='user123',
            project_id='proj456'
        )
        
        assert result['cve_id'] == 'CVE-2021-12345'
        assert result['cvss_score'] == 7.5
        assert result['severity'] == 'high'


class TestMitreDataNode:
    """Tests for MitreDataNode."""
    
    def test_create_mitre_data(self, mock_neo4j_client):
        """Test creating a MitreData node."""
        node = MitreDataNode(mock_neo4j_client)
        
        result = node.create(
            cwe_id='CWE-79',
            name='Cross-site Scripting',
            description='XSS weakness',
            user_id='user123',
            project_id='proj456'
        )
        
        assert result['cwe_id'] == 'CWE-79'
        assert result['name'] == 'Cross-site Scripting'


class TestCapecNode:
    """Tests for CapecNode."""
    
    def test_create_capec(self, mock_neo4j_client):
        """Test creating a Capec node."""
        node = CapecNode(mock_neo4j_client)
        
        result = node.create(
            capec_id='CAPEC-63',
            name='Cross-Site Scripting (XSS)',
            description='XSS attack pattern',
            likelihood='High',
            severity='High',
            user_id='user123',
            project_id='proj456'
        )
        
        assert result['capec_id'] == 'CAPEC-63'
        assert result['name'] == 'Cross-Site Scripting (XSS)'


class TestExploitNode:
    """Tests for ExploitNode."""
    
    def test_create_exploit(self, mock_neo4j_client):
        """Test creating an Exploit node."""
        node = ExploitNode(mock_neo4j_client)
        
        result = node.create(
            exploit_id='EXP-2021-001',
            name='Apache Exploit',
            exploit_type='remote',
            platform='linux',
            author='researcher',
            published_date='2021-01-01',
            user_id='user123',
            project_id='proj456'
        )
        
        assert result['id'] == 'EXP-2021-001'
        assert result['name'] == 'Apache Exploit'
        assert result['type'] == 'remote'
        assert result['platform'] == 'linux'
