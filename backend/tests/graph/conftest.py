"""
Test configuration and fixtures for graph tests.
"""

import pytest
from unittest.mock import Mock, MagicMock
from app.db.neo4j_client import Neo4jClient


@pytest.fixture
def mock_neo4j_client():
    """Create a mock Neo4j client for testing."""
    client = Mock(spec=Neo4jClient)
    
    # Mock the create_node method
    def mock_create_node(label, properties, merge=True):
        # Return properties with added id if not present
        if 'id' not in properties:
            if label == 'Port':
                properties['id'] = f"{properties.get('ip')}:{properties.get('number')}/{properties.get('protocol', 'tcp')}"
            elif label == 'Service':
                properties['id'] = f"{properties.get('name')}:{properties.get('version', 'unknown')}"
            elif label == 'Endpoint':
                properties['id'] = f"{properties.get('method')}:{properties.get('path')}"
            elif label == 'Parameter':
                properties['id'] = f"{properties.get('name')}:{properties.get('type')}"
            elif label == 'Header':
                properties['id'] = f"{properties.get('name')}:{properties.get('value')}"
            elif label == 'DNSRecord':
                properties['id'] = f"{properties.get('type')}:{properties.get('value')}"
            elif label == 'Vulnerability':
                import hashlib
                vuln_str = f"{properties.get('name')}:{properties.get('severity')}:{properties.get('source')}"
                properties['id'] = hashlib.md5(vuln_str.encode()).hexdigest()
        return properties
    
    client.create_node = Mock(side_effect=mock_create_node)
    
    # Mock the create_relationship method
    client.create_relationship = Mock(return_value=True)
    
    # Mock the execute_query method
    client.execute_query = Mock(return_value=[])
    
    return client


@pytest.fixture
def sample_domain_data():
    """Sample domain discovery data for testing."""
    return {
        'domain': 'example.com',
        'timestamp': '2024-01-01T00:00:00Z',
        'whois': {
            'registrar': 'Example Registrar',
            'creation_date': '2000-01-01',
            'expiration_date': '2025-01-01',
            'org': 'Example Organization',
            'country': 'US',
            'name_servers': ['ns1.example.com', 'ns2.example.com'],
            'status': ['ok']
        },
        'subdomains': ['www.example.com', 'api.example.com'],
        'dns_records': {
            'www.example.com': {
                'records': {
                    'A': ['192.0.2.1'],
                    'AAAA': ['2001:db8::1']
                }
            },
            'api.example.com': {
                'records': {
                    'A': ['192.0.2.2']
                }
            }
        },
        'ip_mapping': {
            'www.example.com': ['192.0.2.1', '2001:db8::1'],
            'api.example.com': ['192.0.2.2']
        }
    }


@pytest.fixture
def sample_port_scan_data():
    """Sample port scan data for testing."""
    return {
        'scanned_ips': [
            {
                'ip': '192.0.2.1',
                'cdn_info': {
                    'is_cdn': False
                },
                'asn_info': {
                    'asn': 'AS12345',
                    'org': 'Example ISP',
                    'country': 'US'
                },
                'ports': [
                    {
                        'port': 80,
                        'protocol': 'tcp',
                        'state': 'open',
                        'service': 'http',
                        'version': '2.4.41',
                        'banner': 'Apache/2.4.41 (Ubuntu)'
                    },
                    {
                        'port': 443,
                        'protocol': 'tcp',
                        'state': 'open',
                        'service': 'https',
                        'version': '2.4.41'
                    }
                ]
            }
        ]
    }


@pytest.fixture
def sample_http_probe_data():
    """Sample HTTP probe data for testing."""
    return {
        'probed_urls': [
            {
                'url': 'https://example.com',
                'ip': '192.0.2.1',
                'port': 443,
                'status_code': 200,
                'content_type': 'text/html',
                'content_length': 1234,
                'server': 'Apache/2.4.41',
                'title': 'Example Domain',
                'response_time': 123.45,
                'technologies': [
                    {
                        'name': 'Apache',
                        'version': '2.4.41',
                        'confidence': 100,
                        'categories': ['Web servers']
                    },
                    {
                        'name': 'PHP',
                        'version': '7.4',
                        'confidence': 95,
                        'categories': ['Programming languages']
                    }
                ],
                'headers': {
                    'Server': 'Apache/2.4.41',
                    'Content-Type': 'text/html; charset=UTF-8',
                    'X-Powered-By': 'PHP/7.4'
                },
                'tls': {
                    'certificate': {
                        'subject': 'CN=example.com',
                        'issuer': 'CN=Let\'s Encrypt Authority',
                        'valid_from': '2024-01-01',
                        'valid_to': '2024-04-01',
                        'serial_number': '0123456789abcdef'
                    }
                }
            }
        ]
    }


@pytest.fixture
def sample_resource_enum_data():
    """Sample resource enumeration data for testing."""
    return {
        'endpoints': [
            {
                'path': '/api/users',
                'method': 'GET',
                'base_url': 'https://example.com',
                'status_code': 200,
                'content_type': 'application/json',
                'parameters': [
                    {
                        'name': 'page',
                        'type': 'query',
                        'example_value': '1'
                    },
                    {
                        'name': 'limit',
                        'type': 'query',
                        'example_value': '10'
                    }
                ]
            },
            {
                'path': '/api/users/{id}',
                'method': 'GET',
                'base_url': 'https://example.com',
                'status_code': 200,
                'content_type': 'application/json',
                'parameters': [
                    {
                        'name': 'id',
                        'type': 'path',
                        'example_value': '123'
                    }
                ]
            }
        ]
    }


@pytest.fixture
def sample_vulnerability_data():
    """Sample vulnerability scan data for testing."""
    return {
        'vulnerabilities': [
            {
                'name': 'Cross-Site Scripting (XSS)',
                'template_id': 'xss-reflected',
                'severity': 'high',
                'category': 'injection',
                'source': 'nuclei',
                'description': 'Reflected XSS vulnerability detected',
                'endpoint': '/search',
                'matcher_name': 'xss-reflected',
                'tags': ['xss', 'injection'],
                'cve_ids': [],
            },
            {
                'name': 'Apache HTTP Server 2.4.41 - Multiple Vulnerabilities',
                'severity': 'medium',
                'category': 'vulnerability',
                'source': 'nuclei',
                'description': 'Known vulnerabilities in Apache 2.4.41',
                'technology': 'Apache',
                'cve_ids': ['CVE-2021-12345'],
                'cve_data': {
                    'CVE-2021-12345': {
                        'cvss_score': 7.5,
                        'severity': 'high',
                        'description': 'Example CVE description',
                        'published_date': '2021-01-01'
                    }
                }
            }
        ]
    }


@pytest.fixture
def sample_mitre_data():
    """Sample MITRE mapping data for testing."""
    return {
        'cwe_mappings': [
            {
                'cve_id': 'CVE-2021-12345',
                'cwe_id': 'CWE-79',
                'name': 'Improper Neutralization of Input During Web Page Generation',
                'description': 'Cross-site Scripting (XSS)',
                'capec_ids': [
                    {
                        'capec_id': 'CAPEC-63',
                        'name': 'Cross-Site Scripting (XSS)',
                        'description': 'XSS attack pattern',
                        'likelihood': 'High',
                        'severity': 'High'
                    }
                ]
            }
        ]
    }
