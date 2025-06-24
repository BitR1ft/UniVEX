"""
Tests for Week 12 — Complete Ingestion Pipeline.

Verifies end-to-end ingestion across all six phases and confirms that
the full attack-surface pipeline produces the expected nodes and
relationships when all phases are executed in sequence.
"""

import pytest
from unittest.mock import Mock, call, patch
from app.db.neo4j_client import Neo4jClient
from app.graph.ingestion import (
    GraphIngestion,
    ingest_domain_discovery,
    ingest_port_scan,
    ingest_http_probe,
    ingest_resource_enumeration,
    ingest_vulnerability_scan,
    ingest_mitre_data,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_neo4j_client():
    """Mock Neo4j client that echoes back properties."""
    client = Mock(spec=Neo4jClient)

    def _create_node(label, properties, merge=True):
        if "id" not in properties:
            if label == "Port":
                properties["id"] = (
                    f"{properties.get('ip')}:{properties.get('number')}"
                    f"/{properties.get('protocol', 'tcp')}"
                )
            elif label == "Service":
                properties["id"] = (
                    f"{properties.get('name')}:{properties.get('version', 'unknown')}"
                )
            elif label == "Endpoint":
                properties["id"] = (
                    f"{properties.get('method')}:{properties.get('path')}"
                )
            elif label == "Parameter":
                properties["id"] = (
                    f"{properties.get('name')}:{properties.get('type')}"
                )
            elif label == "Header":
                properties["id"] = (
                    f"{properties.get('name')}:{properties.get('value')}"
                )
            elif label == "DNSRecord":
                properties["id"] = (
                    f"{properties.get('type')}:{properties.get('value')}"
                )
            elif label == "Vulnerability":
                import hashlib
                vuln_str = (
                    f"{properties.get('name')}:{properties.get('severity')}"
                    f":{properties.get('source')}"
                )
                properties["id"] = hashlib.md5(vuln_str.encode()).hexdigest()
        return properties

    client.create_node = Mock(side_effect=_create_node)
    client.create_relationship = Mock(return_value=True)
    client.execute_query = Mock(return_value=[])
    return client


@pytest.fixture
def full_project_data():
    """Complete project data spanning all 6 ingestion phases."""
    return {
        # Phase 1 – Domain Discovery
        "domain_discovery": {
            "domain": "target.example.com",
            "whois": {
                "registrar": "Example Registrar",
                "creation_date": "2010-01-01",
                "org": "Target Corp",
                "country": "US",
            },
            "subdomains": [
                "www.target.example.com",
                "api.target.example.com",
                "mail.target.example.com",
            ],
            "dns_records": {
                "www.target.example.com": {
                    "records": {"A": ["203.0.113.10"], "AAAA": ["2001:db8::10"]}
                },
                "api.target.example.com": {
                    "records": {"A": ["203.0.113.11"]}
                },
                "mail.target.example.com": {
                    "records": {
                        "A": ["203.0.113.12"],
                        "MX": ["mail.target.example.com"],
                    }
                },
            },
            "ip_mapping": {
                "www.target.example.com": ["203.0.113.10", "2001:db8::10"],
                "api.target.example.com": ["203.0.113.11"],
                "mail.target.example.com": ["203.0.113.12"],
            },
        },
        # Phase 2 – Port Scan
        "port_scan": {
            "scanned_ips": [
                {
                    "ip": "203.0.113.10",
                    "asn_info": {"asn": "AS64496", "org": "Target ISP", "country": "US"},
                    "ports": [
                        {"port": 80, "protocol": "tcp", "state": "open",
                         "service": "http", "version": "2.4.52"},
                        {"port": 443, "protocol": "tcp", "state": "open",
                         "service": "https", "version": "2.4.52"},
                        {"port": 22, "protocol": "tcp", "state": "open",
                         "service": "ssh", "version": "OpenSSH_8.9"},
                    ],
                },
                {
                    "ip": "203.0.113.11",
                    "ports": [
                        {"port": 8080, "protocol": "tcp", "state": "open",
                         "service": "http-proxy", "version": "nginx/1.24"},
                    ],
                },
            ]
        },
        # Phase 3 – HTTP Probe
        "http_probe": {
            "probed_urls": [
                {
                    "url": "https://www.target.example.com",
                    "ip": "203.0.113.10",
                    "port": 443,
                    "status_code": 200,
                    "title": "Target Corp",
                    "server": "Apache/2.4.52",
                    "technologies": [
                        {"name": "Apache", "version": "2.4.52", "confidence": 100,
                         "categories": ["Web servers"]},
                        {"name": "PHP", "version": "8.1", "confidence": 90,
                         "categories": ["Programming languages"]},
                    ],
                    "headers": {
                        "Server": "Apache/2.4.52",
                        "X-Frame-Options": "DENY",
                        "Content-Security-Policy": "default-src 'self'",
                    },
                    "tls": {
                        "certificate": {
                            "subject": "CN=www.target.example.com",
                            "issuer": "Let's Encrypt",
                            "valid_from": "2026-01-01",
                            "valid_to": "2026-04-01",
                            "serial_number": "aabbccddeeff",
                        }
                    },
                },
                {
                    "url": "http://api.target.example.com:8080",
                    "ip": "203.0.113.11",
                    "port": 8080,
                    "status_code": 200,
                    "title": "API Gateway",
                    "server": "nginx/1.24",
                    "technologies": [
                        {"name": "nginx", "version": "1.24", "confidence": 100,
                         "categories": ["Web servers"]},
                    ],
                    "headers": {"Server": "nginx/1.24"},
                },
            ]
        },
        # Phase 4 – Resource Enumeration
        "resource_enum": {
            "endpoints": [
                {
                    "path": "/api/v1/users",
                    "method": "GET",
                    "base_url": "https://www.target.example.com",
                    "status_code": 200,
                    "parameters": [
                        {"name": "page", "type": "query"},
                        {"name": "limit", "type": "query"},
                    ],
                },
                {
                    "path": "/api/v1/users",
                    "method": "POST",
                    "base_url": "https://www.target.example.com",
                    "status_code": 201,
                    "parameters": [
                        {"name": "username", "type": "body"},
                        {"name": "email", "type": "body"},
                        {"name": "password", "type": "body"},
                    ],
                },
                {
                    "path": "/api/v1/admin",
                    "method": "GET",
                    "base_url": "https://www.target.example.com",
                    "status_code": 200,
                    "parameters": [],
                },
            ]
        },
        # Phase 5 – Vulnerability Scan
        "vuln_scan": {
            "vulnerabilities": [
                {
                    "name": "Cross-Site Scripting (XSS)",
                    "template_id": "xss-reflected",
                    "severity": "high",
                    "category": "injection",
                    "source": "nuclei",
                    "description": "Reflected XSS in search parameter",
                    "endpoint": "/api/v1/users",
                    "technology": "PHP",
                    "cve_ids": [],
                },
                {
                    "name": "Apache HTTP Server CVE",
                    "severity": "critical",
                    "category": "rce",
                    "source": "nuclei",
                    "technology": "Apache",
                    "cve_ids": ["CVE-2021-41773"],
                    "cve_data": {
                        "CVE-2021-41773": {
                            "cvss_score": 9.8,
                            "severity": "critical",
                            "description": "Path traversal in Apache 2.4.49",
                            "published_date": "2021-10-04",
                        }
                    },
                },
                {
                    "name": "Exposed Admin Panel",
                    "severity": "medium",
                    "category": "misconfig",
                    "source": "nuclei",
                    "description": "Admin panel accessible without auth",
                    "endpoint": "/api/v1/admin",
                    "cve_ids": [],
                },
            ]
        },
        # Phase 6 – MITRE Data
        "mitre_data": {
            "cwe_mappings": [
                {
                    "cve_id": "CVE-2021-41773",
                    "cwe_id": "CWE-22",
                    "name": "Improper Limitation of a Pathname",
                    "description": "Path traversal weakness",
                    "capec_ids": [
                        {
                            "capec_id": "CAPEC-126",
                            "name": "Path Traversal",
                            "description": "Using .. in paths to access files",
                            "likelihood": "High",
                            "severity": "High",
                        }
                    ],
                },
                {
                    "cve_id": None,
                    "cwe_id": "CWE-79",
                    "name": "Improper Neutralization of Input",
                    "description": "XSS weakness",
                    "capec_ids": [
                        {
                            "capec_id": "CAPEC-63",
                            "name": "Cross-Site Scripting (XSS)",
                            "description": "Injecting scripts into pages",
                            "likelihood": "High",
                            "severity": "High",
                        }
                    ],
                },
            ]
        },
    }


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestDomainDiscoveryIngestion:
    """Day 73 — Domain → Subdomain → IP → DNSRecord chain."""

    def test_full_domain_ingestion(self, mock_neo4j_client, full_project_data):
        ingestion = GraphIngestion(mock_neo4j_client)
        stats = ingestion.ingest_domain_discovery(
            full_project_data["domain_discovery"],
            user_id="u1",
            project_id="p1",
        )
        assert stats["domains"] == 1
        assert stats["subdomains"] == 3
        assert stats["ips"] == 4  # 2 from www, 1 from api, 1 from mail
        assert stats["dns_records"] > 0
        assert stats["relationships"] > 0

    def test_domain_node_is_created(self, mock_neo4j_client, full_project_data):
        ingestion = GraphIngestion(mock_neo4j_client)
        ingestion.ingest_domain_discovery(
            full_project_data["domain_discovery"],
            user_id="u1",
            project_id="p1",
        )
        labels_created = [
            c[0][0] for c in mock_neo4j_client.create_node.call_args_list
        ]
        assert "Domain" in labels_created
        assert "Subdomain" in labels_created
        assert "IP" in labels_created
        assert "DNSRecord" in labels_created

    def test_has_subdomain_relationship_created(self, mock_neo4j_client, full_project_data):
        ingestion = GraphIngestion(mock_neo4j_client)
        ingestion.ingest_domain_discovery(
            full_project_data["domain_discovery"],
            user_id="u1",
            project_id="p1",
        )
        rel_types = [
            c[0][6] for c in mock_neo4j_client.create_relationship.call_args_list
        ]
        assert "HAS_SUBDOMAIN" in rel_types
        assert "RESOLVES_TO" in rel_types


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestPortScanIngestion:
    """Day 74 — IP → Port → Service chain."""

    def test_port_scan_stats(self, mock_neo4j_client, full_project_data):
        ingestion = GraphIngestion(mock_neo4j_client)
        stats = ingestion.ingest_port_scan(
            full_project_data["port_scan"],
            user_id="u1",
            project_id="p1",
        )
        assert stats["ips"] == 2
        assert stats["ports"] == 4  # 3 from first IP + 1 from second
        assert stats["services"] == 4
        assert stats["relationships"] > 0

    def test_has_port_relationship_created(self, mock_neo4j_client, full_project_data):
        ingestion = GraphIngestion(mock_neo4j_client)
        ingestion.ingest_port_scan(
            full_project_data["port_scan"],
            user_id="u1",
            project_id="p1",
        )
        rel_types = [
            c[0][6] for c in mock_neo4j_client.create_relationship.call_args_list
        ]
        assert "HAS_PORT" in rel_types
        assert "RUNS_SERVICE" in rel_types

    def test_port_without_service(self, mock_neo4j_client):
        ingestion = GraphIngestion(mock_neo4j_client)
        data = {
            "scanned_ips": [
                {"ip": "10.0.0.1", "ports": [{"port": 9999, "protocol": "tcp"}]}
            ]
        }
        stats = ingestion.ingest_port_scan(data)
        assert stats["ports"] == 1
        assert stats["services"] == 0


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestHttpProbeIngestion:
    """Day 75 — BaseURL → Technology, Header, Certificate chain."""

    def test_http_probe_stats(self, mock_neo4j_client, full_project_data):
        ingestion = GraphIngestion(mock_neo4j_client)
        stats = ingestion.ingest_http_probe(
            full_project_data["http_probe"],
            user_id="u1",
            project_id="p1",
        )
        assert stats["base_urls"] == 2
        assert stats["technologies"] == 3  # Apache, PHP, nginx
        assert stats["headers"] == 4       # 3 from first + 1 from second
        assert stats["certificates"] == 1  # only www has TLS
        assert stats["relationships"] > 0

    def test_uses_technology_relationship(self, mock_neo4j_client, full_project_data):
        ingestion = GraphIngestion(mock_neo4j_client)
        ingestion.ingest_http_probe(
            full_project_data["http_probe"],
            user_id="u1",
            project_id="p1",
        )
        rel_types = [
            c[0][6] for c in mock_neo4j_client.create_relationship.call_args_list
        ]
        assert "USES_TECHNOLOGY" in rel_types
        assert "HAS_HEADER" in rel_types
        assert "HAS_CERTIFICATE" in rel_types

    def test_port_baseurl_link(self, mock_neo4j_client, full_project_data):
        ingestion = GraphIngestion(mock_neo4j_client)
        ingestion.ingest_http_probe(
            full_project_data["http_probe"],
            user_id="u1",
            project_id="p1",
        )
        rel_types = [
            c[0][6] for c in mock_neo4j_client.create_relationship.call_args_list
        ]
        assert "SERVES_URL" in rel_types


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestResourceEnumerationIngestion:
    """Day 76 — Endpoint → Parameter chain."""

    def test_resource_enum_stats(self, mock_neo4j_client, full_project_data):
        ingestion = GraphIngestion(mock_neo4j_client)
        stats = ingestion.ingest_resource_enumeration(
            full_project_data["resource_enum"],
            user_id="u1",
            project_id="p1",
        )
        assert stats["endpoints"] == 3
        assert stats["parameters"] == 5  # 2 + 3 + 0
        assert stats["relationships"] > 0

    def test_has_endpoint_relationship(self, mock_neo4j_client, full_project_data):
        ingestion = GraphIngestion(mock_neo4j_client)
        ingestion.ingest_resource_enumeration(
            full_project_data["resource_enum"],
            user_id="u1",
            project_id="p1",
        )
        rel_types = [
            c[0][6] for c in mock_neo4j_client.create_relationship.call_args_list
        ]
        assert "HAS_ENDPOINT" in rel_types
        assert "HAS_PARAMETER" in rel_types

    def test_endpoint_without_base_url(self, mock_neo4j_client):
        ingestion = GraphIngestion(mock_neo4j_client)
        data = {
            "endpoints": [{"path": "/no-base", "method": "GET", "parameters": []}]
        }
        stats = ingestion.ingest_resource_enumeration(data)
        assert stats["endpoints"] == 1
        # No HAS_ENDPOINT relationship should be created (no base_url)
        rel_types = [
            c[0][6] for c in mock_neo4j_client.create_relationship.call_args_list
        ]
        assert "HAS_ENDPOINT" not in rel_types


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestVulnerabilityScanIngestion:
    """Day 77 — Vulnerability → Endpoint, Technology → CVE chain."""

    def test_vuln_scan_stats(self, mock_neo4j_client, full_project_data):
        ingestion = GraphIngestion(mock_neo4j_client)
        stats = ingestion.ingest_vulnerability_scan(
            full_project_data["vuln_scan"],
            user_id="u1",
            project_id="p1",
        )
        assert stats["vulnerabilities"] == 3
        assert stats["cves"] == 1  # Only CVE-2021-41773
        assert stats["relationships"] > 0

    def test_found_at_and_has_known_cve(self, mock_neo4j_client, full_project_data):
        ingestion = GraphIngestion(mock_neo4j_client)
        ingestion.ingest_vulnerability_scan(
            full_project_data["vuln_scan"],
            user_id="u1",
            project_id="p1",
        )
        rel_types = [
            c[0][6] for c in mock_neo4j_client.create_relationship.call_args_list
        ]
        assert "FOUND_AT" in rel_types
        assert "HAS_KNOWN_CVE" in rel_types

    def test_vuln_without_endpoint(self, mock_neo4j_client):
        ingestion = GraphIngestion(mock_neo4j_client)
        data = {
            "vulnerabilities": [
                {"name": "Generic Vuln", "severity": "low", "source": "nuclei"}
            ]
        }
        stats = ingestion.ingest_vulnerability_scan(data)
        assert stats["vulnerabilities"] == 1
        assert stats["cves"] == 0


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestMitreIngestion:
    """Day 78 — CVE → CWE → CAPEC chain."""

    def test_mitre_stats(self, mock_neo4j_client, full_project_data):
        ingestion = GraphIngestion(mock_neo4j_client)
        stats = ingestion.ingest_mitre_data(
            full_project_data["mitre_data"],
            user_id="u1",
            project_id="p1",
        )
        assert stats["cwe"] == 2
        assert stats["capec"] == 2
        assert stats["relationships"] > 0

    def test_has_cwe_has_capec_relationships(self, mock_neo4j_client, full_project_data):
        ingestion = GraphIngestion(mock_neo4j_client)
        ingestion.ingest_mitre_data(
            full_project_data["mitre_data"],
            user_id="u1",
            project_id="p1",
        )
        rel_types = [
            c[0][6] for c in mock_neo4j_client.create_relationship.call_args_list
        ]
        assert "HAS_CWE" in rel_types
        assert "HAS_CAPEC" in rel_types

    def test_mitre_without_cve_link(self, mock_neo4j_client, full_project_data):
        """CWE with cve_id=None should still create CWE and CAPEC nodes."""
        ingestion = GraphIngestion(mock_neo4j_client)
        data = {
            "cwe_mappings": [
                {
                    "cve_id": None,
                    "cwe_id": "CWE-79",
                    "name": "XSS",
                    "capec_ids": [
                        {"capec_id": "CAPEC-63", "name": "XSS Pattern"}
                    ],
                }
            ]
        }
        stats = ingestion.ingest_mitre_data(data)
        assert stats["cwe"] == 1
        assert stats["capec"] == 1
        rel_types = [
            c[0][6] for c in mock_neo4j_client.create_relationship.call_args_list
        ]
        # No HAS_CWE (no cve_id), but HAS_CAPEC should exist
        assert "HAS_CWE" not in rel_types
        assert "HAS_CAPEC" in rel_types


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestEndToEndPipeline:
    """Day 79 — Full sequential pipeline across all 6 phases."""

    def test_full_pipeline_produces_all_node_types(
        self, mock_neo4j_client, full_project_data
    ):
        """Run all 6 phases and assert each node label was created."""
        ingestion = GraphIngestion(mock_neo4j_client)
        ingestion.ingest_domain_discovery(
            full_project_data["domain_discovery"], user_id="u1", project_id="p1"
        )
        ingestion.ingest_port_scan(
            full_project_data["port_scan"], user_id="u1", project_id="p1"
        )
        ingestion.ingest_http_probe(
            full_project_data["http_probe"], user_id="u1", project_id="p1"
        )
        ingestion.ingest_resource_enumeration(
            full_project_data["resource_enum"], user_id="u1", project_id="p1"
        )
        ingestion.ingest_vulnerability_scan(
            full_project_data["vuln_scan"], user_id="u1", project_id="p1"
        )
        ingestion.ingest_mitre_data(
            full_project_data["mitre_data"], user_id="u1", project_id="p1"
        )

        labels_created = {
            c[0][0] for c in mock_neo4j_client.create_node.call_args_list
        }
        expected_labels = {
            "Domain", "Subdomain", "IP", "DNSRecord",
            "Port", "Service",
            "BaseURL", "Technology", "Header", "Certificate",
            "Endpoint", "Parameter",
            "Vulnerability", "CVE",
            "MitreData", "Capec",
        }
        for label in expected_labels:
            assert label in labels_created, (
                f"Expected label '{label}' was not created during pipeline run"
            )

    def test_full_pipeline_produces_all_relationship_types(
        self, mock_neo4j_client, full_project_data
    ):
        """Run all phases and assert every relationship type was created."""
        ingestion = GraphIngestion(mock_neo4j_client)
        ingestion.ingest_domain_discovery(
            full_project_data["domain_discovery"], user_id="u1", project_id="p1"
        )
        ingestion.ingest_port_scan(
            full_project_data["port_scan"], user_id="u1", project_id="p1"
        )
        ingestion.ingest_http_probe(
            full_project_data["http_probe"], user_id="u1", project_id="p1"
        )
        ingestion.ingest_resource_enumeration(
            full_project_data["resource_enum"], user_id="u1", project_id="p1"
        )
        ingestion.ingest_vulnerability_scan(
            full_project_data["vuln_scan"], user_id="u1", project_id="p1"
        )
        ingestion.ingest_mitre_data(
            full_project_data["mitre_data"], user_id="u1", project_id="p1"
        )

        rel_types_created = {
            c[0][6] for c in mock_neo4j_client.create_relationship.call_args_list
        }
        expected_rels = {
            "HAS_SUBDOMAIN", "RESOLVES_TO", "HAS_DNS_RECORD",
            "HAS_PORT", "RUNS_SERVICE",
            "SERVES_URL", "USES_TECHNOLOGY", "HAS_HEADER", "HAS_CERTIFICATE",
            "HAS_ENDPOINT", "HAS_PARAMETER",
            "FOUND_AT", "HAS_KNOWN_CVE",
            "HAS_CWE", "HAS_CAPEC",
        }
        for rel in expected_rels:
            assert rel in rel_types_created, (
                f"Expected relationship '{rel}' was not created during pipeline run"
            )

    def test_full_pipeline_total_node_count(
        self, mock_neo4j_client, full_project_data
    ):
        """Verify create_node was called a reasonable number of times."""
        ingestion = GraphIngestion(mock_neo4j_client)
        ingestion.ingest_domain_discovery(
            full_project_data["domain_discovery"], user_id="u1", project_id="p1"
        )
        ingestion.ingest_port_scan(
            full_project_data["port_scan"], user_id="u1", project_id="p1"
        )
        ingestion.ingest_http_probe(
            full_project_data["http_probe"], user_id="u1", project_id="p1"
        )
        ingestion.ingest_resource_enumeration(
            full_project_data["resource_enum"], user_id="u1", project_id="p1"
        )
        ingestion.ingest_vulnerability_scan(
            full_project_data["vuln_scan"], user_id="u1", project_id="p1"
        )
        ingestion.ingest_mitre_data(
            full_project_data["mitre_data"], user_id="u1", project_id="p1"
        )
        # There should be at least 30 node creation calls across all phases
        assert mock_neo4j_client.create_node.call_count >= 30

    def test_full_pipeline_multi_tenancy(
        self, mock_neo4j_client, full_project_data
    ):
        """All nodes must carry user_id and project_id."""
        ingestion = GraphIngestion(mock_neo4j_client)
        for phase_fn, data_key in [
            (ingestion.ingest_domain_discovery, "domain_discovery"),
            (ingestion.ingest_port_scan, "port_scan"),
            (ingestion.ingest_http_probe, "http_probe"),
            (ingestion.ingest_resource_enumeration, "resource_enum"),
            (ingestion.ingest_vulnerability_scan, "vuln_scan"),
            (ingestion.ingest_mitre_data, "mitre_data"),
        ]:
            mock_neo4j_client.create_node.reset_mock()
            phase_fn(
                full_project_data[data_key], user_id="u1", project_id="p1"
            )
            for c in mock_neo4j_client.create_node.call_args_list:
                props = c[0][1]
                assert props.get("user_id") == "u1", (
                    f"Missing user_id in {c[0][0]} node: {props}"
                )
                assert props.get("project_id") == "p1", (
                    f"Missing project_id in {c[0][0]} node: {props}"
                )

    def test_pipeline_convenience_functions(self, mock_neo4j_client, full_project_data):
        """Module-level convenience wrappers should work identically to class methods."""
        # Domain discovery
        stats = ingest_domain_discovery(
            mock_neo4j_client,
            full_project_data["domain_discovery"],
            user_id="u1",
            project_id="p1",
        )
        assert stats["domains"] == 1

        mock_neo4j_client.create_node.reset_mock()

        # Port scan
        stats = ingest_port_scan(
            mock_neo4j_client,
            full_project_data["port_scan"],
            user_id="u1",
            project_id="p1",
        )
        assert stats["ports"] == 4

        mock_neo4j_client.create_node.reset_mock()

        # Vulnerability scan
        stats = ingest_vulnerability_scan(
            mock_neo4j_client,
            full_project_data["vuln_scan"],
            user_id="u1",
            project_id="p1",
        )
        assert stats["vulnerabilities"] == 3

    def test_pipeline_handles_empty_input(self, mock_neo4j_client):
        """All ingestion phases must handle empty/minimal input gracefully."""
        ingestion = GraphIngestion(mock_neo4j_client)
        assert ingestion.ingest_domain_discovery({})["domains"] == 0
        assert ingestion.ingest_port_scan({})["ports"] == 0
        assert ingestion.ingest_http_probe({})["base_urls"] == 0
        assert ingestion.ingest_resource_enumeration({})["endpoints"] == 0
        assert ingestion.ingest_vulnerability_scan({})["vulnerabilities"] == 0
        assert ingestion.ingest_mitre_data({})["cwe"] == 0

    def test_pipeline_exception_isolation(self, mock_neo4j_client, full_project_data):
        """A failure in create_node should not propagate — empty stats returned."""
        mock_neo4j_client.create_node.side_effect = Exception("DB error")
        ingestion = GraphIngestion(mock_neo4j_client)

        # Each phase should return zero stats, not raise
        for phase_fn, data_key in [
            (ingestion.ingest_domain_discovery, "domain_discovery"),
            (ingestion.ingest_port_scan, "port_scan"),
            (ingestion.ingest_http_probe, "http_probe"),
            (ingestion.ingest_resource_enumeration, "resource_enum"),
            (ingestion.ingest_vulnerability_scan, "vuln_scan"),
            (ingestion.ingest_mitre_data, "mitre_data"),
        ]:
            stats = phase_fn(full_project_data[data_key])
            assert all(v == 0 for v in stats.values()), (
                f"Expected all-zero stats on exception for {data_key}, got {stats}"
            )
