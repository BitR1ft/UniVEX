"""
Tests for Week 11 — Graph Schema Design.

Covers:
          AuditEvent)
          Tool/Scan/Finding/Evidence relationships)
"""

import pytest
from unittest.mock import Mock
from app.db.neo4j_client import Neo4jClient
from app.graph.nodes import (
    DomainNode, SubdomainNode, IPNode, PortNode, ServiceNode,
    BaseURLNode, EndpointNode, ParameterNode, TechnologyNode,
    HeaderNode, CertificateNode, DNSRecordNode,
    VulnerabilityNode, CVENode, MitreDataNode, CapecNode, ExploitNode,
    SessionNode, CredentialNode,
    EvidenceNode, ToolNode, ScanNode, FindingNode, AuditEventNode,
)
from app.graph.relationships import (
    # Infrastructure
    link_domain_subdomain, link_subdomain_ip, link_ip_port,
    link_port_service, link_port_baseurl, link_baseurl_endpoint,
    link_endpoint_parameter, link_baseurl_technology,
    link_baseurl_header, link_baseurl_certificate, link_subdomain_dnsrecord,
    # Vulnerability
    link_vulnerability_endpoint, link_vulnerability_parameter,
    link_ip_vulnerability, link_technology_cve,
    link_cve_mitre, link_mitre_capec, link_exploit_cve, link_exploit_ip,
    # Session / Credential
    link_exploit_session, link_session_ip, link_session_credential,
    link_credential_service,
    # Tool / Scan / Finding / Evidence
    link_tool_scan, link_scan_finding, link_finding_evidence,
    link_finding_vulnerability,
)
from app.graph.schema_validation import (
    validate_schema,
    ensure_constraints,
    run_smoke_queries,
    EXPECTED_NODE_LABELS,
    EXPECTED_RELATIONSHIP_TYPES,
    EXPECTED_CONSTRAINTS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_neo4j_client():
    """Mock Neo4j client that echoes back the properties it receives."""
    client = Mock(spec=Neo4jClient)

    def _create_node(label, properties, merge=True):
        if "id" not in properties:
            if label == "Port":
                properties["id"] = (
                    f"{properties.get('ip')}:{properties.get('number')}"
                    f"/{properties.get('protocol', 'tcp')}"
                )
            elif label in ("Service", "Tool"):
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


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestCoreNodeTypes:
    """Day 67 — Domain, Subdomain, IP, Port node creation."""

    def test_domain_node_created_with_whois(self, mock_neo4j_client):
        node = DomainNode(mock_neo4j_client)
        result = node.create(
            "example.com",
            whois_data={"registrar": "ACME", "org": "ACME Corp"},
            user_id="u1",
            project_id="p1",
        )
        assert result["name"] == "example.com"
        assert result["registrar"] == "ACME"
        assert result["user_id"] == "u1"
        assert "discovered_at" in result
        call_label = mock_neo4j_client.create_node.call_args[0][0]
        assert call_label == "Domain"

    def test_subdomain_node_linked_to_parent(self, mock_neo4j_client):
        node = SubdomainNode(mock_neo4j_client)
        result = node.create("www.example.com", "example.com")
        assert result["parent_domain"] == "example.com"

    def test_ip_node_with_asn_info(self, mock_neo4j_client):
        node = IPNode(mock_neo4j_client)
        result = node.create(
            "192.0.2.1",
            asn_info={"asn": "AS64496", "org": "Test ISP", "country": "US"},
        )
        assert result["asn"] == "AS64496"

    def test_port_node_has_composite_id(self, mock_neo4j_client):
        node = PortNode(mock_neo4j_client)
        result = node.create("192.0.2.1", 443, protocol="tcp", state="open")
        assert result["id"] == "192.0.2.1:443/tcp"


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestServiceTechnologyNodes:
    """Day 68 — Service, BaseURL, Endpoint, Parameter, Technology nodes."""

    def test_service_node_id_includes_version(self, mock_neo4j_client):
        node = ServiceNode(mock_neo4j_client)
        result = node.create("http", version="2.4.41", banner="Apache")
        assert result["id"] == "http:2.4.41"
        assert result["banner"] == "Apache"

    def test_baseurl_node_with_metadata(self, mock_neo4j_client):
        node = BaseURLNode(mock_neo4j_client)
        result = node.create(
            "https://example.com",
            http_metadata={"status_code": 200, "title": "Home"},
        )
        assert result["url"] == "https://example.com"
        assert result["status_code"] == 200

    def test_endpoint_node_composite_id(self, mock_neo4j_client):
        node = EndpointNode(mock_neo4j_client)
        result = node.create("/api/users", method="POST")
        assert result["id"] == "POST:/api/users"

    def test_parameter_node_types(self, mock_neo4j_client):
        node = ParameterNode(mock_neo4j_client)
        for ptype in ("query", "body", "header", "path"):
            result = node.create("param", param_type=ptype)
            assert result["type"] == ptype

    def test_technology_node_with_categories(self, mock_neo4j_client):
        node = TechnologyNode(mock_neo4j_client)
        result = node.create(
            "WordPress",
            version="6.0",
            confidence=98.0,
            categories=["CMS"],
        )
        assert result["version"] == "6.0"
        assert "CMS" in result["categories"]


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestVulnerabilityAndCVENodes:
    """Day 69 — Vulnerability, CVE, MitreData, Capec, Exploit nodes."""

    def test_vulnerability_node_id_is_md5(self, mock_neo4j_client):
        import hashlib
        node = VulnerabilityNode(mock_neo4j_client)
        result = node.create("XSS", "high", source="nuclei")
        expected_id = hashlib.md5(b"XSS:high:nuclei").hexdigest()
        assert result["id"] == expected_id

    def test_cve_node_stores_cvss(self, mock_neo4j_client):
        node = CVENode(mock_neo4j_client)
        result = node.create("CVE-2024-1234", cvss_score=9.8, severity="critical")
        assert result["cvss_score"] == 9.8

    def test_mitre_data_node(self, mock_neo4j_client):
        node = MitreDataNode(mock_neo4j_client)
        result = node.create("CWE-79", name="XSS")
        assert result["cwe_id"] == "CWE-79"

    def test_capec_node_with_likelihood(self, mock_neo4j_client):
        node = CapecNode(mock_neo4j_client)
        result = node.create("CAPEC-63", name="XSS", likelihood="High")
        assert result["likelihood"] == "High"

    def test_exploit_node(self, mock_neo4j_client):
        node = ExploitNode(mock_neo4j_client)
        result = node.create("EDB-12345", "Apache RCE", exploit_type="remote")
        assert result["id"] == "EDB-12345"
        assert result["type"] == "remote"


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestAdvancedNodeTypes:
    """Day 70 — Session, Credential, Evidence, Tool, Scan, Finding, AuditEvent."""

    def test_evidence_node_required_fields(self, mock_neo4j_client):
        node = EvidenceNode(mock_neo4j_client)
        result = node.create(
            "ev-001",
            "request",
            "GET /admin HTTP/1.1\nHost: example.com",
            source_url="https://example.com/admin",
            description="Admin path accessible without auth",
            user_id="u1",
            project_id="p1",
        )
        assert result["id"] == "ev-001"
        assert result["evidence_type"] == "request"
        assert result["source_url"] == "https://example.com/admin"
        assert result["user_id"] == "u1"
        assert "discovered_at" in result
        call_label = mock_neo4j_client.create_node.call_args[0][0]
        assert call_label == "Evidence"

    def test_tool_node_id_includes_version(self, mock_neo4j_client):
        node = ToolNode(mock_neo4j_client)
        result = node.create("nuclei", version="3.1.0", tool_type="scanner")
        assert result["id"] == "nuclei:3.1.0"
        assert result["tool_type"] == "scanner"

    def test_tool_node_unknown_version(self, mock_neo4j_client):
        node = ToolNode(mock_neo4j_client)
        result = node.create("custom-tool")
        assert result["id"] == "custom-tool:unknown"

    def test_scan_node_with_config(self, mock_neo4j_client):
        node = ScanNode(mock_neo4j_client)
        result = node.create(
            "scan-abc",
            "nuclei",
            "https://example.com",
            status="completed",
            started_at="2026-02-22T08:00:00Z",
            completed_at="2026-02-22T08:10:00Z",
            config={"severity": ["high", "critical"]},
            user_id="u1",
            project_id="p1",
        )
        assert result["id"] == "scan-abc"
        assert result["tool_name"] == "nuclei"
        assert result["status"] == "completed"
        assert "config" in result  # stored as JSON string
        call_label = mock_neo4j_client.create_node.call_args[0][0]
        assert call_label == "Scan"

    def test_scan_node_default_status(self, mock_neo4j_client):
        node = ScanNode(mock_neo4j_client)
        result = node.create("scan-xyz", "nmap", "192.0.2.0/24")
        assert result["status"] == "completed"

    def test_finding_node_all_fields(self, mock_neo4j_client):
        node = FindingNode(mock_neo4j_client)
        result = node.create(
            "finding-001",
            "Exposed Admin Panel",
            "high",
            "misconfig",
            target="https://example.com/admin",
            description="Admin interface reachable without authentication",
            remediation="Restrict access to admin paths via IP allowlist",
            confidence=0.95,
            user_id="u1",
            project_id="p1",
        )
        assert result["id"] == "finding-001"
        assert result["severity"] == "high"
        assert result["confidence"] == 0.95
        assert result["user_id"] == "u1"
        call_label = mock_neo4j_client.create_node.call_args[0][0]
        assert call_label == "Finding"

    def test_finding_node_minimal(self, mock_neo4j_client):
        node = FindingNode(mock_neo4j_client)
        result = node.create("finding-002", "Open Port 22", "info", "exposure")
        assert result["finding_type"] == "exposure"
        assert "target" not in result

    def test_audit_event_node(self, mock_neo4j_client):
        node = AuditEventNode(mock_neo4j_client)
        result = node.create(
            "ae-001",
            "scan_started",
            "user@example.com",
            "created",
            resource_type="Scan",
            resource_id="scan-abc",
            outcome="success",
            details='{"tool": "nuclei"}',
            user_id="u1",
            project_id="p1",
        )
        assert result["id"] == "ae-001"
        assert result["event_type"] == "scan_started"
        assert result["outcome"] == "success"
        assert result["resource_type"] == "Scan"
        assert "timestamp" in result
        call_label = mock_neo4j_client.create_node.call_args[0][0]
        assert call_label == "AuditEvent"

    def test_audit_event_default_outcome(self, mock_neo4j_client):
        node = AuditEventNode(mock_neo4j_client)
        result = node.create("ae-002", "project_created", "admin", "created")
        assert result["outcome"] == "success"


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestRelationshipTypes:
    """Day 71 — Verify all 27 relationship types can be created."""

    # Helper: assert the last create_relationship call used the expected type
    @staticmethod
    def _last_rel_type(client) -> str:
        return client.create_relationship.call_args[0][6]

    def test_infrastructure_chain(self, mock_neo4j_client):
        """Infrastructure: HAS_SUBDOMAIN → RESOLVES_TO → HAS_PORT → RUNS_SERVICE
        → SERVES_URL → HAS_ENDPOINT → HAS_PARAMETER → USES_TECHNOLOGY
        → HAS_HEADER → HAS_CERTIFICATE → HAS_DNS_RECORD."""
        c = mock_neo4j_client
        link_domain_subdomain(c, "example.com", "www.example.com")
        assert self._last_rel_type(c) == "HAS_SUBDOMAIN"

        link_subdomain_ip(c, "www.example.com", "192.0.2.1")
        assert self._last_rel_type(c) == "RESOLVES_TO"

        link_ip_port(c, "192.0.2.1", "192.0.2.1:80/tcp")
        assert self._last_rel_type(c) == "HAS_PORT"

        link_port_service(c, "192.0.2.1:80/tcp", "http:2.4.41")
        assert self._last_rel_type(c) == "RUNS_SERVICE"

        link_port_baseurl(c, "192.0.2.1:80/tcp", "http://example.com")
        assert self._last_rel_type(c) == "SERVES_URL"

        link_baseurl_endpoint(c, "http://example.com", "GET:/api/users")
        assert self._last_rel_type(c) == "HAS_ENDPOINT"

        link_endpoint_parameter(c, "GET:/api/users", "page:query")
        assert self._last_rel_type(c) == "HAS_PARAMETER"

        link_baseurl_technology(c, "http://example.com", "Apache")
        assert self._last_rel_type(c) == "USES_TECHNOLOGY"

        link_baseurl_header(c, "http://example.com", "Server:Apache")
        assert self._last_rel_type(c) == "HAS_HEADER"

        link_baseurl_certificate(c, "https://example.com", "cert-123")
        assert self._last_rel_type(c) == "HAS_CERTIFICATE"

        link_subdomain_dnsrecord(c, "www.example.com", "A:192.0.2.1")
        assert self._last_rel_type(c) == "HAS_DNS_RECORD"

    def test_vulnerability_chain(self, mock_neo4j_client):
        """Vulnerability: FOUND_AT, AFFECTS_PARAMETER, HAS_VULNERABILITY,
        HAS_KNOWN_CVE, HAS_CWE, HAS_CAPEC, EXPLOITED_CVE, TARGETED_IP."""
        c = mock_neo4j_client
        link_vulnerability_endpoint(c, "vuln-hash", "GET:/search")
        assert self._last_rel_type(c) == "FOUND_AT"

        link_vulnerability_parameter(c, "vuln-hash", "q:query")
        assert self._last_rel_type(c) == "AFFECTS_PARAMETER"

        link_ip_vulnerability(c, "192.0.2.1", "vuln-hash")
        assert self._last_rel_type(c) == "HAS_VULNERABILITY"

        link_technology_cve(c, "Apache", "CVE-2024-1234")
        assert self._last_rel_type(c) == "HAS_KNOWN_CVE"

        link_cve_mitre(c, "CVE-2024-1234", "CWE-79")
        assert self._last_rel_type(c) == "HAS_CWE"

        link_mitre_capec(c, "CWE-79", "CAPEC-63")
        assert self._last_rel_type(c) == "HAS_CAPEC"

        link_exploit_cve(c, "EDB-12345", "CVE-2024-1234")
        assert self._last_rel_type(c) == "EXPLOITED_CVE"

        link_exploit_ip(c, "EDB-12345", "192.0.2.1")
        assert self._last_rel_type(c) == "TARGETED_IP"

    def test_session_credential_relationships(self, mock_neo4j_client):
        """Session/Credential: ESTABLISHED_SESSION, OPENED_ON,
        HAS_CREDENTIAL, VALIDATES_FOR."""
        c = mock_neo4j_client
        link_exploit_session(c, "EDB-12345", "sess-001")
        assert self._last_rel_type(c) == "ESTABLISHED_SESSION"

        link_session_ip(c, "sess-001", "192.0.2.1")
        assert self._last_rel_type(c) == "OPENED_ON"

        link_session_credential(c, "sess-001", "cred-001")
        assert self._last_rel_type(c) == "HAS_CREDENTIAL"

        link_credential_service(c, "cred-001", "ssh:7.9")
        assert self._last_rel_type(c) == "VALIDATES_FOR"

    def test_tool_scan_finding_evidence_relationships(self, mock_neo4j_client):
        """Tool/Scan/Finding/Evidence: PERFORMED_SCAN, PRODUCED_FINDING,
        SUPPORTED_BY, RELATED_TO."""
        c = mock_neo4j_client
        link_tool_scan(c, "nuclei:3.1.0", "scan-abc")
        assert self._last_rel_type(c) == "PERFORMED_SCAN"

        link_scan_finding(c, "scan-abc", "finding-001")
        assert self._last_rel_type(c) == "PRODUCED_FINDING"

        link_finding_evidence(c, "finding-001", "ev-001")
        assert self._last_rel_type(c) == "SUPPORTED_BY"

        link_finding_vulnerability(c, "finding-001", "vuln-hash")
        assert self._last_rel_type(c) == "RELATED_TO"

    def test_total_relationship_types_count(self):
        """Verify we define at least 20 relationship types in the registry."""
        assert len(EXPECTED_RELATIONSHIP_TYPES) >= 20


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

class TestSchemaValidation:
    """Day 72 — Schema validation script correctness."""

    def test_expected_node_labels_covers_all_types(self):
        """All 24 node types must be in the expected labels list."""
        required = [
            "Domain", "Subdomain", "IP", "Port", "Service",
            "BaseURL", "Endpoint", "Parameter", "Technology",
            "Header", "Certificate", "DNSRecord",
            "Vulnerability", "CVE", "MitreData", "Capec", "Exploit",
            "Session", "Credential",
            "Evidence", "Tool", "Scan", "Finding", "AuditEvent",
        ]
        for label in required:
            assert label in EXPECTED_NODE_LABELS, (
                f"{label} missing from EXPECTED_NODE_LABELS"
            )

    def test_expected_relationship_types_completeness(self):
        """All 27 relationship types must appear in the registry."""
        required = [
            "HAS_SUBDOMAIN", "RESOLVES_TO", "HAS_PORT", "RUNS_SERVICE",
            "SERVES_URL", "HAS_ENDPOINT", "HAS_PARAMETER", "USES_TECHNOLOGY",
            "HAS_HEADER", "HAS_CERTIFICATE", "HAS_DNS_RECORD",
            "FOUND_AT", "AFFECTS_PARAMETER", "HAS_VULNERABILITY",
            "HAS_KNOWN_CVE", "HAS_CWE", "HAS_CAPEC",
            "EXPLOITED_CVE", "TARGETED_IP",
            "ESTABLISHED_SESSION", "OPENED_ON", "HAS_CREDENTIAL",
            "VALIDATES_FOR",
            "PERFORMED_SCAN", "PRODUCED_FINDING", "SUPPORTED_BY", "RELATED_TO",
        ]
        for rel in required:
            assert rel in EXPECTED_RELATIONSHIP_TYPES, (
                f"{rel} missing from EXPECTED_RELATIONSHIP_TYPES"
            )

    def test_expected_constraints_covers_all_labels(self):
        """Every node label must have a uniqueness constraint defined."""
        for label in EXPECTED_NODE_LABELS:
            assert label in EXPECTED_CONSTRAINTS, (
                f"{label} missing from EXPECTED_CONSTRAINTS"
            )

    def test_validate_schema_no_constraints_in_db(self, mock_neo4j_client):
        """validate_schema reports missing constraints when DB is empty."""
        # execute_query returns [] → no constraints found
        mock_neo4j_client.execute_query.return_value = []
        report = validate_schema(mock_neo4j_client, check_live_data=False)
        assert report["constraints_ok"] is False
        assert len(report["missing_constraints"]) == len(EXPECTED_CONSTRAINTS)
        assert report["valid"] is False

    def test_validate_schema_all_constraints_present(self, mock_neo4j_client):
        """validate_schema reports valid when all constraints are present."""
        # Build fake constraint records that cover all expected labels/props
        fake_constraints = [
            {
                "type": "UNIQUENESS",
                "labelsOrTypes": [label],
                "properties": [prop],
                "name": f"constraint_{label}_{prop}",
            }
            for label, prop in EXPECTED_CONSTRAINTS.items()
        ]
        mock_neo4j_client.execute_query.return_value = fake_constraints
        report = validate_schema(mock_neo4j_client, check_live_data=False)
        assert report["constraints_ok"] is True
        assert report["missing_constraints"] == []
        assert report["valid"] is True

    def test_ensure_constraints_creates_missing(self, mock_neo4j_client):
        """ensure_constraints creates all constraints when DB is empty."""
        # First call (get existing constraints) returns []
        mock_neo4j_client.execute_query.side_effect = [
            [],   # _get_db_constraints()
            *[[] for _ in EXPECTED_CONSTRAINTS],  # one per CREATE call
        ]
        result = ensure_constraints(mock_neo4j_client)
        assert result["created"] == len(EXPECTED_CONSTRAINTS)
        assert result["already_exist"] == 0
        assert result["failed"] == 0

    def test_ensure_constraints_skips_existing(self, mock_neo4j_client):
        """ensure_constraints skips labels that already have constraints."""
        # Return all expected constraints as already existing
        fake_constraints = [
            {
                "type": "UNIQUENESS",
                "labelsOrTypes": [label],
                "properties": [prop],
                "name": f"constraint_{label}_{prop}",
            }
            for label, prop in EXPECTED_CONSTRAINTS.items()
        ]
        mock_neo4j_client.execute_query.return_value = fake_constraints
        result = ensure_constraints(mock_neo4j_client)
        assert result["already_exist"] == len(EXPECTED_CONSTRAINTS)
        assert result["created"] == 0

    def test_run_smoke_queries_all_pass(self, mock_neo4j_client):
        """run_smoke_queries reports all_passed when execute_query succeeds."""
        mock_neo4j_client.execute_query.return_value = [{"cnt": 0}]
        result = run_smoke_queries(mock_neo4j_client)
        assert result["all_passed"] is True

    def test_run_smoke_queries_one_fail(self, mock_neo4j_client):
        """run_smoke_queries reports failure when a query raises an exception."""
        call_count = 0

        def _side_effect(query, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("syntax error")
            return [{"cnt": 0}]

        mock_neo4j_client.execute_query.side_effect = _side_effect
        result = run_smoke_queries(mock_neo4j_client)
        assert result["all_passed"] is False
        # At least one key should report a failure string
        failures = [v for k, v in result.items() if k != "all_passed" and v != "pass"]
        assert len(failures) >= 1
