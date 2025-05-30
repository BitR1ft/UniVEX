"""
Neo4j Relationship Handlers.
Implements all relationship types for the attack surface graph database.
"""

from typing import Dict, Optional, Any
from app.db.neo4j_client import Neo4jClient
import logging

logger = logging.getLogger(__name__)


def create_relationship(
    client: Neo4jClient,
    from_label: str,
    from_property: str,
    from_value: Any,
    to_label: str,
    to_property: str,
    to_value: Any,
    rel_type: str,
    rel_properties: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Generic relationship creation function.
    
    Args:
        client: Neo4j client instance
        from_label: Source node label
        from_property: Source node property to match
        from_value: Source node property value
        to_label: Target node label
        to_property: Target node property to match
        to_value: Target node property value
        rel_type: Relationship type
        rel_properties: Optional relationship properties
        
    Returns:
        True if relationship created successfully
    """
    try:
        return client.create_relationship(
            from_label, from_property, from_value,
            to_label, to_property, to_value,
            rel_type, rel_properties
        )
    except Exception as e:
        logger.error(f"Failed to create relationship {rel_type}: {e}")
        return False


def link_domain_subdomain(
    client: Neo4jClient,
    domain_name: str,
    subdomain_name: str,
    **rel_props
) -> bool:
    """Create HAS_SUBDOMAIN relationship from Domain to Subdomain."""
    return create_relationship(
        client,
        'Domain', 'name', domain_name,
        'Subdomain', 'name', subdomain_name,
        'HAS_SUBDOMAIN',
        rel_props or None
    )


def link_subdomain_ip(
    client: Neo4jClient,
    subdomain_name: str,
    ip_address: str,
    **rel_props
) -> bool:
    """Create RESOLVES_TO relationship from Subdomain to IP."""
    return create_relationship(
        client,
        'Subdomain', 'name', subdomain_name,
        'IP', 'address', ip_address,
        'RESOLVES_TO',
        rel_props or None
    )


def link_ip_port(
    client: Neo4jClient,
    ip_address: str,
    port_id: str,
    **rel_props
) -> bool:
    """Create HAS_PORT relationship from IP to Port."""
    return create_relationship(
        client,
        'IP', 'address', ip_address,
        'Port', 'id', port_id,
        'HAS_PORT',
        rel_props or None
    )


def link_port_service(
    client: Neo4jClient,
    port_id: str,
    service_id: str,
    **rel_props
) -> bool:
    """Create RUNS_SERVICE relationship from Port to Service."""
    return create_relationship(
        client,
        'Port', 'id', port_id,
        'Service', 'id', service_id,
        'RUNS_SERVICE',
        rel_props or None
    )


def link_port_baseurl(
    client: Neo4jClient,
    port_id: str,
    base_url: str,
    **rel_props
) -> bool:
    """Create SERVES_URL relationship from Port to BaseURL."""
    return create_relationship(
        client,
        'Port', 'id', port_id,
        'BaseURL', 'url', base_url,
        'SERVES_URL',
        rel_props or None
    )


def link_baseurl_endpoint(
    client: Neo4jClient,
    base_url: str,
    endpoint_id: str,
    **rel_props
) -> bool:
    """Create HAS_ENDPOINT relationship from BaseURL to Endpoint."""
    return create_relationship(
        client,
        'BaseURL', 'url', base_url,
        'Endpoint', 'id', endpoint_id,
        'HAS_ENDPOINT',
        rel_props or None
    )


def link_endpoint_parameter(
    client: Neo4jClient,
    endpoint_id: str,
    parameter_id: str,
    **rel_props
) -> bool:
    """Create HAS_PARAMETER relationship from Endpoint to Parameter."""
    return create_relationship(
        client,
        'Endpoint', 'id', endpoint_id,
        'Parameter', 'id', parameter_id,
        'HAS_PARAMETER',
        rel_props or None
    )


def link_baseurl_technology(
    client: Neo4jClient,
    base_url: str,
    technology_name: str,
    **rel_props
) -> bool:
    """Create USES_TECHNOLOGY relationship from BaseURL to Technology."""
    return create_relationship(
        client,
        'BaseURL', 'url', base_url,
        'Technology', 'name', technology_name,
        'USES_TECHNOLOGY',
        rel_props or None
    )


def link_baseurl_header(
    client: Neo4jClient,
    base_url: str,
    header_id: str,
    **rel_props
) -> bool:
    """Create HAS_HEADER relationship from BaseURL to Header."""
    return create_relationship(
        client,
        'BaseURL', 'url', base_url,
        'Header', 'id', header_id,
        'HAS_HEADER',
        rel_props or None
    )


def link_baseurl_certificate(
    client: Neo4jClient,
    base_url: str,
    certificate_id: str,
    **rel_props
) -> bool:
    """Create HAS_CERTIFICATE relationship from BaseURL to Certificate."""
    return create_relationship(
        client,
        'BaseURL', 'url', base_url,
        'Certificate', 'id', certificate_id,
        'HAS_CERTIFICATE',
        rel_props or None
    )


def link_subdomain_dnsrecord(
    client: Neo4jClient,
    subdomain_name: str,
    dns_record_id: str,
    **rel_props
) -> bool:
    """Create HAS_DNS_RECORD relationship from Subdomain to DNSRecord."""
    return create_relationship(
        client,
        'Subdomain', 'name', subdomain_name,
        'DNSRecord', 'id', dns_record_id,
        'HAS_DNS_RECORD',
        rel_props or None
    )


def link_vulnerability_endpoint(
    client: Neo4jClient,
    vulnerability_id: str,
    endpoint_id: str,
    **rel_props
) -> bool:
    """Create FOUND_AT relationship from Vulnerability to Endpoint."""
    return create_relationship(
        client,
        'Vulnerability', 'id', vulnerability_id,
        'Endpoint', 'id', endpoint_id,
        'FOUND_AT',
        rel_props or None
    )


def link_vulnerability_parameter(
    client: Neo4jClient,
    vulnerability_id: str,
    parameter_id: str,
    **rel_props
) -> bool:
    """Create AFFECTS_PARAMETER relationship from Vulnerability to Parameter."""
    return create_relationship(
        client,
        'Vulnerability', 'id', vulnerability_id,
        'Parameter', 'id', parameter_id,
        'AFFECTS_PARAMETER',
        rel_props or None
    )


def link_ip_vulnerability(
    client: Neo4jClient,
    ip_address: str,
    vulnerability_id: str,
    **rel_props
) -> bool:
    """Create HAS_VULNERABILITY relationship from IP to Vulnerability (for GVM scans)."""
    return create_relationship(
        client,
        'IP', 'address', ip_address,
        'Vulnerability', 'id', vulnerability_id,
        'HAS_VULNERABILITY',
        rel_props or None
    )


def link_technology_cve(
    client: Neo4jClient,
    technology_name: str,
    cve_id: str,
    **rel_props
) -> bool:
    """Create HAS_KNOWN_CVE relationship from Technology to CVE."""
    return create_relationship(
        client,
        'Technology', 'name', technology_name,
        'CVE', 'id', cve_id,
        'HAS_KNOWN_CVE',
        rel_props or None
    )


def link_cve_mitre(
    client: Neo4jClient,
    cve_id: str,
    cwe_id: str,
    **rel_props
) -> bool:
    """Create HAS_CWE relationship from CVE to MitreData."""
    return create_relationship(
        client,
        'CVE', 'id', cve_id,
        'MitreData', 'id', cwe_id,
        'HAS_CWE',
        rel_props or None
    )


def link_mitre_capec(
    client: Neo4jClient,
    cwe_id: str,
    capec_id: str,
    **rel_props
) -> bool:
    """Create HAS_CAPEC relationship from MitreData to Capec."""
    return create_relationship(
        client,
        'MitreData', 'id', cwe_id,
        'Capec', 'id', capec_id,
        'HAS_CAPEC',
        rel_props or None
    )


def link_exploit_cve(
    client: Neo4jClient,
    exploit_id: str,
    cve_id: str,
    **rel_props
) -> bool:
    """Create EXPLOITED_CVE relationship from Exploit to CVE."""
    return create_relationship(
        client,
        'Exploit', 'id', exploit_id,
        'CVE', 'id', cve_id,
        'EXPLOITED_CVE',
        rel_props or None
    )


def link_exploit_ip(
    client: Neo4jClient,
    exploit_id: str,
    ip_address: str,
    **rel_props
) -> bool:
    """Create TARGETED_IP relationship from Exploit to IP."""
    return create_relationship(
        client,
        'Exploit', 'id', exploit_id,
        'IP', 'address', ip_address,
        'TARGETED_IP',
        rel_props or None
    )


# ── Session & Credential relationships ──────────────────────────────────────

def link_exploit_session(
    client: Neo4jClient,
    exploit_id: str,
    session_id: str,
    **rel_props
) -> bool:
    """Create ESTABLISHED_SESSION relationship from Exploit to Session."""
    return create_relationship(
        client,
        'Exploit', 'id', exploit_id,
        'Session', 'id', session_id,
        'ESTABLISHED_SESSION',
        rel_props or None
    )


def link_session_ip(
    client: Neo4jClient,
    session_id: str,
    ip_address: str,
    **rel_props
) -> bool:
    """Create OPENED_ON relationship from Session to IP."""
    return create_relationship(
        client,
        'Session', 'id', session_id,
        'IP', 'address', ip_address,
        'OPENED_ON',
        rel_props or None
    )


def link_session_credential(
    client: Neo4jClient,
    session_id: str,
    credential_id: str,
    **rel_props
) -> bool:
    """Create HAS_CREDENTIAL relationship from Session to Credential."""
    return create_relationship(
        client,
        'Session', 'id', session_id,
        'Credential', 'id', credential_id,
        'HAS_CREDENTIAL',
        rel_props or None
    )


def link_credential_service(
    client: Neo4jClient,
    credential_id: str,
    service_id: str,
    **rel_props
) -> bool:
    """Create VALIDATES_FOR relationship from Credential to Service."""
    return create_relationship(
        client,
        'Credential', 'id', credential_id,
        'Service', 'id', service_id,
        'VALIDATES_FOR',
        rel_props or None
    )


# ── Tool, Scan, Finding & Evidence relationships ─────────────────────────────

def link_tool_scan(
    client: Neo4jClient,
    tool_id: str,
    scan_id: str,
    **rel_props
) -> bool:
    """Create PERFORMED_SCAN relationship from Tool to Scan."""
    return create_relationship(
        client,
        'Tool', 'id', tool_id,
        'Scan', 'id', scan_id,
        'PERFORMED_SCAN',
        rel_props or None
    )


def link_scan_finding(
    client: Neo4jClient,
    scan_id: str,
    finding_id: str,
    **rel_props
) -> bool:
    """Create PRODUCED_FINDING relationship from Scan to Finding."""
    return create_relationship(
        client,
        'Scan', 'id', scan_id,
        'Finding', 'id', finding_id,
        'PRODUCED_FINDING',
        rel_props or None
    )


def link_finding_evidence(
    client: Neo4jClient,
    finding_id: str,
    evidence_id: str,
    **rel_props
) -> bool:
    """Create SUPPORTED_BY relationship from Finding to Evidence."""
    return create_relationship(
        client,
        'Finding', 'id', finding_id,
        'Evidence', 'id', evidence_id,
        'SUPPORTED_BY',
        rel_props or None
    )


def link_finding_vulnerability(
    client: Neo4jClient,
    finding_id: str,
    vulnerability_id: str,
    **rel_props
) -> bool:
    """Create RELATED_TO relationship from Finding to Vulnerability."""
    return create_relationship(
        client,
        'Finding', 'id', finding_id,
        'Vulnerability', 'id', vulnerability_id,
        'RELATED_TO',
        rel_props or None
    )
