"""
Data Ingestion Pipeline for Neo4j Graph Database.
Ingests data from all reconnaissance phases and vulnerability scans.
"""

from typing import Dict, List, Optional, Any
from app.db.neo4j_client import Neo4jClient
from app.graph.nodes import (
    DomainNode, SubdomainNode, IPNode, PortNode, ServiceNode,
    BaseURLNode, EndpointNode, ParameterNode, TechnologyNode,
    HeaderNode, CertificateNode, DNSRecordNode, VulnerabilityNode,
    CVENode, MitreDataNode, CapecNode
)
from app.graph.relationships import (
    link_domain_subdomain, link_subdomain_ip, link_subdomain_dnsrecord,
    link_ip_port, link_port_service, link_port_baseurl,
    link_baseurl_endpoint, link_endpoint_parameter,
    link_baseurl_technology, link_baseurl_header, link_baseurl_certificate,
    link_vulnerability_endpoint, link_ip_vulnerability,
    link_technology_cve, link_cve_mitre, link_mitre_capec
)
import logging

logger = logging.getLogger(__name__)


class GraphIngestion:
    """Handles data ingestion into Neo4j graph database."""
    
    def __init__(self, neo4j_client: Neo4jClient):
        self.client = neo4j_client
        
        # Initialize node handlers
        self.domain_node = DomainNode(neo4j_client)
        self.subdomain_node = SubdomainNode(neo4j_client)
        self.ip_node = IPNode(neo4j_client)
        self.port_node = PortNode(neo4j_client)
        self.service_node = ServiceNode(neo4j_client)
        self.baseurl_node = BaseURLNode(neo4j_client)
        self.endpoint_node = EndpointNode(neo4j_client)
        self.parameter_node = ParameterNode(neo4j_client)
        self.technology_node = TechnologyNode(neo4j_client)
        self.header_node = HeaderNode(neo4j_client)
        self.certificate_node = CertificateNode(neo4j_client)
        self.dnsrecord_node = DNSRecordNode(neo4j_client)
        self.vulnerability_node = VulnerabilityNode(neo4j_client)
        self.cve_node = CVENode(neo4j_client)
        self.mitre_node = MitreDataNode(neo4j_client)
        self.capec_node = CapecNode(neo4j_client)
    
    def ingest_domain_discovery(
        self,
        data: Dict[str, Any],
        user_id: Optional[str] = None,
        project_id: Optional[str] = None
    ) -> Dict[str, int]:
        """
        Ingest Phase 1 - Domain Discovery data.
        
        Args:
            data: Domain discovery JSON data
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            
        Returns:
            Statistics of ingested nodes
        """
        stats = {
            'domains': 0,
            'subdomains': 0,
            'ips': 0,
            'dns_records': 0,
            'relationships': 0
        }
        
        try:
            domain_name = data.get('domain')
            if not domain_name:
                logger.error("No domain name in data")
                return stats
            
            # Create Domain node
            whois_data = data.get('whois')
            self.domain_node.create(
                name=domain_name,
                whois_data=whois_data,
                user_id=user_id,
                project_id=project_id
            )
            stats['domains'] += 1
            
            # Process subdomains
            subdomains = data.get('subdomains', [])
            dns_records = data.get('dns_records', {})
            ip_mapping = data.get('ip_mapping', {})
            
            for subdomain in subdomains:
                # Create Subdomain node
                dns_result = dns_records.get(subdomain, {})
                self.subdomain_node.create(
                    name=subdomain,
                    parent_domain=domain_name,
                    dns_records=dns_result.get('records'),
                    user_id=user_id,
                    project_id=project_id
                )
                stats['subdomains'] += 1
                
                # Link Domain -> Subdomain
                if link_domain_subdomain(self.client, domain_name, subdomain):
                    stats['relationships'] += 1
                
                # Process IP addresses
                ips = ip_mapping.get(subdomain, [])
                for ip in ips:
                    # Create IP node
                    self.ip_node.create(
                        address=ip,
                        user_id=user_id,
                        project_id=project_id
                    )
                    stats['ips'] += 1
                    
                    # Link Subdomain -> IP
                    if link_subdomain_ip(self.client, subdomain, ip):
                        stats['relationships'] += 1
                
                # Process DNS records
                records = dns_result.get('records', {})
                if records:
                    for record_type, values in records.items():
                        if isinstance(values, list):
                            for value in values:
                                if value:  # Skip empty values
                                    self.dnsrecord_node.create(
                                        record_type=record_type,
                                        value=value,
                                        subdomain=subdomain,
                                        user_id=user_id,
                                        project_id=project_id
                                    )
                                    stats['dns_records'] += 1
                                    
                                    # Link Subdomain -> DNSRecord
                                    record_id = f"{record_type}:{value}"
                                    if link_subdomain_dnsrecord(self.client, subdomain, record_id):
                                        stats['relationships'] += 1
            
            logger.info(f"Ingested domain discovery data: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"Error ingesting domain discovery data: {e}")
            return stats
    
    def ingest_port_scan(
        self,
        data: Dict[str, Any],
        user_id: Optional[str] = None,
        project_id: Optional[str] = None
    ) -> Dict[str, int]:
        """
        Ingest Phase 2 - Port Scan data.
        
        Args:
            data: Port scan JSON data
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            
        Returns:
            Statistics of ingested nodes
        """
        stats = {
            'ips': 0,
            'ports': 0,
            'services': 0,
            'relationships': 0
        }
        
        try:
            # Process scanned IPs
            scanned_ips = data.get('scanned_ips', [])
            
            for ip_data in scanned_ips:
                ip_address = ip_data.get('ip')
                if not ip_address:
                    continue
                
                # Update/Create IP node with additional info
                cdn_info = ip_data.get('cdn_info')
                asn_info = ip_data.get('asn_info')
                
                self.ip_node.create(
                    address=ip_address,
                    cdn_info=cdn_info,
                    asn_info=asn_info,
                    user_id=user_id,
                    project_id=project_id
                )
                stats['ips'] += 1
                
                # Process ports
                ports = ip_data.get('ports', [])
                for port_data in ports:
                    port_number = port_data.get('port')
                    protocol = port_data.get('protocol', 'tcp')
                    state = port_data.get('state', 'open')
                    
                    # Create Port node
                    port_node_data = self.port_node.create(
                        ip=ip_address,
                        number=port_number,
                        protocol=protocol,
                        state=state,
                        user_id=user_id,
                        project_id=project_id
                    )
                    port_id = port_node_data.get('id', f"{ip_address}:{port_number}/{protocol}")
                    stats['ports'] += 1
                    
                    # Link IP -> Port
                    if link_ip_port(self.client, ip_address, port_id):
                        stats['relationships'] += 1
                    
                    # Process service
                    service_name = port_data.get('service')
                    if service_name:
                        version = port_data.get('version')
                        banner = port_data.get('banner')
                        
                        service_node_data = self.service_node.create(
                            name=service_name,
                            version=version,
                            banner=banner,
                            user_id=user_id,
                            project_id=project_id
                        )
                        service_id = service_node_data.get('id', f"{service_name}:{version or 'unknown'}")
                        stats['services'] += 1
                        
                        # Link Port -> Service
                        if link_port_service(self.client, port_id, service_id):
                            stats['relationships'] += 1
            
            logger.info(f"Ingested port scan data: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"Error ingesting port scan data: {e}")
            return stats
    
    def ingest_http_probe(
        self,
        data: Dict[str, Any],
        user_id: Optional[str] = None,
        project_id: Optional[str] = None
    ) -> Dict[str, int]:
        """
        Ingest Phase 3 - HTTP Probe data.
        
        Args:
            data: HTTP probe JSON data
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            
        Returns:
            Statistics of ingested nodes
        """
        stats = {
            'base_urls': 0,
            'technologies': 0,
            'headers': 0,
            'certificates': 0,
            'relationships': 0
        }
        
        try:
            # Process probed URLs
            probed_urls = data.get('probed_urls', [])
            
            for url_data in probed_urls:
                url = url_data.get('url')
                if not url:
                    continue
                
                # Create BaseURL node
                http_metadata = {
                    'status_code': url_data.get('status_code'),
                    'content_type': url_data.get('content_type'),
                    'content_length': url_data.get('content_length'),
                    'server': url_data.get('server'),
                    'title': url_data.get('title'),
                    'response_time': url_data.get('response_time'),
                }
                
                self.baseurl_node.create(
                    url=url,
                    http_metadata=http_metadata,
                    user_id=user_id,
                    project_id=project_id
                )
                stats['base_urls'] += 1
                
                # Link Port -> BaseURL
                port = url_data.get('port')
                ip = url_data.get('ip')
                if port and ip:
                    port_id = f"{ip}:{port}/tcp"
                    if link_port_baseurl(self.client, port_id, url):
                        stats['relationships'] += 1
                
                # Process technologies
                technologies = url_data.get('technologies', [])
                for tech in technologies:
                    tech_name = tech.get('name')
                    if tech_name:
                        self.technology_node.create(
                            name=tech_name,
                            version=tech.get('version'),
                            confidence=tech.get('confidence'),
                            categories=tech.get('categories', []),
                            user_id=user_id,
                            project_id=project_id
                        )
                        stats['technologies'] += 1
                        
                        # Link BaseURL -> Technology
                        if link_baseurl_technology(self.client, url, tech_name):
                            stats['relationships'] += 1
                
                # Process headers
                headers = url_data.get('headers', {})
                for header_name, header_value in headers.items():
                    if header_name and header_value:
                        header_node_data = self.header_node.create(
                            name=header_name,
                            value=header_value,
                            user_id=user_id,
                            project_id=project_id
                        )
                        header_id = header_node_data.get('id', f"{header_name}:{header_value}")
                        stats['headers'] += 1
                        
                        # Link BaseURL -> Header
                        if link_baseurl_header(self.client, url, header_id):
                            stats['relationships'] += 1
                
                # Process TLS certificate
                tls_data = url_data.get('tls', {})
                if tls_data:
                    cert = tls_data.get('certificate', {})
                    if cert:
                        cert_node_data = self.certificate_node.create(
                            subject=cert.get('subject', ''),
                            issuer=cert.get('issuer'),
                            valid_from=cert.get('valid_from'),
                            valid_to=cert.get('valid_to'),
                            serial_number=cert.get('serial_number'),
                            user_id=user_id,
                            project_id=project_id
                        )
                        cert_id = cert_node_data.get('id')
                        if cert_id:
                            stats['certificates'] += 1
                            
                            # Link BaseURL -> Certificate
                            if link_baseurl_certificate(self.client, url, cert_id):
                                stats['relationships'] += 1
            
            logger.info(f"Ingested HTTP probe data: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"Error ingesting HTTP probe data: {e}")
            return stats
    
    def ingest_resource_enumeration(
        self,
        data: Dict[str, Any],
        user_id: Optional[str] = None,
        project_id: Optional[str] = None
    ) -> Dict[str, int]:
        """
        Ingest Phase 4 - Resource Enumeration data.
        
        Args:
            data: Resource enumeration JSON data
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            
        Returns:
            Statistics of ingested nodes
        """
        stats = {
            'endpoints': 0,
            'parameters': 0,
            'relationships': 0
        }
        
        try:
            # Process discovered endpoints
            endpoints = data.get('endpoints', [])
            
            for endpoint_data in endpoints:
                path = endpoint_data.get('path')
                if not path:
                    continue
                
                method = endpoint_data.get('method', 'GET')
                base_url = endpoint_data.get('base_url')
                
                # Create Endpoint node
                endpoint_node_data = self.endpoint_node.create(
                    path=path,
                    method=method,
                    base_url=base_url,
                    user_id=user_id,
                    project_id=project_id,
                    status_code=endpoint_data.get('status_code'),
                    content_type=endpoint_data.get('content_type'),
                )
                endpoint_id = endpoint_node_data.get('id', f"{method}:{path}")
                stats['endpoints'] += 1
                
                # Link BaseURL -> Endpoint
                if base_url and link_baseurl_endpoint(self.client, base_url, endpoint_id):
                    stats['relationships'] += 1
                
                # Process parameters
                parameters = endpoint_data.get('parameters', [])
                for param in parameters:
                    param_name = param.get('name')
                    if param_name:
                        param_type = param.get('type', 'query')
                        example_value = param.get('example_value')
                        
                        param_node_data = self.parameter_node.create(
                            name=param_name,
                            param_type=param_type,
                            example_value=example_value,
                            user_id=user_id,
                            project_id=project_id
                        )
                        param_id = param_node_data.get('id', f"{param_name}:{param_type}")
                        stats['parameters'] += 1
                        
                        # Link Endpoint -> Parameter
                        if link_endpoint_parameter(self.client, endpoint_id, param_id):
                            stats['relationships'] += 1
            
            logger.info(f"Ingested resource enumeration data: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"Error ingesting resource enumeration data: {e}")
            return stats

    def ingest_ffuf_results(
        self,
        data: Dict[str, Any],
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
    ) -> Dict[str, int]:
        """
        Ingest ffuf web-fuzzing results into the Neo4j graph.

        Creates ``Endpoint`` nodes for each discovered path and links them to
        the parent ``BaseURL`` node (if one already exists for the base URL).

        Args:
            data: ffuf result dict as returned by ``FfufServer._run_ffuf()``.
                  Expected structure::

                      {
                          "url": "http://10.10.10.1/",
                          "results": [
                              {
                                  "path": "/admin",
                                  "method": "GET",
                                  "base_url": "http://10.10.10.1/",
                                  "status_code": 200,
                                  "content_length": 1024,
                                  "discovered_by": "ffuf",
                              },
                              ...
                          ]
                      }

            user_id:    Optional user identifier for multi-tenancy.
            project_id: Optional project identifier for multi-tenancy.

        Returns:
            Statistics dict: ``{endpoints, relationships}``
        """
        stats: Dict[str, int] = {"endpoints": 0, "relationships": 0}

        try:
            base_url: Optional[str] = data.get("url")
            results: List[Dict[str, Any]] = data.get("results", [])

            for endpoint_data in results:
                path = endpoint_data.get("path")
                if not path:
                    continue

                method = endpoint_data.get("method", "GET")
                ep_base_url = endpoint_data.get("base_url") or base_url

                endpoint_node_data = self.endpoint_node.create(
                    path=path,
                    method=method,
                    base_url=ep_base_url,
                    user_id=user_id,
                    project_id=project_id,
                    status_code=endpoint_data.get("status_code"),
                    content_length=endpoint_data.get("content_length"),
                    discovered_by=endpoint_data.get("discovered_by", "ffuf"),
                )
                endpoint_id = endpoint_node_data.get("id", f"{method}:{path}")
                stats["endpoints"] += 1

                # Link BaseURL → Endpoint (if a BaseURL node exists for this URL)
                if ep_base_url:
                    from app.graph.relationships import link_baseurl_endpoint

                    if link_baseurl_endpoint(self.client, ep_base_url, endpoint_id):
                        stats["relationships"] += 1

            logger.info("Ingested ffuf results: %s", stats)
            return stats

        except Exception as exc:
            logger.error("Error ingesting ffuf results: %s", exc)
            return stats

    def ingest_vulnerability_scan(
        self,
        data: Dict[str, Any],
        user_id: Optional[str] = None,
        project_id: Optional[str] = None
    ) -> Dict[str, int]:
        """
        Ingest Phase 5 - Vulnerability Scan data.
        
        Args:
            data: Vulnerability scan JSON data
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            
        Returns:
            Statistics of ingested nodes
        """
        stats = {
            'vulnerabilities': 0,
            'cves': 0,
            'relationships': 0
        }
        
        try:
            # Process vulnerabilities
            vulnerabilities = data.get('vulnerabilities', [])
            
            for vuln_data in vulnerabilities:
                vuln_name = vuln_data.get('name') or vuln_data.get('template_id')
                if not vuln_name:
                    continue
                
                # Create Vulnerability node
                vuln_node_data = self.vulnerability_node.create(
                    name=vuln_name,
                    severity=vuln_data.get('severity', 'info'),
                    category=vuln_data.get('category'),
                    source=vuln_data.get('source', 'nuclei'),
                    description=vuln_data.get('description'),
                    user_id=user_id,
                    project_id=project_id,
                    template_id=vuln_data.get('template_id'),
                    matcher_name=vuln_data.get('matcher_name'),
                    tags=vuln_data.get('tags', []),
                )
                vuln_id = vuln_node_data.get('id')
                stats['vulnerabilities'] += 1
                
                # Link to endpoint if available
                endpoint = vuln_data.get('endpoint')
                if endpoint:
                    # Assuming endpoint is a path
                    endpoint_id = f"GET:{endpoint}"
                    if link_vulnerability_endpoint(self.client, vuln_id, endpoint_id):
                        stats['relationships'] += 1
                
                # Link to IP if available (for GVM vulnerabilities)
                ip = vuln_data.get('ip')
                if ip:
                    if link_ip_vulnerability(self.client, ip, vuln_id):
                        stats['relationships'] += 1
                
                # Process associated CVEs
                cve_ids = vuln_data.get('cve_ids', [])
                for cve_id in cve_ids:
                    if cve_id:
                        # Check if CVE data is enriched
                        cve_data = vuln_data.get('cve_data', {}).get(cve_id, {})
                        
                        self.cve_node.create(
                            cve_id=cve_id,
                            cvss_score=cve_data.get('cvss_score'),
                            severity=cve_data.get('severity'),
                            description=cve_data.get('description'),
                            published_date=cve_data.get('published_date'),
                            user_id=user_id,
                            project_id=project_id
                        )
                        stats['cves'] += 1
                        
                        # Link Technology -> CVE if technology is specified
                        technology = vuln_data.get('technology')
                        if technology:
                            if link_technology_cve(self.client, technology, cve_id):
                                stats['relationships'] += 1
            
            logger.info(f"Ingested vulnerability scan data: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"Error ingesting vulnerability scan data: {e}")
            return stats
    
    def ingest_mitre_data(
        self,
        data: Dict[str, Any],
        user_id: Optional[str] = None,
        project_id: Optional[str] = None
    ) -> Dict[str, int]:
        """
        Ingest MITRE ATT&CK data (CWE and CAPEC mappings).
        
        Args:
            data: MITRE mapping JSON data
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            
        Returns:
            Statistics of ingested nodes
        """
        stats = {
            'cwe': 0,
            'capec': 0,
            'relationships': 0
        }
        
        try:
            # Process CWE mappings
            cwe_mappings = data.get('cwe_mappings', [])
            
            for cwe_mapping in cwe_mappings:
                cwe_id = cwe_mapping.get('cwe_id')
                if not cwe_id:
                    continue
                
                # Create MitreData (CWE) node
                self.mitre_node.create(
                    cwe_id=cwe_id,
                    name=cwe_mapping.get('name'),
                    description=cwe_mapping.get('description'),
                    user_id=user_id,
                    project_id=project_id
                )
                stats['cwe'] += 1
                
                # Link CVE -> CWE
                cve_id = cwe_mapping.get('cve_id')
                if cve_id:
                    if link_cve_mitre(self.client, cve_id, cwe_id):
                        stats['relationships'] += 1
                
                # Process CAPEC mappings
                capec_ids = cwe_mapping.get('capec_ids', [])
                for capec_data in capec_ids:
                    if isinstance(capec_data, dict):
                        capec_id = capec_data.get('capec_id')
                        if capec_id:
                            self.capec_node.create(
                                capec_id=capec_id,
                                name=capec_data.get('name'),
                                description=capec_data.get('description'),
                                likelihood=capec_data.get('likelihood'),
                                severity=capec_data.get('severity'),
                                user_id=user_id,
                                project_id=project_id
                            )
                            stats['capec'] += 1
                            
                            # Link CWE -> CAPEC
                            if link_mitre_capec(self.client, cwe_id, capec_id):
                                stats['relationships'] += 1
            
            logger.info(f"Ingested MITRE data: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"Error ingesting MITRE data: {e}")
            return stats


# Convenience functions for direct ingestion
def ingest_domain_discovery(
    neo4j_client: Neo4jClient,
    data: Dict[str, Any],
    user_id: Optional[str] = None,
    project_id: Optional[str] = None
) -> Dict[str, int]:
    """Ingest domain discovery data."""
    ingestion = GraphIngestion(neo4j_client)
    return ingestion.ingest_domain_discovery(data, user_id, project_id)


def ingest_port_scan(
    neo4j_client: Neo4jClient,
    data: Dict[str, Any],
    user_id: Optional[str] = None,
    project_id: Optional[str] = None
) -> Dict[str, int]:
    """Ingest port scan data."""
    ingestion = GraphIngestion(neo4j_client)
    return ingestion.ingest_port_scan(data, user_id, project_id)


def ingest_http_probe(
    neo4j_client: Neo4jClient,
    data: Dict[str, Any],
    user_id: Optional[str] = None,
    project_id: Optional[str] = None
) -> Dict[str, int]:
    """Ingest HTTP probe data."""
    ingestion = GraphIngestion(neo4j_client)
    return ingestion.ingest_http_probe(data, user_id, project_id)


def ingest_resource_enumeration(
    neo4j_client: Neo4jClient,
    data: Dict[str, Any],
    user_id: Optional[str] = None,
    project_id: Optional[str] = None
) -> Dict[str, int]:
    """Ingest resource enumeration data."""
    ingestion = GraphIngestion(neo4j_client)
    return ingestion.ingest_resource_enumeration(data, user_id, project_id)


def ingest_vulnerability_scan(
    neo4j_client: Neo4jClient,
    data: Dict[str, Any],
    user_id: Optional[str] = None,
    project_id: Optional[str] = None
) -> Dict[str, int]:
    """Ingest vulnerability scan data."""
    ingestion = GraphIngestion(neo4j_client)
    return ingestion.ingest_vulnerability_scan(data, user_id, project_id)


def ingest_mitre_data(
    neo4j_client: Neo4jClient,
    data: Dict[str, Any],
    user_id: Optional[str] = None,
    project_id: Optional[str] = None
) -> Dict[str, int]:
    """Ingest MITRE data."""
    ingestion = GraphIngestion(neo4j_client)
    return ingestion.ingest_mitre_data(data, user_id, project_id)



async def ingest_sqli_finding(
    url: str,
    parameters: list,
    dbms: str,
    technique: str = None,
    project_id: str = None,
    user_id: str = None,
) -> None:
    """
    Persist a SQL injection finding to the Neo4j attack graph.

    Creates a Vulnerability node tagged with category='sqli' and links it
    to the Endpoint node for the target URL.  Called by SQLMapDetectTool
    when a project_id is available.

    This is a standalone async wrapper that creates its own Neo4j driver
    connection using the application settings.
    """
    try:
        from app.core.config import settings
        from neo4j import AsyncGraphDatabase

        driver = AsyncGraphDatabase.driver(
            settings.NEO4J_URI,
            auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
        )

        cypher = """
        MERGE (vuln:Vulnerability {url: $url, category: 'sqli', type: 'SQL Injection'})
        SET
          vuln.parameters  = $parameters,
          vuln.dbms        = $dbms,
          vuln.technique   = $technique,
          vuln.severity    = 'high',
          vuln.project_id  = $project_id,
          vuln.user_id     = $user_id,
          vuln.discovered_at = timestamp()
        WITH vuln
        MERGE (ep:Endpoint {url: $url})
        SET
          ep.project_id = $project_id,
          ep.user_id    = $user_id
        MERGE (ep)-[:HAS_VULNERABILITY]->(vuln)
        RETURN vuln
        """

        async with driver.session() as session:
            await session.run(
                cypher,
                url=url,
                parameters=parameters,
                dbms=dbms,
                technique=technique or "unknown",
                project_id=project_id or "",
                user_id=user_id or "",
            )

        await driver.close()

    except Exception as exc:
        import logging as _logging
        _logging.getLogger(__name__).warning(
            "ingest_sqli_finding: %s", exc
        )
