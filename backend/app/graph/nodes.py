"""
Neo4j Node Types Implementation.
Implements all 17 node types for the attack surface graph database.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
from app.db.neo4j_client import Neo4jClient
import logging

logger = logging.getLogger(__name__)


class BaseNode:
    """Base class for all node types with common multi-tenancy properties."""
    
    def __init__(self, neo4j_client: Neo4jClient):
        self.client = neo4j_client
    
    def _add_tenant_info(
        self, 
        properties: Dict[str, Any], 
        user_id: Optional[str] = None, 
        project_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Add user_id and project_id for multi-tenancy."""
        if user_id:
            properties['user_id'] = user_id
        if project_id:
            properties['project_id'] = project_id
        properties['created_at'] = datetime.utcnow().isoformat()
        return properties


class DomainNode(BaseNode):
    """Domain node (root of attack surface)."""
    
    def create(
        self,
        name: str,
        whois_data: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a Domain node.
        
        Args:
            name: Domain name (e.g., 'example.com')
            whois_data: WHOIS information
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties
            
        Returns:
            Created node properties
        """
        properties = {
            'name': name,
            'discovered_at': datetime.utcnow().isoformat(),
        }
        
        # Add WHOIS properties
        if whois_data:
            properties.update({
                'registrar': whois_data.get('registrar'),
                'creation_date': whois_data.get('creation_date'),
                'expiration_date': whois_data.get('expiration_date'),
                'org': whois_data.get('org'),
                'country': whois_data.get('country'),
                'name_servers': whois_data.get('name_servers', []),
                'status': whois_data.get('status', []),
            })
        
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        
        return self.client.create_node('Domain', properties, merge=True)


class SubdomainNode(BaseNode):
    """Subdomain node."""
    
    def create(
        self,
        name: str,
        parent_domain: str,
        dns_records: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a Subdomain node.
        
        Args:
            name: Subdomain name (e.g., 'www.example.com')
            parent_domain: Parent domain name
            dns_records: DNS resolution information
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties
            
        Returns:
            Created node properties
        """
        properties = {
            'name': name,
            'parent_domain': parent_domain,
            'discovered_at': datetime.utcnow().isoformat(),
        }
        
        if dns_records:
            properties['dns_records'] = dns_records
        
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        
        return self.client.create_node('Subdomain', properties, merge=True)


class IPNode(BaseNode):
    """IP address node."""
    
    def create(
        self,
        address: str,
        cdn_info: Optional[Dict[str, Any]] = None,
        asn_info: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create an IP node.
        
        Args:
            address: IP address
            cdn_info: CDN detection information
            asn_info: ASN information
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties
            
        Returns:
            Created node properties
        """
        properties = {
            'address': address,
            'discovered_at': datetime.utcnow().isoformat(),
        }
        
        if cdn_info:
            properties.update({
                'is_cdn': cdn_info.get('is_cdn', False),
                'cdn_name': cdn_info.get('cdn_name'),
            })
        
        if asn_info:
            properties.update({
                'asn': asn_info.get('asn'),
                'asn_org': asn_info.get('org'),
                'asn_country': asn_info.get('country'),
            })
        
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        
        return self.client.create_node('IP', properties, merge=True)


class PortNode(BaseNode):
    """Port node."""
    
    def create(
        self,
        ip: str,
        number: int,
        protocol: str = 'tcp',
        state: str = 'open',
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a Port node.
        
        Args:
            ip: Associated IP address
            number: Port number
            protocol: Protocol (tcp/udp)
            state: Port state (open/closed/filtered)
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties
            
        Returns:
            Created node properties
        """
        properties = {
            'ip': ip,
            'number': number,
            'protocol': protocol,
            'state': state,
            'discovered_at': datetime.utcnow().isoformat(),
        }
        
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        
        # Create unique identifier
        properties['id'] = f"{ip}:{number}/{protocol}"
        
        return self.client.create_node('Port', properties, merge=True)


class ServiceNode(BaseNode):
    """Service node."""
    
    def create(
        self,
        name: str,
        version: Optional[str] = None,
        banner: Optional[str] = None,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a Service node.
        
        Args:
            name: Service name
            version: Service version
            banner: Service banner
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties
            
        Returns:
            Created node properties
        """
        properties = {
            'name': name,
            'discovered_at': datetime.utcnow().isoformat(),
        }
        
        if version:
            properties['version'] = version
        if banner:
            properties['banner'] = banner
        
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        
        # Create unique identifier
        properties['id'] = f"{name}:{version or 'unknown'}"
        
        return self.client.create_node('Service', properties, merge=True)


class BaseURLNode(BaseNode):
    """BaseURL node (HTTP endpoint)."""
    
    def create(
        self,
        url: str,
        http_metadata: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a BaseURL node.
        
        Args:
            url: Base URL
            http_metadata: HTTP probe metadata
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties
            
        Returns:
            Created node properties
        """
        properties = {
            'url': url,
            'discovered_at': datetime.utcnow().isoformat(),
        }
        
        if http_metadata:
            properties.update({
                'status_code': http_metadata.get('status_code'),
                'content_type': http_metadata.get('content_type'),
                'content_length': http_metadata.get('content_length'),
                'server': http_metadata.get('server'),
                'title': http_metadata.get('title'),
                'response_time': http_metadata.get('response_time'),
            })
        
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        
        return self.client.create_node('BaseURL', properties, merge=True)


class EndpointNode(BaseNode):
    """Endpoint node (API/web endpoint)."""
    
    def create(
        self,
        path: str,
        method: str = 'GET',
        base_url: Optional[str] = None,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create an Endpoint node.
        
        Args:
            path: Endpoint path
            method: HTTP method
            base_url: Associated base URL
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties
            
        Returns:
            Created node properties
        """
        properties = {
            'path': path,
            'method': method,
            'discovered_at': datetime.utcnow().isoformat(),
        }
        
        if base_url:
            properties['base_url'] = base_url
        
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        
        # Create unique identifier
        properties['id'] = f"{method}:{path}"
        
        return self.client.create_node('Endpoint', properties, merge=True)


class ParameterNode(BaseNode):
    """Parameter node (URL/POST parameter)."""
    
    def create(
        self,
        name: str,
        param_type: str = 'query',  # query, body, header, path
        example_value: Optional[str] = None,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a Parameter node.
        
        Args:
            name: Parameter name
            param_type: Parameter type (query/body/header/path)
            example_value: Example value
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties
            
        Returns:
            Created node properties
        """
        properties = {
            'name': name,
            'type': param_type,
            'discovered_at': datetime.utcnow().isoformat(),
        }
        
        if example_value:
            properties['example_value'] = example_value
        
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        
        # Create unique identifier
        properties['id'] = f"{name}:{param_type}"
        
        return self.client.create_node('Parameter', properties, merge=True)


class TechnologyNode(BaseNode):
    """Technology node (detected technology)."""
    
    def create(
        self,
        name: str,
        version: Optional[str] = None,
        confidence: Optional[float] = None,
        categories: Optional[List[str]] = None,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a Technology node.
        
        Args:
            name: Technology name
            version: Technology version
            confidence: Detection confidence (0-100)
            categories: Technology categories
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties
            
        Returns:
            Created node properties
        """
        properties = {
            'name': name,
            'discovered_at': datetime.utcnow().isoformat(),
        }
        
        if version:
            properties['version'] = version
        if confidence is not None:
            properties['confidence'] = confidence
        if categories:
            properties['categories'] = categories
        
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        
        return self.client.create_node('Technology', properties, merge=True)


class HeaderNode(BaseNode):
    """HTTP Header node."""
    
    def create(
        self,
        name: str,
        value: str,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a Header node.
        
        Args:
            name: Header name
            value: Header value
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties
            
        Returns:
            Created node properties
        """
        properties = {
            'name': name,
            'value': value,
            'discovered_at': datetime.utcnow().isoformat(),
        }
        
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        
        # Create unique identifier
        properties['id'] = f"{name}:{value}"
        
        return self.client.create_node('Header', properties, merge=True)


class CertificateNode(BaseNode):
    """TLS/SSL Certificate node."""
    
    def create(
        self,
        subject: str,
        issuer: Optional[str] = None,
        valid_from: Optional[str] = None,
        valid_to: Optional[str] = None,
        serial_number: Optional[str] = None,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a Certificate node.
        
        Args:
            subject: Certificate subject
            issuer: Certificate issuer
            valid_from: Validity start date
            valid_to: Validity end date
            serial_number: Certificate serial number
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties
            
        Returns:
            Created node properties
        """
        properties = {
            'subject': subject,
            'discovered_at': datetime.utcnow().isoformat(),
        }
        
        if issuer:
            properties['issuer'] = issuer
        if valid_from:
            properties['valid_from'] = valid_from
        if valid_to:
            properties['valid_to'] = valid_to
        if serial_number:
            properties['serial_number'] = serial_number
        
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        
        # Create unique identifier
        properties['id'] = serial_number or f"{subject}:{issuer}"
        
        return self.client.create_node('Certificate', properties, merge=True)


class DNSRecordNode(BaseNode):
    """DNS Record node."""
    
    def create(
        self,
        record_type: str,
        value: str,
        subdomain: Optional[str] = None,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a DNSRecord node.
        
        Args:
            record_type: DNS record type (A, AAAA, MX, TXT, etc.)
            value: Record value
            subdomain: Associated subdomain
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties
            
        Returns:
            Created node properties
        """
        properties = {
            'type': record_type,
            'value': value,
            'discovered_at': datetime.utcnow().isoformat(),
        }
        
        if subdomain:
            properties['subdomain'] = subdomain
        
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        
        # Create unique identifier
        properties['id'] = f"{record_type}:{value}"
        
        return self.client.create_node('DNSRecord', properties, merge=True)


class VulnerabilityNode(BaseNode):
    """Vulnerability node."""
    
    def create(
        self,
        name: str,
        severity: str,
        category: Optional[str] = None,
        source: str = 'nuclei',  # nuclei, gvm, security_check
        description: Optional[str] = None,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a Vulnerability node.
        
        Args:
            name: Vulnerability name/title
            severity: Severity level (info, low, medium, high, critical)
            category: Vulnerability category
            source: Detection source
            description: Vulnerability description
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties
            
        Returns:
            Created node properties
        """
        properties = {
            'name': name,
            'severity': severity,
            'source': source,
            'discovered_at': datetime.utcnow().isoformat(),
        }
        
        if category:
            properties['category'] = category
        if description:
            properties['description'] = description
        
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        
        # Create unique identifier
        import hashlib
        vuln_str = f"{name}:{severity}:{source}"
        properties['id'] = hashlib.md5(vuln_str.encode(), usedforsecurity=False).hexdigest()
        
        return self.client.create_node('Vulnerability', properties, merge=True)


class CVENode(BaseNode):
    """CVE (Common Vulnerabilities and Exposures) node."""
    
    def create(
        self,
        cve_id: str,
        cvss_score: Optional[float] = None,
        severity: Optional[str] = None,
        description: Optional[str] = None,
        published_date: Optional[str] = None,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a CVE node.
        
        Args:
            cve_id: CVE identifier (e.g., 'CVE-2021-12345')
            cvss_score: CVSS score (0-10)
            severity: Severity level
            description: CVE description
            published_date: Publication date
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties
            
        Returns:
            Created node properties
        """
        properties = {
            'id': cve_id,
            'cve_id': cve_id,
        }
        
        if cvss_score is not None:
            properties['cvss_score'] = cvss_score
        if severity:
            properties['severity'] = severity
        if description:
            properties['description'] = description
        if published_date:
            properties['published_date'] = published_date
        
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        
        return self.client.create_node('CVE', properties, merge=True)


class MitreDataNode(BaseNode):
    """MITRE CWE (Common Weakness Enumeration) node."""
    
    def create(
        self,
        cwe_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a MitreData (CWE) node.
        
        Args:
            cwe_id: CWE identifier (e.g., 'CWE-79')
            name: CWE name
            description: CWE description
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties
            
        Returns:
            Created node properties
        """
        properties = {
            'id': cwe_id,
            'cwe_id': cwe_id,
        }
        
        if name:
            properties['name'] = name
        if description:
            properties['description'] = description
        
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        
        return self.client.create_node('MitreData', properties, merge=True)


class CapecNode(BaseNode):
    """CAPEC (Common Attack Pattern Enumeration and Classification) node."""
    
    def create(
        self,
        capec_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        likelihood: Optional[str] = None,
        severity: Optional[str] = None,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a Capec node.
        
        Args:
            capec_id: CAPEC identifier (e.g., 'CAPEC-63')
            name: Attack pattern name
            description: Attack pattern description
            likelihood: Likelihood of attack
            severity: Attack severity
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties
            
        Returns:
            Created node properties
        """
        properties = {
            'id': capec_id,
            'capec_id': capec_id,
        }
        
        if name:
            properties['name'] = name
        if description:
            properties['description'] = description
        if likelihood:
            properties['likelihood'] = likelihood
        if severity:
            properties['severity'] = severity
        
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        
        return self.client.create_node('Capec', properties, merge=True)


class ExploitNode(BaseNode):
    """Exploit node."""
    
    def create(
        self,
        exploit_id: str,
        name: str,
        exploit_type: Optional[str] = None,
        platform: Optional[str] = None,
        author: Optional[str] = None,
        published_date: Optional[str] = None,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create an Exploit node.
        
        Args:
            exploit_id: Exploit identifier
            name: Exploit name
            exploit_type: Type of exploit
            platform: Target platform
            author: Exploit author
            published_date: Publication date
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties
            
        Returns:
            Created node properties
        """
        properties = {
            'id': exploit_id,
            'name': name,
        }
        
        if exploit_type:
            properties['type'] = exploit_type
        if platform:
            properties['platform'] = platform
        if author:
            properties['author'] = author
        if published_date:
            properties['published_date'] = published_date
        
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        
        return self.client.create_node('Exploit', properties, merge=True)


class SessionNode(BaseNode):
    """Active exploitation session node."""
    
    def create(
        self,
        session_id: str,
        session_type: str,
        target_host: str,
        target_port: Optional[int] = None,
        status: str = "active",
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a Session node.
        
        Args:
            session_id: Session identifier
            session_type: Type of session (meterpreter, shell, etc.)
            target_host: Target host IP/hostname
            target_port: Target port number
            status: Session status (active, closed, lost)
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties
            
        Returns:
            Created node properties
        """
        properties = {
            'id': session_id,
            'session_type': session_type,
            'target_host': target_host,
            'status': status,
        }
        
        if target_port is not None:
            properties['target_port'] = target_port
        
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        
        return self.client.create_node('Session', properties, merge=True)


class CredentialNode(BaseNode):
    """Discovered credential node."""
    
    def create(
        self,
        credential_id: str,
        username: str,
        credential_type: str = "password",
        service: Optional[str] = None,
        target_host: Optional[str] = None,
        source: Optional[str] = None,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a Credential node.
        
        Args:
            credential_id: Credential identifier
            username: Discovered username
            credential_type: Type (password, hash, token, key)
            service: Service the credential is for
            target_host: Host where credential was found
            source: Discovery source (brute_force, dump, etc.)
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties
            
        Returns:
            Created node properties
        """
        properties = {
            'id': credential_id,
            'username': username,
            'credential_type': credential_type,
        }
        
        if service:
            properties['service'] = service
        if target_host:
            properties['target_host'] = target_host
        if source:
            properties['source'] = source
        
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        
        return self.client.create_node('Credential', properties, merge=True)


class EvidenceNode(BaseNode):
    """Evidence node — proof supporting a vulnerability finding."""

    def create(
        self,
        evidence_id: str,
        evidence_type: str,
        content: str,
        source_url: Optional[str] = None,
        description: Optional[str] = None,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create an Evidence node.

        Args:
            evidence_id: Unique evidence identifier
            evidence_type: Type of evidence (request, response, screenshot, log)
            content: Raw evidence content (request/response body, log line, etc.)
            source_url: URL where evidence was captured
            description: Human-readable description
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties

        Returns:
            Created node properties
        """
        properties = {
            'id': evidence_id,
            'evidence_type': evidence_type,
            'content': content,
            'discovered_at': datetime.utcnow().isoformat(),
        }

        if source_url:
            properties['source_url'] = source_url
        if description:
            properties['description'] = description

        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)

        return self.client.create_node('Evidence', properties, merge=True)


class ToolNode(BaseNode):
    """Tool node — a scanning or exploitation tool used during assessment."""

    def create(
        self,
        name: str,
        version: Optional[str] = None,
        tool_type: Optional[str] = None,
        description: Optional[str] = None,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a Tool node.

        Args:
            name: Tool name (e.g., 'nuclei', 'nmap', 'naabu')
            version: Tool version string
            tool_type: Category (scanner, exploit, crawler, fuzzer, etc.)
            description: Brief tool description
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties

        Returns:
            Created node properties
        """
        properties = {
            'name': name,
            'discovered_at': datetime.utcnow().isoformat(),
        }

        if version:
            properties['version'] = version
        if tool_type:
            properties['tool_type'] = tool_type
        if description:
            properties['description'] = description

        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)

        # Composite unique identifier includes version so different tool versions
        # can coexist in the graph.
        properties['id'] = f"{name}:{version or 'unknown'}"

        return self.client.create_node('Tool', properties, merge=True)


class ScanNode(BaseNode):
    """Scan node — a single tool-execution instance within a project."""

    def create(
        self,
        scan_id: str,
        tool_name: str,
        target: str,
        status: str = "completed",
        started_at: Optional[str] = None,
        completed_at: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a Scan node.

        Args:
            scan_id: Unique scan identifier (UUID)
            tool_name: Name of the tool that ran this scan
            target: Scan target (domain, IP, URL)
            status: Execution status (pending, running, completed, failed)
            started_at: ISO 8601 start timestamp
            completed_at: ISO 8601 completion timestamp
            config: Tool configuration used for this scan
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties

        Returns:
            Created node properties
        """
        properties = {
            'id': scan_id,
            'tool_name': tool_name,
            'target': target,
            'status': status,
            'created_at': datetime.utcnow().isoformat(),
        }

        if started_at:
            properties['started_at'] = started_at
        if completed_at:
            properties['completed_at'] = completed_at
        if config:
            import json
            properties['config'] = json.dumps(config)

        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)

        return self.client.create_node('Scan', properties, merge=True)


class FindingNode(BaseNode):
    """Finding node — a discrete observation produced by a scan."""

    def create(
        self,
        finding_id: str,
        title: str,
        severity: str,
        finding_type: str,
        target: Optional[str] = None,
        description: Optional[str] = None,
        remediation: Optional[str] = None,
        confidence: Optional[float] = None,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a Finding node.

        Args:
            finding_id: Unique finding identifier (UUID or hash)
            title: Short finding title
            severity: Severity level (info, low, medium, high, critical)
            finding_type: Category (vuln, misconfig, exposure, info, etc.)
            target: Target where the finding was observed
            description: Detailed description
            remediation: Recommended remediation steps
            confidence: Detection confidence score (0.0–1.0)
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties

        Returns:
            Created node properties
        """
        properties = {
            'id': finding_id,
            'title': title,
            'severity': severity,
            'finding_type': finding_type,
            'discovered_at': datetime.utcnow().isoformat(),
        }

        if target:
            properties['target'] = target
        if description:
            properties['description'] = description
        if remediation:
            properties['remediation'] = remediation
        if confidence is not None:
            properties['confidence'] = confidence

        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)

        return self.client.create_node('Finding', properties, merge=True)


class AuditEventNode(BaseNode):
    """Audit event node — immutable record of a significant system action."""

    def create(
        self,
        event_id: str,
        event_type: str,
        actor: str,
        action: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        outcome: str = "success",
        details: Optional[str] = None,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create an AuditEvent node.

        Args:
            event_id: Unique event identifier (UUID)
            event_type: Type of event (scan_started, finding_created, etc.)
            actor: User or system that triggered the event
            action: Verb describing the action (created, updated, deleted, etc.)
            resource_type: Type of affected resource (Scan, Project, etc.)
            resource_id: ID of the affected resource
            outcome: Result of the action (success, failure, partial)
            details: Additional context as a string (JSON or plain text)
            user_id: User identifier for multi-tenancy
            project_id: Project identifier for multi-tenancy
            **kwargs: Additional properties

        Returns:
            Created node properties
        """
        properties = {
            'id': event_id,
            'event_type': event_type,
            'actor': actor,
            'action': action,
            'outcome': outcome,
            'timestamp': datetime.utcnow().isoformat(),
        }

        if resource_type:
            properties['resource_type'] = resource_type
        if resource_id:
            properties['resource_id'] = resource_id
        if details:
            properties['details'] = details

        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)

        return self.client.create_node('AuditEvent', properties, merge=True)


# ===========================================================================
# Active Directory Node Types (Day 12 — BloodHound Engine)
# ===========================================================================


class ADUserNode(BaseNode):
    """Active Directory user account node."""

    def create(
        self,
        objectid: str,
        name: str,
        samaccountname: str = "",
        distinguishedname: str = "",
        description: str = "",
        enabled: bool = True,
        hasspn: bool = False,
        dontreqpreauth: bool = False,
        admincount: bool = False,
        pwdneverexpires: bool = False,
        domain: str = "",
        owned: bool = False,
        highvalue: bool = False,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Create or merge an ADUser node."""
        properties = {
            "objectid": objectid,
            "name": name,
            "samaccountname": samaccountname,
            "distinguishedname": distinguishedname,
            "description": description,
            "enabled": enabled,
            "hasspn": hasspn,
            "dontreqpreauth": dontreqpreauth,
            "admincount": admincount,
            "pwdneverexpires": pwdneverexpires,
            "domain": domain,
            "owned": owned,
            "highvalue": highvalue,
        }
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        return self.client.create_node("ADUser", properties, merge=True)


class ADGroupNode(BaseNode):
    """Active Directory security / distribution group node."""

    def create(
        self,
        objectid: str,
        name: str,
        samaccountname: str = "",
        distinguishedname: str = "",
        description: str = "",
        admincount: bool = False,
        highvalue: bool = False,
        domain: str = "",
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Create or merge an ADGroup node."""
        properties = {
            "objectid": objectid,
            "name": name,
            "samaccountname": samaccountname,
            "distinguishedname": distinguishedname,
            "description": description,
            "admincount": admincount,
            "highvalue": highvalue,
            "domain": domain,
        }
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        return self.client.create_node("ADGroup", properties, merge=True)


class ADComputerNode(BaseNode):
    """Active Directory domain-joined computer / server node."""

    def create(
        self,
        objectid: str,
        name: str,
        samaccountname: str = "",
        distinguishedname: str = "",
        operatingsystem: str = "",
        enabled: bool = True,
        unconstraineddelegation: bool = False,
        constraineddelegation: bool = False,
        haslaps: bool = False,
        highvalue: bool = False,
        domain: str = "",
        owned: bool = False,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Create or merge an ADComputer node."""
        properties = {
            "objectid": objectid,
            "name": name,
            "samaccountname": samaccountname,
            "distinguishedname": distinguishedname,
            "operatingsystem": operatingsystem,
            "enabled": enabled,
            "unconstraineddelegation": unconstraineddelegation,
            "constraineddelegation": constraineddelegation,
            "haslaps": haslaps,
            "highvalue": highvalue,
            "domain": domain,
            "owned": owned,
        }
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        return self.client.create_node("ADComputer", properties, merge=True)


class ADOUNode(BaseNode):
    """Active Directory Organizational Unit node."""

    def create(
        self,
        objectid: str,
        name: str,
        distinguishedname: str = "",
        description: str = "",
        blocksinheritance: bool = False,
        domain: str = "",
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Create or merge an ADOU node."""
        properties = {
            "objectid": objectid,
            "name": name,
            "distinguishedname": distinguishedname,
            "description": description,
            "blocksinheritance": blocksinheritance,
            "domain": domain,
        }
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        return self.client.create_node("ADOU", properties, merge=True)


class ADGPONode(BaseNode):
    """Active Directory Group Policy Object node."""

    def create(
        self,
        objectid: str,
        name: str,
        distinguishedname: str = "",
        description: str = "",
        gpcpath: str = "",
        domain: str = "",
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Create or merge an ADGPO node."""
        properties = {
            "objectid": objectid,
            "name": name,
            "distinguishedname": distinguishedname,
            "description": description,
            "gpcpath": gpcpath,
            "domain": domain,
        }
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        return self.client.create_node("ADGPO", properties, merge=True)


class ADDomainNode(BaseNode):
    """Active Directory domain root node."""

    def create(
        self,
        objectid: str,
        name: str,
        distinguishedname: str = "",
        description: str = "",
        functionallevel: str = "",
        domain: str = "",
        highvalue: bool = True,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Create or merge an ADDomain node."""
        properties = {
            "objectid": objectid,
            "name": name,
            "distinguishedname": distinguishedname,
            "description": description,
            "functionallevel": functionallevel,
            "domain": domain or name,
            "highvalue": highvalue,
        }
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        return self.client.create_node("ADDomain", properties, merge=True)


class ADTrustNode(BaseNode):
    """Active Directory cross-domain / cross-forest trust relationship node."""

    def create(
        self,
        objectid: str,
        source_domain: str,
        target_domain: str,
        trusttype: str = "ParentChild",
        direction: int = 2,
        transitive: bool = True,
        sidfiltering: bool = False,
        targetdomainsid: str = "",
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Create or merge an ADTrust node."""
        properties = {
            "objectid": objectid,
            "name": f"{source_domain}→{target_domain}",
            "source_domain": source_domain,
            "target_domain": target_domain,
            "trusttype": trusttype,
            "direction": direction,
            "transitive": transitive,
            "sidfiltering": sidfiltering,
            "targetdomainsid": targetdomainsid,
        }
        properties.update(kwargs)
        properties = self._add_tenant_info(properties, user_id, project_id)
        return self.client.create_node("ADTrust", properties, merge=True)
