# Neo4j Graph Database Schema Documentation

## Overview

The UniVex attack surface graph database uses Neo4j to store and represent relationships between all reconnaissance and vulnerability data. The schema consists of **17 node types** and **20+ relationship types**, forming a complete knowledge graph of the target's attack surface.

## Multi-Tenancy

All nodes include the following properties for multi-tenancy:
- `user_id` - User identifier for data isolation
- `project_id` - Project identifier for data isolation  
- `created_at` - Timestamp of node creation (ISO 8601 format)

## Node Types

### 1. Domain Node
**Label:** `Domain`

Root node of the attack surface graph representing the target domain.

**Properties:**
- `name` (string, unique) - Domain name (e.g., "example.com")
- `discovered_at` (string) - Discovery timestamp
- `registrar` (string, optional) - Domain registrar from WHOIS
- `creation_date` (string, optional) - Domain creation date from WHOIS
- `expiration_date` (string, optional) - Domain expiration date from WHOIS
- `org` (string, optional) - Registrant organization
- `country` (string, optional) - Registrant country
- `name_servers` (list, optional) - Name servers
- `status` (list, optional) - Domain status codes

**Relationships:**
- `HAS_SUBDOMAIN` → Subdomain

---

### 2. Subdomain Node
**Label:** `Subdomain`

Represents discovered subdomains of the target.

**Properties:**
- `name` (string, unique) - Subdomain name (e.g., "www.example.com")
- `parent_domain` (string) - Parent domain name
- `discovered_at` (string) - Discovery timestamp
- `dns_records` (dict, optional) - DNS resolution results

**Relationships:**
- ← `HAS_SUBDOMAIN` - Domain
- `RESOLVES_TO` → IP
- `HAS_DNS_RECORD` → DNSRecord

---

### 3. IP Node
**Label:** `IP`

Represents IP addresses discovered through DNS resolution.

**Properties:**
- `address` (string, unique) - IP address (IPv4 or IPv6)
- `discovered_at` (string) - Discovery timestamp
- `is_cdn` (boolean, optional) - Whether IP belongs to CDN
- `cdn_name` (string, optional) - CDN provider name
- `asn` (string, optional) - Autonomous System Number
- `asn_org` (string, optional) - ASN organization name
- `asn_country` (string, optional) - ASN country

**Relationships:**
- ← `RESOLVES_TO` - Subdomain
- `HAS_PORT` → Port
- `HAS_VULNERABILITY` → Vulnerability (for GVM network vulnerabilities)

---

### 4. Port Node
**Label:** `Port`

Represents open/filtered ports discovered during port scanning.

**Properties:**
- `id` (string, unique) - Composite identifier (e.g., "192.168.1.1:80/tcp")
- `ip` (string) - Associated IP address
- `number` (integer) - Port number (1-65535)
- `protocol` (string) - Protocol ("tcp" or "udp")
- `state` (string) - Port state ("open", "closed", "filtered")
- `discovered_at` (string) - Discovery timestamp

**Relationships:**
- ← `HAS_PORT` - IP
- `RUNS_SERVICE` → Service
- `SERVES_URL` → BaseURL

---

### 5. Service Node
**Label:** `Service`

Represents services running on ports.

**Properties:**
- `id` (string, unique) - Composite identifier (e.g., "http:2.4.41")
- `name` (string) - Service name (e.g., "http", "ssh")
- `version` (string, optional) - Service version
- `banner` (string, optional) - Service banner
- `discovered_at` (string) - Discovery timestamp

**Relationships:**
- ← `RUNS_SERVICE` - Port

---

### 6. BaseURL Node
**Label:** `BaseURL`

Represents HTTP/HTTPS URLs discovered through probing.

**Properties:**
- `url` (string, unique) - Full URL (e.g., "https://example.com")
- `discovered_at` (string) - Discovery timestamp
- `status_code` (integer, optional) - HTTP status code
- `content_type` (string, optional) - Response content type
- `content_length` (integer, optional) - Response content length
- `server` (string, optional) - Server header value
- `title` (string, optional) - HTML page title
- `response_time` (float, optional) - Response time in milliseconds

**Relationships:**
- ← `SERVES_URL` - Port
- `HAS_ENDPOINT` → Endpoint
- `USES_TECHNOLOGY` → Technology
- `HAS_HEADER` → Header
- `HAS_CERTIFICATE` → Certificate

---

### 7. Endpoint Node
**Label:** `Endpoint`

Represents discovered API endpoints and web paths.

**Properties:**
- `id` (string, unique) - Composite identifier (e.g., "GET:/api/users")
- `path` (string) - Endpoint path (e.g., "/api/users")
- `method` (string) - HTTP method (GET, POST, etc.)
- `base_url` (string, optional) - Associated base URL
- `status_code` (integer, optional) - Response status code
- `content_type` (string, optional) - Response content type
- `discovered_at` (string) - Discovery timestamp

**Relationships:**
- ← `HAS_ENDPOINT` - BaseURL
- `HAS_PARAMETER` → Parameter
- ← `FOUND_AT` - Vulnerability

---

### 8. Parameter Node
**Label:** `Parameter`

Represents parameters in endpoints (query, body, header, path).

**Properties:**
- `id` (string, unique) - Composite identifier (e.g., "user_id:query")
- `name` (string) - Parameter name
- `type` (string) - Parameter type ("query", "body", "header", "path")
- `example_value` (string, optional) - Example value discovered
- `discovered_at` (string) - Discovery timestamp

**Relationships:**
- ← `HAS_PARAMETER` - Endpoint
- ← `AFFECTS_PARAMETER` - Vulnerability

---

### 9. Technology Node
**Label:** `Technology`

Represents detected technologies (frameworks, libraries, CMS, etc.).

**Properties:**
- `name` (string, unique) - Technology name (e.g., "WordPress", "jQuery")
- `version` (string, optional) - Technology version
- `confidence` (float, optional) - Detection confidence (0-100)
- `categories` (list, optional) - Technology categories
- `discovered_at` (string) - Discovery timestamp

**Relationships:**
- ← `USES_TECHNOLOGY` - BaseURL
- `HAS_KNOWN_CVE` → CVE

---

### 10. Header Node
**Label:** `Header`

Represents HTTP response headers.

**Properties:**
- `id` (string, unique) - Composite identifier (e.g., "Server:Apache/2.4.41")
- `name` (string) - Header name
- `value` (string) - Header value
- `discovered_at` (string) - Discovery timestamp

**Relationships:**
- ← `HAS_HEADER` - BaseURL

---

### 11. Certificate Node
**Label:** `Certificate`

Represents TLS/SSL certificates.

**Properties:**
- `id` (string, unique) - Serial number or composite identifier
- `subject` (string) - Certificate subject
- `issuer` (string, optional) - Certificate issuer
- `valid_from` (string, optional) - Validity start date
- `valid_to` (string, optional) - Validity end date
- `serial_number` (string, optional) - Certificate serial number
- `discovered_at` (string) - Discovery timestamp

**Relationships:**
- ← `HAS_CERTIFICATE` - BaseURL

---

### 12. DNSRecord Node
**Label:** `DNSRecord`

Represents DNS records (A, AAAA, MX, TXT, CNAME, etc.).

**Properties:**
- `id` (string, unique) - Composite identifier (e.g., "A:192.168.1.1")
- `type` (string) - DNS record type (A, AAAA, MX, TXT, etc.)
- `value` (string) - Record value
- `subdomain` (string, optional) - Associated subdomain
- `discovered_at` (string) - Discovery timestamp

**Relationships:**
- ← `HAS_DNS_RECORD` - Subdomain

---

### 13. Vulnerability Node
**Label:** `Vulnerability`

Represents discovered vulnerabilities from various scanners.

**Properties:**
- `id` (string, unique) - MD5 hash of vulnerability signature
- `name` (string) - Vulnerability name/title
- `severity` (string) - Severity level (info, low, medium, high, critical)
- `category` (string, optional) - Vulnerability category
- `source` (string) - Detection source ("nuclei", "gvm", "security_check")
- `description` (string, optional) - Vulnerability description
- `template_id` (string, optional) - Nuclei template ID
- `matcher_name` (string, optional) - Matcher that triggered
- `tags` (list, optional) - Vulnerability tags
- `discovered_at` (string) - Discovery timestamp

**Relationships:**
- `FOUND_AT` → Endpoint
- `AFFECTS_PARAMETER` → Parameter
- ← `HAS_VULNERABILITY` - IP (for network vulnerabilities)

---

### 14. CVE Node
**Label:** `CVE`

Represents Common Vulnerabilities and Exposures.

**Properties:**
- `id` (string, unique) - CVE identifier (e.g., "CVE-2021-12345")
- `cve_id` (string) - CVE identifier (duplicate for clarity)
- `cvss_score` (float, optional) - CVSS score (0-10)
- `severity` (string, optional) - Severity level
- `description` (string, optional) - CVE description
- `published_date` (string, optional) - Publication date

**Relationships:**
- ← `HAS_KNOWN_CVE` - Technology
- `HAS_CWE` → MitreData
- ← `EXPLOITED_CVE` - Exploit

---

### 15. MitreData Node
**Label:** `MitreData`

Represents MITRE CWE (Common Weakness Enumeration) entries.

**Properties:**
- `id` (string, unique) - CWE identifier (e.g., "CWE-79")
- `cwe_id` (string) - CWE identifier (duplicate for clarity)
- `name` (string, optional) - CWE name
- `description` (string, optional) - CWE description

**Relationships:**
- ← `HAS_CWE` - CVE
- `HAS_CAPEC` → Capec

---

### 16. Capec Node
**Label:** `Capec`

Represents CAPEC (Common Attack Pattern Enumeration and Classification) entries.

**Properties:**
- `id` (string, unique) - CAPEC identifier (e.g., "CAPEC-63")
- `capec_id` (string) - CAPEC identifier (duplicate for clarity)
- `name` (string, optional) - Attack pattern name
- `description` (string, optional) - Attack pattern description
- `likelihood` (string, optional) - Likelihood of attack
- `severity` (string, optional) - Attack severity

**Relationships:**
- ← `HAS_CAPEC` - MitreData

---

### 17. Exploit Node
**Label:** `Exploit`

Represents known exploits for vulnerabilities.

**Properties:**
- `id` (string, unique) - Exploit identifier
- `name` (string) - Exploit name
- `type` (string, optional) - Type of exploit
- `platform` (string, optional) - Target platform
- `author` (string, optional) - Exploit author
- `published_date` (string, optional) - Publication date

**Relationships:**
- `EXPLOITED_CVE` → CVE
- `TARGETED_IP` → IP

---

## Relationship Types

### Infrastructure Chain
1. **HAS_SUBDOMAIN**: Domain → Subdomain
2. **RESOLVES_TO**: Subdomain → IP
3. **HAS_PORT**: IP → Port
4. **RUNS_SERVICE**: Port → Service
5. **SERVES_URL**: Port → BaseURL
6. **HAS_ENDPOINT**: BaseURL → Endpoint
7. **HAS_PARAMETER**: Endpoint → Parameter
8. **USES_TECHNOLOGY**: BaseURL → Technology
9. **HAS_HEADER**: BaseURL → Header
10. **HAS_CERTIFICATE**: BaseURL → Certificate
11. **HAS_DNS_RECORD**: Subdomain → DNSRecord

### Vulnerability Chain
12. **FOUND_AT**: Vulnerability → Endpoint
13. **AFFECTS_PARAMETER**: Vulnerability → Parameter
14. **HAS_VULNERABILITY**: IP → Vulnerability
15. **HAS_KNOWN_CVE**: Technology → CVE
16. **HAS_CWE**: CVE → MitreData
17. **HAS_CAPEC**: MitreData → Capec
18. **EXPLOITED_CVE**: Exploit → CVE
19. **TARGETED_IP**: Exploit → IP

---

## Example Queries

### Get complete attack surface for a project
```cypher
MATCH (d:Domain {project_id: $project_id})
OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
OPTIONAL MATCH (s)-[:RESOLVES_TO]->(ip:IP)
OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
OPTIONAL MATCH (p)-[:RUNS_SERVICE]->(srv:Service)
OPTIONAL MATCH (p)-[:SERVES_URL]->(u:BaseURL)
OPTIONAL MATCH (u)-[:HAS_ENDPOINT]->(e:Endpoint)
RETURN d, s, ip, p, srv, u, e
```

### Get all critical vulnerabilities with their endpoints
```cypher
MATCH (v:Vulnerability {severity: 'critical', project_id: $project_id})
OPTIONAL MATCH (v)-[:FOUND_AT]->(e:Endpoint)
RETURN v, e
ORDER BY v.discovered_at DESC
```

### Get vulnerability chain with CVE → CWE → CAPEC
```cypher
MATCH (v:Vulnerability {project_id: $project_id})
OPTIONAL MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(cve:CVE)
OPTIONAL MATCH (cve)-[:HAS_CWE]->(cwe:MitreData)
OPTIONAL MATCH (cwe)-[:HAS_CAPEC]->(capec:Capec)
RETURN v, t, cve, cwe, capec
```

### Get all technologies with known CVEs
```cypher
MATCH (t:Technology {project_id: $project_id})-[:HAS_KNOWN_CVE]->(cve:CVE)
RETURN t.name, t.version, collect(cve.cve_id) as cves
ORDER BY cve.cvss_score DESC
```

---

## Data Ingestion Pipeline

The graph database is populated through 6 ingestion functions:

1. **ingest_domain_discovery()** - Phase 1: Domain, Subdomain, IP, DNSRecord nodes
2. **ingest_port_scan()** - Phase 2: Port, Service nodes
3. **ingest_http_probe()** - Phase 3: BaseURL, Technology, Header, Certificate nodes
4. **ingest_resource_enumeration()** - Phase 4: Endpoint, Parameter nodes
5. **ingest_vulnerability_scan()** - Phase 5: Vulnerability, CVE nodes
6. **ingest_mitre_data()** - MITRE mapping: MitreData (CWE), Capec nodes

Each function automatically creates nodes and relationships while respecting multi-tenancy constraints.

---

## Constraints and Indexes

### Uniqueness Constraints
All 17 node types have uniqueness constraints on their primary identifiers to prevent duplicate data.

### Performance Indexes
Indexes are created on:
- Time-based fields (`discovered_at`)
- Severity fields (`severity`)
- State fields (`state`, `status_code`)
- Multi-tenancy fields (`user_id`, `project_id`)

---

## Multi-Tenancy Implementation

Data isolation is enforced through:
1. `user_id` and `project_id` on every node
2. Indexes on tenant fields for fast filtering
3. Query filters that always include tenant constraints

Example tenant-filtered query:
```cypher
MATCH (v:Vulnerability {
  project_id: $project_id,
  user_id: $user_id
})
RETURN v
```

---

## Schema Version

**Version:** 1.0  
**Neo4j Graph Database Implementation**  
**Date:** 2026-02-16

---

## Notes

- All timestamps are in ISO 8601 format (UTC)
- Node IDs are either unique identifiers or composite keys for uniqueness
- Relationships can include additional properties for metadata
- The schema supports both web application and network vulnerability scanning
- Graph can be exported for visualization using tools like react-force-graph
