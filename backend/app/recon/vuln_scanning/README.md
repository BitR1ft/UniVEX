# Vulnerability Scanning Module

**UniVex Vulnerability Scanning**

Comprehensive vulnerability scanning with Nuclei integration, CVE enrichment, and MITRE ATT&CK mapping.

## 🎯 Features

### Core Capabilities
- **Nuclei Scanner Integration**: 9,000+ vulnerability templates
- **CVE Enrichment**: Automatic enrichment via NVD and Vulners APIs
- **MITRE Mapping**: CWE and CAPEC attack pattern mapping
- **DAST Mode**: Dynamic application security testing with fuzzing
- **Interactsh Integration**: Blind vulnerability detection
- **Multi-Mode Scanning**: Basic, Full, Passive, Active, CVE-only modes

## 📦 Components

### 1. Schemas (`schemas.py`)
Pydantic models for vulnerability data structures:
- `VulnScanRequest`: Scan configuration
- `VulnerabilityInfo`: Vulnerability details
- `CVEInfo`: CVE data with CVSS scores
- `CWEInfo`: Common Weakness Enumeration
- `CAPECInfo`: Attack pattern information
- `MITREData`: MITRE ATT&CK mapping
- `VulnScanStats`: Scan statistics
- `VulnScanResult`: Complete results

### 2. Nuclei Wrapper (`nuclei_wrapper.py`)
Python wrapper for Nuclei scanner:
- Template management and auto-updates
- Severity and tag filtering
- DAST mode with parameter injection
- Interactsh for blind vulnerabilities
- Performance settings (rate limiting, concurrency)
- JSON output parsing

### 3. CVE Enricher (`cve_enricher.py`)
CVE data enrichment:
- NVD API integration with rate limiting
- Vulners API as fallback
- CVE lookup by ID
- CVE search by product/version
- CVSS score extraction
- Result caching

### 4. MITRE Mapper (`mitre_mapper.py`)
MITRE ATT&CK framework mapping:
- CVE to CWE mapping
- CWE to CAPEC mapping
- CWE hierarchy extraction
- CAPEC attack pattern details
- Database auto-updates

### 5. Vulnerability Orchestrator (`vuln_orchestrator.py`)
Main orchestration logic:
- Multi-phase scanning workflow
- Parallel/sequential execution
- Result deduplication
- Statistics calculation
- Error handling

### 6. CLI Interface (`cli.py`)
Command-line interface:
- Multiple scanning modes
- Flexible configuration
- JSON output
- Verbose logging

## 🚀 Usage

### Basic Scan
```bash
python -m app.recon.vuln_scanning.cli scan https://example.com --mode basic
```

### Full Scan (All Features)
```bash
python -m app.recon.vuln_scanning.cli scan https://example.com --mode full -v
```

### Passive Scan (Non-Intrusive)
```bash
python -m app.recon.vuln_scanning.cli scan https://example.com --mode passive
```

### Active DAST Scan
```bash
python -m app.recon.vuln_scanning.cli scan https://example.com --mode active --dast --interactsh
```

### CVE Enrichment Only
```bash
python -m app.recon.vuln_scanning.cli scan --mode cve_only --tech-file technologies.json
```

### Custom Configuration
```bash
python -m app.recon.vuln_scanning.cli scan https://example.com \
    --severity critical high medium \
    --include-tags cve xss sqli \
    --rate-limit 50 \
    --concurrency 10 \
    -o results.json
```

### Scan from File
```bash
python -m app.recon.vuln_scanning.cli scan -f targets.txt -o vulnerabilities.json
```

## 📊 Scan Modes

### 1. Basic Mode
- Nuclei with critical/high severity only
- No CVE enrichment
- No MITRE mapping
- Fast execution

### 2. Full Mode (Default)
- All Nuclei templates
- CVE enrichment
- MITRE CWE/CAPEC mapping
- Comprehensive results

### 3. Passive Mode
- Non-intrusive checks only
- Safe for production
- No active fuzzing

### 4. Active Mode
- DAST fuzzing enabled
- Parameter injection (XSS, SQLi, RCE, etc.)
- Aggressive testing
- **Use with caution**

### 5. CVE-Only Mode
- No Nuclei scanning
- CVE enrichment based on detected technologies
- Useful for vulnerability assessment

## 🔧 Configuration

### Nuclei Configuration
```python
nuclei_config = NucleiConfig(
    severity_filter=[VulnSeverity.CRITICAL, VulnSeverity.HIGH],
    include_tags=["cve", "xss", "sqli"],
    exclude_tags=["dos", "fuzz"],
    dast_enabled=False,
    interactsh_enabled=False,
    rate_limit=100,  # requests/sec
    concurrency=25,  # parallel templates
    timeout=10,      # per-request timeout
    auto_update_templates=True
)
```

### CVE Enrichment Configuration
```python
cve_config = CVEEnrichmentConfig(
    enabled=True,
    nvd_api_key="your-nvd-api-key",  # Optional
    use_vulners=True,
    cache_results=True,
    min_cvss_score=4.0
)
```

### MITRE Mapping Configuration
```python
mitre_config = MITREConfig(
    enabled=True,
    cve_to_cwe=True,
    cwe_to_capec=True,
    auto_update_db=True
)
```

## 📈 Output Format

### JSON Structure
```json
{
  "request": {
    "targets": ["https://example.com"],
    "mode": "full"
  },
  "vulnerabilities": [
    {
      "id": "nuclei-CVE-2024-1234",
      "title": "SQL Injection in Login Form",
      "severity": "high",
      "category": "sqli",
      "source": "nuclei",
      "matched_at": "https://example.com/login",
      "cve": {
        "cve_id": "CVE-2024-1234",
        "cvss_score": 8.5,
        "severity": "high",
        "mitre": {
          "cwe": {
            "cwe_id": "CWE-89",
            "cwe_name": "SQL Injection"
          },
          "capec": [
            {
              "capec_id": "CAPEC-66",
              "capec_name": "SQL Injection",
              "likelihood": "High",
              "severity": "Very High"
            }
          ]
        }
      }
    }
  ],
  "stats": {
    "total_vulnerabilities": 42,
    "by_severity": {
      "critical": 5,
      "high": 15,
      "medium": 20,
      "low": 2
    },
    "by_category": {
      "sqli": 8,
      "xss": 12,
      "cve": 15
    },
    "execution_time": 125.5
  }
}
```

## 🧪 Testing

### Run Unit Tests
```bash
cd backend
pytest tests/recon/vuln_scanning/ -v
```

### Test on Sample Target
```bash
# Test passive scan
python -m app.recon.vuln_scanning.cli scan http://testphp.vulnweb.com --mode passive

# Test active scan (use test environments only!)
python -m app.recon.vuln_scanning.cli scan http://testphp.vulnweb.com --mode active --dast
```

## ⚠️ Security & Ethics

### Important Notes
1. **Authorization Required**: Only scan systems you own or have explicit permission to test
2. **Active Mode**: DAST fuzzing can be destructive - use only in test environments
3. **Rate Limiting**: Respect target server resources
4. **Legal Compliance**: Ensure compliance with local laws and regulations

### Responsible Use
- Always get written permission before scanning
- Use passive mode for production systems
- Monitor your scans and stop if issues occur
- Report findings responsibly

## 📚 Dependencies

### Required Tools
- **Nuclei**: `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`

### Python Packages
- httpx: HTTP client for CVE APIs
- pydantic: Data validation
- Standard library: json, logging, subprocess, etc.

## 🔗 Integration

### With Reconnaissance Pipeline
```python
# After HTTP probing, extract technologies
technologies = http_probe_result.technologies

# Run vulnerability scan
vuln_request = VulnScanRequest(
    targets=http_probe_result.base_urls,
    detected_technologies=technologies,
    mode=ScanMode.FULL
)

orchestrator = VulnScanOrchestrator(vuln_request)
vuln_result = await orchestrator.run()
```

### With Neo4j Database
```python
# Ingest vulnerabilities into graph
for vuln in vuln_result.vulnerabilities:
    neo4j_client.create_vulnerability_node(vuln)
    if vuln.cve:
        neo4j_client.create_cve_node(vuln.cve)
    if vuln.cve and vuln.cve.mitre:
        neo4j_client.create_mitre_nodes(vuln.cve.mitre)
```

## 📝 Implementation Notes

### Nuclei Integration
- Nuclei wrapper with template management
- Severity and tag filtering
- JSON output parsing
- Auto-update mechanism

### DAST & Advanced Features
- DAST fuzzing mode
- Interactsh integration
- Performance optimization
- Headless browser support

### CVE Enrichment
- NVD API integration
- Vulners API fallback
- Rate limiting and caching
- Product/version search

### MITRE Mapping
- CVE to CWE mapping
- CWE to CAPEC mapping
- Attack pattern details
- Database management

## 🎓 Learning Resources

- [Nuclei Documentation](https://docs.projectdiscovery.io/tools/nuclei/overview)
- [NVD API Guide](https://nvd.nist.gov/developers)
- [MITRE CWE](https://cwe.mitre.org/)
- [MITRE CAPEC](https://capec.mitre.org/)
- [CVSS Specification](https://www.first.org/cvss/)

---

## 🆕 Week 6 Additions (Days 35-41)

### NucleiOrchestrator (`nuclei_orchestrator.py`)
Canonical BaseOrchestrator extension for Nuclei:
- Async subprocess execution via `asyncio.create_subprocess_exec`
- Configurable severity filter, tag include/exclude, Interactsh OOB
- `_normalise()` maps Nuclei JSON → canonical `Finding` objects
- CVE & CWE extraction from template classification fields
- `scan_targets()` classmethod for concurrent multi-host scanning

### NucleiTemplateUpdater (`template_updater.py`)
Template lifecycle management:
- `update()` – async `nuclei -update-templates` execution
- Version detection via `nuclei -version`
- Persistent audit history in `~/.univex/nuclei_templates_state.json`
- Optional APScheduler-based scheduled refresh (`start_scheduler()`)

### InteractshClient (`interactsh_client.py`)
OOB interaction detection for blind vulnerabilities:
- Async context manager with HTTP session management
- Unique correlation ID generation
- Payload helpers: DNS, HTTP, Log4Shell/JNDI, SSRF
- `poll()` for continuous interaction capture
- `on_interaction()` callback registration

### /api/scans/nuclei REST Endpoints
- `POST /api/scans/nuclei` – start a scan (returns task_id)
- `GET  /api/scans/nuclei/{task_id}` – poll status
- `GET  /api/scans/nuclei/{task_id}/results` – retrieve findings

---

## 👨‍💻 Author

**BitR1FT** — Founder & Lead Developer  
- Project: UniVex (open-source)
- GitHub: [@BitR1ft](https://github.com/BitR1ft)

## 📄 License

Part of UniVex project
