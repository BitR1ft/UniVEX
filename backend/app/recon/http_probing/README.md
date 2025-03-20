# HTTP Probing Module - Month 5

Comprehensive HTTP/HTTPS probing and web technology detection module.

## Overview

This module provides advanced HTTP probing capabilities including:

- **HTTP Response Analysis**: Status codes, headers, response times, content metadata
- **TLS/SSL Inspection**: Certificate extraction, cipher analysis, JARM fingerprinting
- **Technology Detection**: 6,000+ signatures via Wappalyzer + httpx built-in detection
- **Security Analysis**: Security header evaluation, weak cipher detection
- **Favicon Fingerprinting**: MD5, SHA256, and Shodan-compatible MurmurHash3 hashing
- **Content Analysis**: Title extraction, meta tags, word counts

## Components

### 1. HttpProbe (`http_probe.py`)
Core HTTP probing using httpx tool:
- Parallel HTTP/HTTPS requests
- Response metadata extraction
- Redirect chain tracking
- Security header parsing
- Content analysis

### 2. TLSInspector (`tls_inspector.py`)
TLS/SSL certificate inspection:
- X.509 certificate parsing
- Subject and SAN extraction
- Expiration date analysis
- Cipher suite analysis
- JARM fingerprinting
- Weak cipher detection

### 3. TechDetector (`tech_detector.py`)
Technology detection using httpx:
- Framework detection (React, Vue, Django, etc.)
- CMS identification (WordPress, Drupal, etc.)
- Server detection (Nginx, Apache, etc.)
- Header-based detection
- Technology deduplication and merging

### 4. WappalyzerWrapper (`wappalyzer_wrapper.py`)
Wappalyzer integration for comprehensive technology detection:
- 6,000+ technology signatures
- Category-based classification
- Version extraction
- Confidence scoring
- Auto-update capability

### 5. FaviconHasher (`favicon_hasher.py`)
Favicon fingerprinting:
- MD5 hashing
- SHA256 hashing
- MurmurHash3 (Shodan-compatible)
- Multiple favicon location attempts

### 6. HttpProbeOrchestrator (`http_orchestrator.py`)
Workflow coordination:
- Multi-stage probing pipeline
- Parallel execution
- Result aggregation
- Statistics calculation

## Installation

### Prerequisites

1. **Install httpx**:
```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

2. **Install Wappalyzer** (optional but recommended):
```bash
npm install -g wappalyzer
```

3. **Install Python dependencies**:
```bash
pip install mmh3 cryptography
```

## Usage

### Python API

```python
from app.recon.http_probing import HttpProbeOrchestrator, HttpProbeRequest, ProbeMode

# Create request
request = HttpProbeRequest(
    targets=["https://example.com", "https://google.com"],
    mode=ProbeMode.FULL,
    tech_detection=True,
    wappalyzer=True,
    tls_inspection=True,
    favicon_hash=True
)

# Execute probe
orchestrator = HttpProbeOrchestrator(request)
result = await orchestrator.run()

# Access results
for target in result.results:
    print(f"URL: {target.url}")
    print(f"Status: {target.status_code}")
    print(f"Technologies: {len(target.technologies)}")
    if target.tls:
        print(f"TLS Version: {target.tls.version}")
```

### CLI

```bash
# Basic probe
python -m app.recon.http_probing.cli probe https://example.com

# Probe multiple targets
python -m app.recon.http_probing.cli probe https://site1.com https://site2.com

# Probe from file
python -m app.recon.http_probing.cli probe -f targets.txt

# Full probe with all features
python -m app.recon.http_probing.cli probe https://example.com --mode full -v

# Save to JSON
python -m app.recon.http_probing.cli probe https://example.com -o results.json

# Disable Wappalyzer
python -m app.recon.http_probing.cli probe https://example.com --no-wappalyzer
```

### REST API

```bash
# Start async probe
curl -X POST http://localhost:8000/api/http-probe/probe \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["https://example.com"],
    "mode": "full",
    "tech_detection": true
  }'

# Check results
curl http://localhost:8000/api/http-probe/results/{task_id}

# Quick synchronous probe (max 10 targets)
curl -X POST http://localhost:8000/api/http-probe/quick-probe \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["https://example.com"],
    "mode": "full"
  }'
```

## Configuration

### ProbeMode Options

- **BASIC**: Basic HTTP probing only (fast)
- **FULL**: Complete probing with all features (comprehensive)
- **STEALTH**: Minimal requests (low footprint)

### Request Parameters

```python
HttpProbeRequest(
    targets: List[str],              # Target URLs
    mode: ProbeMode = FULL,          # Probing mode
    follow_redirects: bool = True,   # Follow redirects
    max_redirects: int = 10,         # Max redirect depth
    timeout: int = 10,               # Request timeout (seconds)
    threads: int = 50,               # Concurrent threads
    tech_detection: bool = True,     # Enable tech detection
    wappalyzer: bool = True,         # Use Wappalyzer
    screenshot: bool = False,        # Capture screenshots
    favicon_hash: bool = True,       # Hash favicons
    tls_inspection: bool = True,     # Inspect TLS
    jarm_fingerprint: bool = True,   # JARM fingerprinting
    security_headers: bool = True    # Analyze security headers
)
```

## Output Schema

### BaseURLInfo

```json
{
  "url": "https://example.com",
  "final_url": "https://www.example.com",
  "scheme": "https",
  "host": "example.com",
  "port": 443,
  "ip": "93.184.216.34",
  "status_code": 200,
  "response_time_ms": 45.2,
  "content": {
    "title": "Example Domain",
    "content_type": "text/html",
    "content_length": 1256
  },
  "technologies": [
    {
      "name": "Nginx",
      "version": "1.18.0",
      "category": "Web Server",
      "confidence": 100,
      "source": "httpx"
    }
  ],
  "tls": {
    "version": "TLSv1.3",
    "cipher_suite": "TLS_AES_256_GCM_SHA384",
    "cipher_strength": "strong",
    "certificate": {
      "subject": "CN=example.com",
      "issuer": "CN=Let's Encrypt",
      "days_until_expiry": 45
    }
  },
  "security_headers": {
    "security_score": 80,
    "strict_transport_security": "max-age=31536000",
    "missing_headers": ["Content-Security-Policy"]
  },
  "favicon": {
    "md5": "f3418a...",
    "sha256": "8c7dd9...",
    "mmh3": -123456789
  }
}
```

## Performance

- **Throughput**: 50+ concurrent requests (configurable)
- **Speed**: ~100-200ms per target (network dependent)
- **Efficiency**: Bulk processing via httpx parallelism
- **Resource Usage**: Minimal memory footprint

## Security Considerations

- **Rate Limiting**: Built-in to avoid overwhelming targets
- **Timeout Controls**: Prevents hanging requests
- **Error Handling**: Graceful failure recovery
- **Input Validation**: Pydantic models for all inputs

## Testing

```bash
# Run tests
pytest backend/tests/test_http_probing.py

# With coverage
pytest backend/tests/test_http_probing.py --cov=app.recon.http_probing
```

## Troubleshooting

### httpx not found
```bash
# Install httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Add to PATH
export PATH=$PATH:~/go/bin
```

### Wappalyzer not found
```bash
# Install Wappalyzer
npm install -g wappalyzer

# Verify installation
wappalyzer --version
```

### TLS inspection fails
- Ensure Python cryptography package is installed
- Check firewall rules for outbound HTTPS (443)
- Verify target supports TLS

## Integration

### With Port Scanning
```python
# Get IPs from port scan
port_results = await port_scanner.scan(...)

# Build URLs for HTTP probing
urls = []
for ip_result in port_results:
    for port in ip_result.ports:
        if port.port in [80, 443, 8080, 8443]:
            scheme = "https" if port.port in [443, 8443] else "http"
            urls.append(f"{scheme}://{ip_result.ip}:{port.port}")

# Probe URLs
http_request = HttpProbeRequest(targets=urls)
http_results = await HttpProbeOrchestrator(http_request).run()
```

## Roadmap

- [ ] Screenshot capture integration (gowitness/aquatone)
- [ ] WebSocket support for real-time progress
- [ ] Database persistence (PostgreSQL/Neo4j)
- [ ] Advanced JARM fingerprint database
- [ ] Custom technology signatures
- [ ] Report generation (PDF/HTML)

## References

- [httpx Documentation](https://github.com/projectdiscovery/httpx)
- [Wappalyzer](https://www.wappalyzer.com/)
- [JARM Fingerprinting](https://github.com/salesforce/jarm)
- [Shodan Favicon Hash](https://www.shodan.io/search/facet/http.favicon.hash)
