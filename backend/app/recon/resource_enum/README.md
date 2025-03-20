# Resource Enumeration Module

Comprehensive endpoint discovery using Katana, GAU, and Kiterunner for the UniVex framework.

## Overview

The Resource Enumeration module discovers web endpoints, API routes, forms, and parameters using three powerful tools:

- **Katana**: Modern web crawler with JavaScript rendering
- **GAU (Get All URLs)**: Historical URL fetcher from multiple sources
- **Kiterunner**: Context-aware API endpoint brute-forcing

### Key Features

✅ **Multi-Tool Integration**: Combines Katana, GAU, and Kiterunner  
✅ **Parallel Execution**: Runs tools concurrently for speed  
✅ **URL Deduplication**: Intelligent merging of results  
✅ **Endpoint Classification**: Categorizes by type (auth, API, admin, etc.)  
✅ **Parameter Discovery**: Extracts and types parameters  
✅ **Form Extraction**: Discovers HTML forms and inputs  
✅ **HTTP Method Detection**: Identifies available methods  
✅ **Liveness Verification**: Checks endpoint availability  
✅ **Comprehensive Output**: JSON schema with full metadata

## Installation

### Prerequisites

The following tools must be installed:

```bash
# Install Katana
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Install GAU
go install github.com/lc/gau/v2/cmd/gau@latest

# Install Kiterunner
# Download from: https://github.com/assetnote/kiterunner/releases
wget https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_amd64.tar.gz
tar -xzf kiterunner_1.0.2_linux_amd64.tar.gz
sudo mv kr /usr/local/bin/

# Download wordlists
sudo mkdir -p /usr/share/kiterunner
wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz
tar -xzf routes-large.kite.tar.gz -C /usr/share/kiterunner/
```

### Python Dependencies

```bash
pip install httpx pydantic
```

## Usage

### CLI Usage

```bash
# Basic enumeration (Katana only)
python -m app.recon.resource_enum.cli enumerate https://example.com --mode basic

# Full enumeration (all tools)
python -m app.recon.resource_enum.cli enumerate https://example.com --mode full -v

# Passive enumeration (GAU only)
python -m app.recon.resource_enum.cli enumerate example.com --mode passive

# Active enumeration (Katana + Kiterunner)
python -m app.recon.resource_enum.cli enumerate https://api.example.com --mode active

# From file with output
python -m app.recon.resource_enum.cli enumerate -f targets.txt -o results.json

# Custom configuration
python -m app.recon.resource_enum.cli enumerate https://example.com \
    --crawl-depth 5 \
    --max-katana-urls 1000 \
    --verify-urls \
    --wordlist routes-small \
    -v
```

### Python API Usage

```python
import asyncio
from app.recon.resource_enum import ResourceEnumRequest, ResourceOrchestrator

async def enumerate_resources():
    # Create request
    request = ResourceEnumRequest(
        targets=["https://example.com"],
        mode="full",
        crawl_depth=3,
        max_katana_urls=500,
        js_crawling=True,
        verify_urls=True,
        parallel_execution=True
    )
    
    # Run enumeration
    orchestrator = ResourceOrchestrator(request)
    result = await orchestrator.run()
    
    # Process results
    print(f"Total endpoints: {result.stats.total_endpoints}")
    for endpoint in result.endpoints:
        print(f"{endpoint.method} {endpoint.url} ({endpoint.category})")

asyncio.run(enumerate_resources())
```

## Enumeration Modes

### Basic Mode
- **Tools**: Katana only
- **Use Case**: Quick crawl of a single site
- **Speed**: Fast
- **Coverage**: Medium

### Passive Mode
- **Tools**: GAU only
- **Use Case**: Historical data, no active scanning
- **Speed**: Fast
- **Coverage**: Historical only

### Active Mode
- **Tools**: Katana + Kiterunner
- **Use Case**: Active discovery with API brute-forcing
- **Speed**: Medium
- **Coverage**: High

### Full Mode (Default)
- **Tools**: Katana + GAU + Kiterunner
- **Use Case**: Maximum coverage
- **Speed**: Slow
- **Coverage**: Maximum

## Configuration Options

### Katana Options

| Option | Default | Description |
|--------|---------|-------------|
| `katana_enabled` | `true` | Enable/disable Katana |
| `crawl_depth` | `3` | Maximum crawl depth (1-5) |
| `max_katana_urls` | `500` | Max URLs to crawl |
| `js_crawling` | `true` | Enable JavaScript rendering |
| `extract_forms` | `true` | Extract HTML forms |

### GAU Options

| Option | Default | Description |
|--------|---------|-------------|
| `gau_enabled` | `true` | Enable/disable GAU |
| `gau_providers` | All | Providers to query |
| `max_gau_urls` | `1000` | Max historical URLs |
| `verify_urls` | `true` | Verify URL liveness |

### Kiterunner Options

| Option | Default | Description |
|--------|---------|-------------|
| `kiterunner_enabled` | `true` | Enable/disable Kiterunner |
| `wordlist` | `routes-large` | Wordlist to use |
| `kite_threads` | `10` | Number of threads |
| `kite_rate_limit` | `100` | Requests per second |

## Output Schema

```json
{
  "request": { ... },
  "endpoints": [
    {
      "url": "https://example.com/api/users",
      "path": "/api/users",
      "method": "GET",
      "category": "api",
      "parameters": [
        {
          "name": "id",
          "type": "id",
          "location": "query",
          "value": "1"
        }
      ],
      "forms": [],
      "source": "katana",
      "status_code": 200,
      "content_length": 1234,
      "is_live": true
    }
  ],
  "stats": {
    "total_endpoints": 150,
    "katana_endpoints": 60,
    "gau_endpoints": 70,
    "kiterunner_endpoints": 20,
    "live_endpoints": 145,
    "total_parameters": 85,
    "total_forms": 12,
    "categories": {
      "api": 50,
      "auth": 10,
      "admin": 5
    },
    "methods": {
      "GET": 120,
      "POST": 25,
      "PUT": 5
    },
    "execution_time": 45.5
  },
  "errors": [],
  "success": true
}
```

## Endpoint Categories

- **auth**: Authentication endpoints (login, signup, oauth)
- **api**: API endpoints (REST, GraphQL, JSON)
- **admin**: Administrative interfaces
- **file**: File upload/download endpoints
- **sensitive**: Potentially sensitive paths (config, backup, .git)
- **dynamic**: Dynamic content with parameters
- **static**: Static resources (CSS, JS, images)
- **unknown**: Unclassified endpoints

## Parameter Types

- **id**: Identifier parameters
- **file**: File-related parameters
- **search**: Search/query parameters
- **auth**: Authentication parameters (tokens, keys, passwords)
- **email**: Email addresses
- **url**: URL parameters
- **integer**: Numeric parameters
- **boolean**: Boolean flags
- **string**: Generic string parameters

## Integration with Other Modules

### With HTTP Probing (Month 5)

```python
# Discover endpoints first
resource_result = await resource_orchestrator.run()

# Probe discovered endpoints
from app.recon.http_probing import HttpProbeRequest, HttpProbeOrchestrator

urls = [endpoint.url for endpoint in resource_result.endpoints]
probe_request = HttpProbeRequest(targets=urls)
probe_result = await HttpProbeOrchestrator(probe_request).run()
```

### With Port Scanning (Month 4)

```python
# Scan ports first
from app.recon.port_scanning import PortScanner

port_results = await port_scanner.scan(targets)

# Extract HTTP services
http_urls = []
for result in port_results.results:
    for port in result.ports:
        if port.service in ['http', 'https', 'ssl/http']:
            scheme = "https" if "ssl" in port.service else "http"
            http_urls.append(f"{scheme}://{result.ip}:{port.port}")

# Enumerate resources
resource_request = ResourceEnumRequest(targets=http_urls)
resource_result = await ResourceOrchestrator(resource_request).run()
```

## Performance Considerations

- **Parallel Execution**: Enabled by default for speed
- **Rate Limiting**: Configurable for each tool
- **Timeout**: Global timeout prevents hanging
- **URL Limits**: Prevents memory issues with large results
- **Deduplication**: Reduces redundant data

## Testing

```bash
# Run tests
cd backend
pytest tests/test_resource_enum.py -v

# With coverage
pytest tests/test_resource_enum.py --cov=app.recon.resource_enum --cov-report=html
```

## Troubleshooting

### Tools Not Found

```bash
# Verify installations
katana -version
gau --version
kr version

# Check PATH
echo $PATH
which katana gau kr
```

### Timeout Issues

```bash
# Increase timeout
python -m app.recon.resource_enum.cli enumerate https://example.com --timeout 600
```

### Memory Issues

```bash
# Reduce limits
python -m app.recon.resource_enum.cli enumerate https://example.com \
    --max-katana-urls 100 \
    --max-gau-urls 200
```

## Examples

### Example 1: Basic Web Application

```bash
python -m app.recon.resource_enum.cli enumerate https://webapp.example.com \
    --mode basic \
    --crawl-depth 3 \
    -o webapp_endpoints.json
```

### Example 2: API Discovery

```bash
python -m app.recon.resource_enum.cli enumerate https://api.example.com \
    --mode active \
    --no-gau \
    --wordlist routes-large \
    --kite-threads 20 \
    -v
```

### Example 3: Historical Analysis

```bash
python -m app.recon.resource_enum.cli enumerate example.com \
    --mode passive \
    --gau-providers wayback commoncrawl \
    --max-gau-urls 5000 \
    --verify-urls
```

### Example 4: Bulk Targets

```bash
# Create targets.txt with multiple URLs
python -m app.recon.resource_enum.cli enumerate \
    -f targets.txt \
    --mode full \
    --parallel \
    -o bulk_results.json
```

## Architecture

```
resource_enum/
├── __init__.py           # Module exports
├── schemas.py            # Pydantic models
├── katana_wrapper.py     # Katana integration
├── gau_wrapper.py        # GAU integration
├── kiterunner_wrapper.py # Kiterunner integration
├── resource_orchestrator.py # Coordination & merging
├── cli.py                # CLI interface
└── README.md             # This file
```

## 🆕 Week 7 Additions (Days 42-48)

### Module Structure

```
app/recon/resource_enum/
├── katana_wrapper.py          # Low-level sync Katana wrapper (Month 6)
├── katana_orchestrator.py     # ✅ NEW – canonical KatanaOrchestrator (Day 42-43)
├── gau_wrapper.py             # Low-level async GAU wrapper (Month 6)
├── gau_orchestrator.py        # ✅ NEW – canonical GAUOrchestrator (Day 44)
├── kiterunner_wrapper.py      # Low-level sync Kiterunner wrapper (Month 6)
├── kiterunner_orchestrator.py # ✅ NEW – canonical KiterunnerOrchestrator (Day 45)
├── url_merger.py              # ✅ NEW – URLMerger pipeline (Day 46)
├── resource_orchestrator.py   # High-level coordinator (Month 6)
├── schemas.py                 # Pydantic models
└── README.md
```

### KatanaOrchestrator (`katana_orchestrator.py`)
Canonical BaseOrchestrator extension for Katana:
- Async `create_subprocess_exec` execution
- `KatanaConfig`: depth, JS rendering, scope enforcement, form extraction, rate limit
- `_normalise()` maps Katana JSON → canonical `Endpoint` objects with parameter extraction
- `crawl_targets()` classmethod for concurrent multi-host crawling

### GAUOrchestrator (`gau_orchestrator.py`)
Canonical BaseOrchestrator extension for Get All URLs:
- All 4 providers: Wayback Machine, Common Crawl, AlienVault OTX, URLScan.io
- `GAUConfig`: provider selection, blacklist, subdomain inclusion, URL cap
- `_normalise()` maps raw URLs → canonical `Endpoint` objects with provenance tracking
- `fetch_targets()` classmethod for concurrent fetching

### KiterunnerOrchestrator (`kiterunner_orchestrator.py`)
Canonical BaseOrchestrator extension for API endpoint brute-forcing:
- `KiterunnerConfig`: built-in wordlist resolution (`routes-large`/`routes-small`), custom paths, threads, rate limit
- Text-output fallback parser for legacy Kiterunner versions
- `_normalise()` maps Kiterunner JSON → canonical `Endpoint` objects tagged `["api-brute", "kiterunner"]`

### URLMerger (`url_merger.py`)
Multi-source URL deduplication and classification pipeline:
- URL normalisation (lowercase, strip fragment, sort query params, remove trailing slash)
- Multi-source merge with provenance tracking (`extra["sources"]`)
- URL categorisation: `auth > api > admin > file > sensitive > static > dynamic > unknown`
- Confidence scoring: liveness × source-count × method × parameters
- `URLMerger.stats()` summary dict

### /api/discovery/urls REST Endpoints
- `POST /api/discovery/urls` – start discovery (tool selection, per-tool config)
- `GET  /api/discovery/urls/{task_id}` – poll status + stats
- `GET  /api/discovery/urls/{task_id}/results` – results with `?category=`, `?source=`, `?min_confidence=` filters

---

## Author

**BitR1FT** (BitR1FT)  
Developed by: BitR1FT  
open-source startup project: UniVex - Month 6

## License

Part of the UniVex project.
