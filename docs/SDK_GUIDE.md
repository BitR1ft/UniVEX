# UniVex SDK Guide

**Version:** 2.1.0  
**Author:** BitR1FT  
**Generated SDKs:** Python (`univex-sdk` on PyPI) · TypeScript (`@bitr1ft/univex` on npm)

---

## Overview

UniVex auto-generates typed SDK clients from its OpenAPI 3.1.0 specification using [Fern](https://buildwithfern.com/). Every GitHub release triggers the `sdk-generate.yml` workflow which publishes fresh clients to PyPI and npm.

The SDKs target the **versioned API** (`/v1/api/...`). Legacy unversioned routes (`/api/...`) remain available but return `X-API-Deprecated: true` headers until their sunset date of **2027-01-01**.

---

## Quick Install

### Python SDK

```bash
pip install univex-sdk
```

### TypeScript SDK

```bash
npm install @bitr1ft/univex
# or
yarn add @bitr1ft/univex
```

---

## Python SDK Usage

### Initialisation

```python
from univex import UniVexClient

client = UniVexClient(
    base_url="https://your-univex-instance.example.com",
    token="your-jwt-token",          # set after login
)

# Or use the async client for async/await workflows
from univex import AsyncUniVexClient
import asyncio

async_client = AsyncUniVexClient(
    base_url="https://your-univex-instance.example.com",
    token="your-jwt-token",
)
```

### Authentication

```python
# Register a new user
user = client.auth.register(
    email="analyst@company.com",
    username="analyst01",
    password="SecurePass123!",
    full_name="Security Analyst",
)

# Login and receive JWT tokens
tokens = client.auth.login(
    username="analyst01",
    password="SecurePass123!",
)

# Re-initialise the client with the access token
client = UniVexClient(
    base_url="https://your-univex-instance.example.com",
    token=tokens.access_token,
)
```

### Projects

```python
# Create a project
project = client.projects.create(
    name="ACME Corp External Assessment",
    description="Q1 2026 external perimeter pentest",
    target_domain="acme.com",
)

# List all projects
projects = client.projects.list()
for p in projects:
    print(p.id, p.name, p.status)

# Get a specific project
project = client.projects.get(project_id=project.id)
```

### Running a Recon Scan

```python
# Start reconnaissance
task = client.recon.start(
    project_id=project.id,
    targets=["acme.com", "192.168.1.0/24"],
    modules=["dns", "whois", "asn"],
)

# Poll for completion
import time
while True:
    status = client.recon.get_status(task_id=task.task_id)
    if status.status in ("completed", "failed"):
        break
    time.sleep(5)

# Fetch results
results = client.recon.get_results(task_id=task.task_id)
print(results.summary)
```

### AI Agent Chat

```python
# Send a message to the AI agent
response = client.agent.chat(
    message="Perform a full recon on acme.com and identify open ports",
    project_id=project.id,
    mode="autonomous",
)
print(response.content)
```

### Findings

```python
# List findings for a project
findings = client.findings.list(project_id=project.id, severity="critical")

# Create a finding manually
finding = client.findings.create(
    project_id=project.id,
    title="SQL Injection in /api/users",
    severity="critical",
    description="Unsanitised user input passed directly to SQL query",
    affected_component="/api/users?id=",
    cvss_score=9.8,
    owasp_category="A03:2021",
)

# Triage a finding
client.findings.triage(
    finding_id=finding.id,
    status="confirmed",
    assignee="analyst01",
    notes="Reproduced in staging — immediate fix required",
)
```

### Generating Reports

```python
# Create a PDF report
report = client.reports.create(
    project_id=project.id,
    report_type="executive",
    format="pdf",
    title="ACME Corp External Assessment Q1 2026",
)

# Download the report
pdf_bytes = client.reports.download(report_id=report.id)
with open("report.pdf", "wb") as f:
    f.write(pdf_bytes)
```

### Compliance Assessment

```python
# Run a SOC 2 compliance assessment
assessment = client.compliance.assess(
    project_id=project.id,
    framework="soc2",
    findings=[f.id for f in findings],
)

# Get the compliance report
report = client.compliance.get_report(framework="soc2")
print(f"Coverage: {report.coverage_percent}%")
print(f"Gaps: {len(report.gaps)}")
```

### Async Client Example

```python
import asyncio
from univex import AsyncUniVexClient

async def run_assessment(target: str):
    async with AsyncUniVexClient(
        base_url="https://univex.example.com",
        token="jwt-token",
    ) as client:
        project = await client.projects.create(name=f"Assessment: {target}")
        recon_task = await client.recon.start(
            project_id=project.id, targets=[target]
        )
        # Stream agent steps
        async for event in client.autochain.stream(chain_id="..."):
            print(event)

asyncio.run(run_assessment("example.com"))
```

---

## TypeScript SDK Usage

### Initialisation

```typescript
import { UniVexClient } from "@bitr1ft/univex";

const client = new UniVexClient({
  baseUrl: "https://your-univex-instance.example.com",
  token: "your-jwt-token",
});
```

### Authentication

```typescript
// Login
const tokens = await client.auth.login({
  username: "analyst01",
  password: "SecurePass123!",
});

const authedClient = new UniVexClient({
  baseUrl: "https://your-univex-instance.example.com",
  token: tokens.accessToken,
});
```

### Projects & Findings

```typescript
// Create a project
const project = await authedClient.projects.create({
  name: "External Assessment",
  targetDomain: "acme.com",
});

// List critical findings
const findings = await authedClient.findings.list({
  projectId: project.id,
  severity: "critical",
});

findings.forEach((f) => {
  console.log(`[${f.severity.toUpperCase()}] ${f.title} — CVSS ${f.cvssScore}`);
});
```

### Real-time Events (SSE)

```typescript
// Stream scan events
const eventSource = new EventSource(
  `https://univex.example.com/v1/api/sse/stream/scans/${projectId}`,
  { headers: { Authorization: `Bearer ${token}` } }
);

eventSource.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log("Scan event:", data);
};
```

---

## Regenerating SDKs Locally

Ensure you have the [Fern CLI](https://docs.buildwithfern.com/overview/cli-reference) installed:

```bash
npm install -g fern-api
```

From the repository root:

```bash
# Validate the OpenAPI spec
fern check

# Generate SDKs into sdks/ directory
fern generate --group local

# The generated SDKs appear at:
# sdks/python/   ← Python SDK
# sdks/typescript/ ← TypeScript SDK
```

### Updating the OpenAPI Spec

The spec lives at `fern/openapi/openapi.yaml`. To export the latest spec from the running FastAPI app:

```bash
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 &
curl http://localhost:8000/openapi.json | python -c "
import sys, json, yaml
print(yaml.dump(json.load(sys.stdin), allow_unicode=True, sort_keys=False))
" > ../fern/openapi/openapi.yaml
```

---

## API Versioning

UniVex follows a formal API versioning strategy:

| Prefix | Status | Sunset |
|---|---|---|
| `/v1/api/...` | **Current** (canonical) | — |
| `/api/...` | Deprecated (legacy) | 2027-01-01 |

All responses include the `X-API-Version` header. Legacy `/api/*` responses additionally include `X-API-Deprecated: true` and a `Link` header pointing to the versioned equivalent.

### Version Discovery

```bash
curl https://univex.example.com/api/version
```

```json
{
  "current_version": "1",
  "supported_versions": ["1"],
  "deprecated_versions": [],
  "current_prefix": "/v1",
  "legacy_prefix": "/api",
  "legacy_sunset": "2027-01-01",
  "docs": "/v1/docs"
}
```

### Migrating from Legacy to Versioned Routes

Replace the `/api/` prefix with `/v1/api/` in all your client code. The SDK handles this automatically — just update the `base_url` to include your server and the SDK will always use the canonical versioned routes.

---

## CI/CD Integration

The `sdk-generate.yml` GitHub Actions workflow runs automatically on every tagged release:

1. Exports the OpenAPI spec from the live FastAPI app
2. Generates the Python SDK using `fernapi/fern-python-sdk`
3. Generates the TypeScript SDK using `fernapi/fern-typescript-node-sdk`
4. Publishes Python SDK to PyPI as `univex-sdk`
5. Publishes TypeScript SDK to npm as `@bitr1ft/univex`
6. Attaches SDK archives to the GitHub release

### Required Repository Secrets

| Secret | Description |
|---|---|
| `FERN_TOKEN` | Fern API token (from [buildwithfern.com](https://buildwithfern.com)) |
| `PYPI_TOKEN` | PyPI API token for publishing `univex-sdk` |
| `NPM_TOKEN` | npm access token for publishing `@bitr1ft/univex` |

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'univex'`**  
Run `pip install univex-sdk` or install from source: `pip install sdks/python/`.

**`401 Unauthorized`**  
Obtain a fresh token via `client.auth.login(...)` and re-initialise the client.

**SDK method does not exist for a new endpoint**  
Regenerate the SDK locally with `fern generate --group local` after updating `fern/openapi/openapi.yaml`.

**TypeScript compilation errors after upgrading SDK**  
Check the [CHANGELOG](../CHANGELOG.md) for breaking changes. The SDK follows semver — patch releases are always backward compatible.
