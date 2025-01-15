<div align="center">

# UniVex
**Autonomous Penetration Testing Platform**

[![Version](https://img.shields.io/badge/version-1.0.0-cyan?style=flat-square)](https://github.com/BitR1ft/UniVex/releases/latest)
[![Python](https://img.shields.io/badge/python-3.11+-green?style=flat-square&logo=python)](https://python.org)
[![Node](https://img.shields.io/badge/node-20+-green?style=flat-square&logo=nodedotjs)](https://nodejs.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109-teal?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-14-black?style=flat-square&logo=nextdotjs)](https://nextjs.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue?style=flat-square&logo=docker)](https://docs.docker.com/compose)
[![Tests](https://img.shields.io/badge/tests-4300%2B-brightgreen?style=flat-square)](#testing)
[![License](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)](LICENSE)

Given a single IP or domain, UniVex autonomously runs the full offensive kill chain — recon through post-exploitation — with 145+ tools, 13 AI agent roles, and an HTTP proxy engine, all inside an isolated Kali container.

[Quick Start](#quick-start) · [Architecture](#architecture) · [API Reference](#api-reference) · [Contributing](#contributing)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Architecture](#architecture)
- [API Reference](#api-reference)
- [Testing](#testing)
- [CI/CD](#cicd)
- [Observability](#observability)
- [Security & Ethics](#security--ethics)
- [Contributing](#contributing)
- [Author](#author)

---

## Overview

UniVex is a full-stack, agentic penetration testing platform. It orchestrates the complete offensive security kill chain without manual intervention:

| Phase | Actions |
|-------|---------|
| **Reconnaissance** | Subdomain enumeration, port scanning, HTTP probing, tech fingerprinting |
| **Vulnerability Discovery** | Nuclei templates, CVE enrichment, MITRE/CWE/CAPEC mapping |
| **Exploitation** | Metasploit auto-configuration, approval gate, execution |
| **Session Upgrade** | Shell → Meterpreter, TTY stabilisation |
| **Post-Exploitation** | LinPEAS/WinPEAS, hash cracking, credential reuse |
| **Flag Capture** | `user.txt` + `root.txt`, MD5 verification, Neo4j storage |

The AI agent uses the **ReAct (Reasoning + Acting)** pattern powered by GPT-4 or Claude, communicating with 11 MCP tool servers running inside an isolated Kali Linux container.

---

## Features

### Core Capabilities

| Category | Details |
|----------|---------|
| **Agent Tools** | 145+ tools: web, cloud, network, AD, proxy, pivoting, deserialization |
| **AI Providers** | 12+ LLM providers: GPT-4, Claude, Gemini, Llama 3.3, and more |
| **Agent Roles** | 13 specialized roles: Planner, Recon, Exploit, WebApp, Report, Coder… |
| **AutoChain** | 46+ deterministic pipelines: bug bounty, AD, internal pentest, web deep |
| **HTTP Proxy** | Full intercepting proxy: capture, replay, intruder, WebSocket, CA cert |
| **Attack Graph** | Neo4j-backed graph with 30+ node types, BloodHound overlay |
| **Compliance Reports** | OWASP Top 10, PCI-DSS 4.0, NIST 800-53, ISO 27001, HIPAA, SOC 2 |
| **Observability** | VictoriaMetrics, ClickHouse, OpenTelemetry, Grafana |
| **Tests** | 4,300+ pytest · 215+ Jest · 54+ Playwright E2E |

### Selected Tool Coverage

| Domain | Tools |
|--------|-------|
| Recon & Discovery | subfinder, amass, httpx, waybackurls, gau, paramspider, katana |
| Subdomain Takeover | 80+ fingerprints, CNAME dangling detection, DNS zone transfer |
| JavaScript Analysis | Endpoint extraction, secret finder, retire.js, source-map, DOM sinks |
| Port Scanning | naabu, nmap, masscan |
| Web Vulnerability | nuclei, sqlmap, ffuf, nikto, xss hunter, wpscan |
| Active Directory | BloodHound, SharpHound, Responder, ntlmrelayx, Mimikatz, DCSync |
| Credential Attacks | Hash cracking, Kerberoasting, AS-REP roasting, Golden/Silver Ticket |
| Tunneling & Pivoting | Chisel, SSH tunnels, SOCKS5, Proxychains, port forwarding |
| Deserialization | ysoserial (Java, 20 chains), PHPGGC (PHP, 20 chains), .NET (13 chains) |
| Cloud Security | AWS, Azure, GCP, Docker, Kubernetes misconfigurations |

---

## Requirements

### Hardware

| Environment | CPU | RAM | Disk |
|-------------|-----|-----|------|
| Development | 2 cores | 8 GB | 20 GB |
| Staging | 4 cores | 16 GB | 50 GB |
| Production | 8+ cores | 32 GB | 200 GB+ |

### Software

| Dependency | Minimum Version |
|------------|----------------|
| Docker Engine | 24.0 |
| Docker Compose | v2.20 (plugin, not legacy standalone) |
| Python | 3.11 (local dev only) |
| Node.js | 20 LTS (local dev only) |

### API Keys

At least **one** LLM provider key is required.

| Variable | Provider | Free Tier |
|----------|----------|-----------|
| `OPENAI_API_KEY` | [OpenAI GPT-4](https://platform.openai.com) | No |
| `ANTHROPIC_API_KEY` | [Anthropic Claude](https://console.anthropic.com) | No |
| `GOOGLE_API_KEY` | [Google Gemini](https://aistudio.google.com/app/apikey) | Yes |
| `GROQ_API_KEY` | [Groq Llama 3.3 70B](https://console.groq.com/keys) | Yes |
| `OPENROUTER_API_KEY` | [OpenRouter (100+ models)](https://openrouter.ai/keys) | Varies |
| `NVD_API_KEY` | [NVD CVE enrichment](https://nvd.nist.gov/developers) | Yes |

---

## Quick Start

> Requires Docker 24+ and Docker Compose V2.

### Verified install (recommended)
```bash
curl -LO https://github.com/BitR1ft/UniVex/releases/latest/download/install.sh
curl -LO https://github.com/BitR1ft/UniVex/releases/latest/download/install.sh.sha256
sha256sum -c install.sh.sha256
bash install.sh
```

> **Always verify the checksum before executing.** Never pipe directly to `bash` without it.

### From source
```bash
git clone https://github.com/BitR1ft/UniVex.git && cd UniVex
cp .env.example .env   # fill in API keys and secrets
docker compose up --build
```

Open **http://localhost:3000** — default credentials are in your `.env`.

### Verify the stack
```bash
docker compose ps
curl -s http://localhost:8000/health | python3 -m json.tool
```

Expected:
```json
{
  "status": "healthy",
  "services": {
    "api": "operational",
    "database": "healthy",
    "neo4j": "healthy"
  }
}
```

### Podman / rootless containers
```bash
curl -LO https://github.com/BitR1ft/UniVex/releases/latest/download/install-podman.sh
curl -LO https://github.com/BitR1ft/UniVex/releases/latest/download/install-podman.sh.sha256
sha256sum -c install-podman.sh.sha256
bash install-podman.sh
```

See [docs/PODMAN_GUIDE.md](docs/PODMAN_GUIDE.md) for SELinux config, systemd integration, and RHEL enterprise deployment.

---

## Installation

### Development
```bash
git clone https://github.com/BitR1ft/UniVex.git univex
cd univex
cp .env.example .env

# Start required services
docker compose up -d postgres neo4j

# Backend
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
prisma generate && prisma db push
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Frontend (separate terminal)
cd frontend && npm install && npm run dev

# Kali tool containers (needed for real scans)
docker compose --profile tools up -d kali-tools recon-container
```

| Service | URL |
|---------|-----|
| Web UI | http://localhost:3000 |
| API + Swagger | http://localhost:8000/docs |
| Neo4j Browser | http://localhost:7474 |
| Grafana | http://localhost:3001 |

### Production
```bash
# Generate secrets
export SECRET_KEY=$(openssl rand -hex 32)
export POSTGRES_PASSWORD=$(openssl rand -base64 24)
export NEO4J_PASSWORD=$(openssl rand -base64 24)
export GRAFANA_PASSWORD=$(openssl rand -base64 24)

cp .env.example .env.production
# Edit .env.production — never commit this file

export IMAGE_TAG=v1.0.0
docker compose \
  -f docker/production/docker-compose.production.yml \
  --env-file .env.production \
  up -d --build

docker exec univex-prod-backend prisma migrate deploy
curl -s http://localhost:8000/readiness | python3 -m json.tool
```

For zero-downtime blue/green deployments, see [`.github/workflows/blue-green.yml`](.github/workflows/blue-green.yml).

---

## Configuration

Copy `.env.example` to `.env` and configure the following.

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | *(required)* | JWT signing key — `openssl rand -hex 32` |
| `ENVIRONMENT` | `development` | `development` · `staging` · `production` |
| `DEBUG` | `false` | Never enable in production |
| `LOG_LEVEL` | `INFO` | `DEBUG` · `INFO` · `WARNING` · `ERROR` |

### Database

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://...` | Full PostgreSQL connection URL |
| `POSTGRES_PASSWORD` | *(required)* | PostgreSQL password |
| `NEO4J_URI` | `bolt://neo4j:7687` | Neo4j Bolt URI |
| `NEO4J_PASSWORD` | *(required)* | Neo4j password |

### Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `ALGORITHM` | `HS256` | JWT algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Access token TTL |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token TTL |

### AI Providers

| Variable | Default |
|----------|---------|
| `OPENAI_MODEL` | `gpt-4o` |
| `ANTHROPIC_MODEL` | `claude-3-5-sonnet-20241022` |
| `GOOGLE_MODEL` | `gemini-1.5-flash` |
| `GROQ_MODEL` | `llama-3.3-70b-versatile` |
| `OPENROUTER_MODEL` | `anthropic/claude-3.5-sonnet` |

### AutoChain

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTO_APPROVE_RISK_LEVEL` | `none` | `none` · `low` · `medium` · `high` · `critical` |
| `NAABU_MCP_URL` | `http://kali-tools:8000` | Naabu MCP server |
| `NUCLEI_MCP_URL` | `http://kali-tools:8002` | Nuclei MCP server |
| `MSF_MCP_URL` | `http://kali-tools:8003` | Metasploit MCP server |

> **Warning:** Only set `AUTO_APPROVE_RISK_LEVEL=critical` in isolated lab environments.

---

## Usage

### Web Interface

1. Open http://localhost:3000 and register or log in.
2. **Create a Project** — enter a target IP or domain.
3. **Start Scan** — streams live tool output in the scan panel.
4. **Attack Graph** tab — interactive Neo4j visualization.
5. **AI Agent** tab — chat interface for manual guidance.

### AI Agent

The agent understands natural language and handles tool selection:
```
"What open ports did you find on 10.10.10.3?"
"Run a Nuclei scan on port 80"
"Search exploits for Apache 2.4.49"
"Try CVE-2021-41773 — I approve"
"Run LinPEAS on the active session"
"Crack 5f4dcc3b5aa765d61d8327deb882cf99"
```

Operations above the configured `AUTO_APPROVE_RISK_LEVEL` pause for a browser confirmation before proceeding.

### AutoChain Pipeline

AutoChain is a deterministic, non-LLM pipeline that runs the full pentest sequence via direct MCP tool calls. It is faster and more predictable than the free-form agent.
```bash
# Start a chain
curl -s -X POST http://localhost:8000/api/autochain/start \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"target": "10.10.10.3", "auto_approve_risk_level": "high"}'

# Poll status
curl -s http://localhost:8000/api/autochain/{chain_id}

# Stream real-time progress
curl -N http://localhost:8000/api/autochain/{chain_id}/stream

# Retrieve captured flags
curl -s http://localhost:8000/api/autochain/{chain_id}/flags

# Stop a running chain
curl -X DELETE http://localhost:8000/api/autochain/{chain_id}
```

### HTB Templates

Two pre-built HackTheBox templates ship with the platform:
```bash
# List available templates
curl -s http://localhost:8000/api/autochain/templates

# Launch htb_easy
curl -s -X POST http://localhost:8000/api/autochain/start/template \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"template_id": "htb_easy", "target": "10.10.10.3"}'
```

`htb_easy` phase sequence:

| Phase | Tool | Action |
|-------|------|--------|
| recon | naabu | TCP port scan — top 1000 |
| recon | ffuf | Directory/file brute-force |
| recon | nmap | Service and version detection |
| vuln_discovery | nuclei | CVE + web templates |
| exploitation | metasploit | Auto-configure and execute |
| post_exploitation | metasploit | Shell → Meterpreter, sysinfo |
| post_exploitation | flag_capture | `/root/root.txt`, `~/user.txt`, MD5 verify |

`htb_medium` extends this with LDAP enumeration, SQLMap, CMS detection, lateral movement, and retry logic.

---

## Architecture

### System Overview
```
┌─────────────────────────────────────────┐
│            Next.js 14 Frontend           │
│  Dashboard · AI Chat · Attack Graph      │
└──────────────┬──────────────────────────┘
               │ HTTP / WebSocket / SSE
┌──────────────▼──────────────────────────┐
│           FastAPI Backend :8000          │
│                                          │
│  /api/auth       JWT auth & tokens       │
│  /api/projects   CRUD, scan control      │
│  /api/agent      Chat, approve, stream   │
│  /api/autochain  Pipeline orchestration  │
│  /api/recon      Recon results           │
│  /api/graph      Cypher queries          │
│  /metrics        Prometheus endpoint     │
│                                          │
│  JWT auth · WAF middleware · Rate limiter│
└──────┬──────────────┬───────────────────┘
       │              │
┌──────▼───┐   ┌──────▼──────────────────┐
│PostgreSQL│   │       Neo4j :7687        │
│  :5432   │   │  30+ node types          │
│          │   │  40+ relationship types   │
│ Users    │   │  BloodHound overlay       │
│ Projects │   │  Real-time graph updates  │
│ Tasks    │   └─────────────────────────┘
└──────────┘
       │ JSON-RPC 2.0 (MCP)
┌──────▼──────────────────────────────────┐
│       Kali Linux Container (isolated)    │
│                                          │
│  NaabuServer      :8000  Port scanning   │
│  CurlServer       :8001  HTTP requests   │
│  NucleiServer     :8002  Vuln templates  │
│  MetasploitServer :8003  MSF Framework   │
│  FfufServer       :8004  Web fuzzing     │
│  SQLMapServer     :8005  SQL injection   │
│  HashCrackerServer:8006  John/Hashcat    │
│  NiktoServer      :8007  Web scanning    │
│  ProxyServer      :8008  HTTP intercept  │
│  DeserServer      :8012  Deserialization │
│  GraphServer            Neo4j queries    │
└─────────────────────────────────────────┘
```

### Network Segmentation

Four isolated Docker networks prevent lateral movement between platform components:

| Network | CIDR | Members |
|---------|------|---------|
| `db-network` | 172.20.1.0/24 | postgres, neo4j, backend |
| `backend-network` | 172.20.2.0/24 | backend, prometheus |
| `frontend-network` | 172.20.3.0/24 | frontend, backend |
| `tools-network` | 172.20.4.0/24 | kali-tools, recon-container, backend |

### Docker Services

| Service | Image | Ports | Purpose |
|---------|-------|-------|---------|
| `frontend` | `./frontend/Dockerfile` | **3000** | Next.js web UI |
| `backend` | `./backend/Dockerfile` | **8000** | FastAPI REST + WebSocket |
| `postgres` | `postgres:16-alpine` | 5432 | Relational store |
| `neo4j` | `neo4j:5.15-community` | 7474, 7687 | Attack graph |
| `kali-tools` | `./docker/kali/Dockerfile` | 8000–8007 | MCP tool servers |
| `recon-container` | `./docker/recon/Dockerfile` | — | Recon tooling |
| `prometheus` | `prom/prometheus:v2.51.0` | 9090 | Metrics collection |
| `grafana` | `grafana/grafana:10.4.0` | **3001** | Dashboards |

### AI Agent Data Flow
```
User message
    │
    ▼
IntentClassifier (Keyword / ML / LLM / Hybrid)
    │
    ├── web_app_attack  → ffuf / sqlmap / nikto
    ├── exploit         → metasploit / searchsploit
    ├── ad_attack       → kerbrute / impacket
    └── post_exploit    → linpeas / hash_cracker
    │
    ▼
LLM generates response + optional tool call
    │
    ├── No tool call    → stream text via SSE
    │
    └── Tool call
            │
            ├── Risk ≤ threshold  → execute via MCP → stream result
            │
            └── Risk > threshold  → send approval_required event
                                        │
                                  User approves/rejects
                                        │
                                  Execute → stream result
```

---

## API Reference

### Authentication
```bash
BASE=http://localhost:8000

# Register
curl -s -X POST $BASE/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@lab.local","password":"SecureP@ss1"}'

# Login
TOKEN=$(curl -s -X POST $BASE/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"SecureP@ss1"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Current user
curl -s $BASE/api/auth/me -H "Authorization: Bearer $TOKEN"
```

### Projects
```bash
# Create
curl -s -X POST $BASE/api/projects \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"HTB Lame","target":"10.10.10.3","enable_recon":true,"enable_exploitation":false}'

# List
curl -s $BASE/api/projects -H "Authorization: Bearer $TOKEN"

# Start / Stop scan
curl -s -X POST $BASE/api/projects/$PROJECT_ID/start -H "Authorization: Bearer $TOKEN"
curl -s -X POST $BASE/api/projects/$PROJECT_ID/stop  -H "Authorization: Bearer $TOKEN"

# Delete
curl -s -X DELETE $BASE/api/projects/$PROJECT_ID -H "Authorization: Bearer $TOKEN"
```

### AI Agent
```bash
# Chat
curl -s -X POST $BASE/api/agent/chat \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message":"What vulnerabilities did you find?","project_id":"'$PROJECT_ID'","stream":false}'

# Approve a pending operation
curl -s -X POST $BASE/api/agent/approve \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"operation_id":"'$OP_ID'","approved":true}'

# WebSocket stream
wscat -c "ws://localhost:8000/api/agent/ws/$CLIENT_ID" -H "Authorization: Bearer $TOKEN"
```

### Graph
```bash
# Cypher query
curl -s -X POST $BASE/api/graph/query \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"MATCH (t:Target)-[:HAS_VULNERABILITY]->(v:CVE) RETURN t, v LIMIT 20"}'

# Project graph
curl -s $BASE/api/graph/projects/$PROJECT_ID -H "Authorization: Bearer $TOKEN"
```

### Health
```bash
curl -s $BASE/health
curl -s $BASE/readiness
curl -s $BASE/metrics          # Prometheus
curl -N "$BASE/api/sse/events?project_id=$PROJECT_ID"   # SSE stream
```

---

## Testing

### Backend
```bash
cd backend

pytest                                      # full suite
pytest --cov=app --cov-report=html          # with coverage
pytest -m "not integration" -x              # fast (skip integration)
pytest tests/agent/test_autochain.py -v     # specific file
```

Key test files:

| File | Tests | Coverage |
|------|-------|---------|
| `test_auth.py` | 18 | JWT auth, registration, token refresh |
| `test_week9_cve_enrichment.py` | 25 | CVE / NVD enrichment |
| `test_week25_security.py` | 31 | Security middleware |
| `tests/agent/test_autochain.py` | 106 | AutoChain orchestrator |
| `tests/agent/test_week11_htb_templates.py` | 42 | HTB templates + MD5 flags |

**Total: 4,300+ backend test cases**

### Frontend
```bash
cd frontend
npm test                    # full suite
npm test -- --watch         # watch mode
npm run test:coverage        # coverage report
```

**Total: 215+ Jest test cases**

### End-to-End
```bash
npx playwright test                        # full E2E suite
npx playwright test e2e/recon.spec.ts      # specific spec
npx playwright test --ui                   # interactive mode
```

**Total: 54+ Playwright test cases**

### Load Testing
```bash
k6 run performance/k6-api.js \
  -e BASE_URL=http://localhost:8000 \
  -e TOKEN=$TOKEN
```

---

## CI/CD

| Workflow | Trigger | Actions |
|----------|---------|---------|
| `ci.yml` | push / PR to `main` | Lint, pytest, Jest, integration tests |
| `docker-build.yml` | push to `main` | Build + push images to registry |
| `deploy.yml` | tag `v*.*.*` | Deploy staging → production |
| `blue-green.yml` | manual / tag | Zero-downtime swap |
| `release.yml` | tag `v*.*.*` | GitHub Release + changelog |
| `security.yml` | schedule + PR | Bandit SAST, Trivy scan, Dependabot |

Branch strategy: `main` (protected) ← `release/*` ← `develop` ← `feature/*`. Hotfixes target `main` and `develop` simultaneously.

---

## Observability

### Prometheus Metrics

Available at `/metrics`. Key custom metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `autopentest_scans_total` | Counter | Total scans launched |
| `autopentest_scan_duration_seconds` | Histogram | Per-phase duration |
| `autopentest_vulnerabilities_found` | Gauge | Findings per project |
| `autopentest_exploits_attempted` | Counter | Exploit attempts by risk level |
| `autopentest_flags_captured_total` | Counter | CTF flags captured |
| `autopentest_agent_tool_calls_total` | Counter | Tool calls by name |

### Grafana Dashboards

Available at http://localhost:3001 (`admin` / `$GRAFANA_PASSWORD`).

Pre-built dashboards: **UniVex Overview**, **FastAPI Performance**, **Container Resources**, **Database Health**.

### Distributed Tracing
```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317 \
OTEL_EXPORTER_OTLP_INSECURE=true \
docker compose up -d backend
```

Compatible with Jaeger, Grafana Tempo, and any OTLP backend.

---

## Security & Ethics

> **Authorised use only.** This tool is for systems you own or have explicit written permission to test. Unauthorised use violates the CFAA, Computer Misuse Act, and equivalent laws in most jurisdictions.

### Built-in Controls

| Control | Description |
|---------|-------------|
| Scope enforcement | Agent will not target IPs outside the defined project scope |
| Approval gates | Operations above `AUTO_APPROVE_RISK_LEVEL` require explicit confirmation |
| Audit logging | All tool calls logged with user ID and timestamp |
| JWT authentication | Every API request requires a valid signed token |
| Rate limiting | 60 req/min · 1,000 req/hr per user (sliding window) |
| WAF middleware | Detects SQLi, XSS, path traversal in API inputs |
| Network isolation | Security tools run in an isolated Docker network with no direct internet access |
| mTLS | Mutual TLS between backend and all 11 MCP servers |

### Responsible Disclosure

Report security vulnerabilities via the [GitHub Security Advisory](https://github.com/BitR1ft/UniVex/security/advisories) tab — not as public issues.

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/USER_MANUAL.md](docs/USER_MANUAL.md) | Step-by-step usage guide |
| [docs/API_REFERENCE.md](docs/API_REFERENCE.md) | Full REST + GraphQL endpoint reference |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design and data flows |
| [docs/MCP_GUIDE.md](docs/MCP_GUIDE.md) | MCP server protocol reference |
| [docs/AGENT_ARCHITECTURE.md](docs/AGENT_ARCHITECTURE.md) | AI agent design |
| [docs/DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md) | PostgreSQL + Neo4j schema |
| [docs/AD_ATTACK_GUIDE.md](docs/AD_ATTACK_GUIDE.md) | BloodHound + AD methodology |
| [docs/PIVOTING_GUIDE.md](docs/PIVOTING_GUIDE.md) | Tunneling and pivoting |
| [docs/PROXY_GUIDE.md](docs/PROXY_GUIDE.md) | HTTP proxy/interceptor |
| [docs/CLOUD_SECURITY_GUIDE.md](docs/CLOUD_SECURITY_GUIDE.md) | AWS / Azure / GCP scanning |
| [docs/OBSERVABILITY.md](docs/OBSERVABILITY.md) | Metrics, tracing, logging |
| [docs/PODMAN_GUIDE.md](docs/PODMAN_GUIDE.md) | Rootless Podman (RHEL/Fedora) |
| [docs/SECURITY.md](docs/SECURITY.md) | Security controls + disclosure |
| [RELEASE_NOTES.md](RELEASE_NOTES.md) | v1.0.0 release notes |

---

## Contributing

1. Fork the repository.
2. Create a branch: `git checkout -b feature/your-feature`
3. Write tests for new functionality.
4. Run the test suites: `pytest` (backend), `npm test` (frontend).
5. Open a pull request against `main`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for code style, commit conventions, and the review process.

---

## Author

**BitR1FT** — Founder & Lead Developer  
GitHub: [@BitR1ft](https://github.com/BitR1ft)

Built on: Metasploit · Nuclei · Naabu · LangGraph · LangChain · OpenAI · Anthropic · react-force-graph

---

<div align="center">

Apache License — see [LICENSE](LICENSE)

**⚠️ For authorised security testing and educational purposes only. Always obtain written permission before testing any system.**

</div>
