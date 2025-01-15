# UniVex v1.0.0 — Release Notes

**Release Date:** March 28, 2026  
**Type:** Initial Public Release  
**License:** MIT

---

## Overview

UniVex v1.0.0 is the first public release of the UniVex AI-powered penetration testing platform.
This release delivers a production-grade, fully autonomous offensive security platform designed
for professional security engineers and red teams.

Given a single target IP or domain, UniVex autonomously executes the complete offensive security
kill chain from reconnaissance through exploitation, post-exploitation, and compliance reporting
with minimal human intervention.

---

## What Is Included in v1.0.0

### AI Agent System (LangGraph ReAct)

- **13 specialised agent roles**: Planner, Recon, Exploit, WebApp, Report, Refiner, Generator, Adviser, Reflector, Enricher, Coder, Installer, SimpleJSON
- **ML-based intent classification** (SVM + TF-IDF) with 4 modes: Keyword, ML, LLM, Hybrid
- **LangGraph StateGraph** with typed state for reliable multi-agent orchestration
- **Human-in-the-loop approval gates** for dangerous operations (configurable risk threshold)
- **Real-time streaming** via Server-Sent Events (SSE) and WebSocket
- **Episodic memory** with Neo4j-backed knowledge graph (Graphiti)
- **Context summariser** — automatic compression at 75% token usage

### LLM Provider Support (12+ Providers)

| Provider | Models |
|----------|--------|
| OpenAI | GPT-4o, GPT-4-turbo, GPT-3.5-turbo |
| Anthropic | Claude 3.5 Sonnet, Claude 3 Opus |
| Google | Gemini 1.5 Flash, Gemini 1.5 Pro |
| Groq | Llama 3.3 70B, Mixtral 8x7B |
| OpenRouter | 100+ models via unified API |
| AWS Bedrock | Claude, Titan, Jurassic, Cohere |
| DeepSeek | DeepSeek Chat, DeepSeek Coder |
| Qwen | qwen-max, qwen-plus, qwen-turbo |
| Zhipu AI | GLM-4 series |
| Moonshot AI | Kimi long-context models |
| vLLM | Self-hosted / air-gapped deployments |

### Reconnaissance Pipeline (5 Phases)

- **Phase 1** — Domain Discovery: subfinder, amass, python-whois, certificate transparency
- **Phase 2** — Port Scanning: Naabu (fast), Nmap (deep service detection)
- **Phase 3** — HTTP Probing: httpx, technology fingerprinting, CDN detection
- **Phase 4** — Resource Enumeration: endpoint discovery, path brute-force (ffuf)
- **Phase 5** — CVE Enrichment: NVD API, MITRE ATT&CK / CWE / CAPEC mapping

### Exploitation Engine

- **Metasploit** auto-module selection and execution
- **ffuf** directory / file / parameter fuzzing (MCP port 8004)
- **SQLMap** injection detection and data extraction (MCP port 8005)
- **Nikto** web server scanner (MCP port 8007)
- **SearchSploit** offline exploit database search
- **WPScan** WordPress vulnerability scanner + CMS chain detection
- Configurable AUTO_APPROVE_RISK_LEVEL (none / low / medium / high / critical)

### Web Application Attack Suite (35+ Tools)

- XSS, Stored XSS, DOM XSS detection
- CSRF token analysis and bypass
- SSRF probe with OAST callbacks
- IDOR enumeration and BOLA/BFLA detection
- JWT analysis, algorithm confusion, key confusion attacks
- GraphQL introspection, injection, and batching attacks
- API security testing (rate limiting, auth bypass, mass assignment)
- OAuth 2.0 flow analysis

### Active Directory Attack Suite

| Tool | Capability |
|------|-----------|
| KerbrouteTool | Username enumeration via Kerberos |
| Enum4LinuxTool | SMB / LDAP host enumeration |
| ASREPRoastTool | AS-REP roasting (Impacket GetNPUsers) |
| KerberoastTool | Kerberoasting (Impacket GetUserSPNs) |
| PassTheHashTool | PtH via CrackMapExec / Impacket |
| LDAPEnumTool | LDAP anonymous / authenticated dump |
| CrackMapExecTool | SMB spray, WinRM login, secrets dump |

### Cloud Security (25 Tools)

- **AWS**: IAM enumeration, S3 bucket analysis, CloudTrail audit, Security Groups, Lambda scan, EC2 enumeration, Secrets Manager audit
- **Azure**: RBAC analysis, Storage Account audit, NSG review, App Registration scan, KeyVault access audit, Defender for Cloud
- **GCP**: IAM policy analysis, Cloud Storage review, Firewall rules, Service Account audit, BigQuery permissions, Cloud Function scan
- **Containers**: Docker socket exposure, image vulnerability scan, privileged container detection, secrets in environment
- **Kubernetes**: RBAC misconfiguration, pod security policy, network policy, secret exposure, node privilege escalation

### Compliance Engine

| Framework | Coverage |
|-----------|----------|
| OWASP Top 10 | Full mapping with evidence |
| PCI-DSS 4.0 | Requirements 6, 10, 11 |
| NIST SP 800-53 | CA, RA, SA, SI families |
| CIS Benchmarks | CIS Controls v8 |

### Report Engine (4 Report Types)

- **Executive Summary** — business risk, CVSS distribution charts
- **Technical Report** — full findings, PoC evidence, remediation
- **Compliance Report** — framework mapping, audit-ready output
- **Campaign Report** — multi-target aggregate analysis

Output formats: **PDF**, **HTML**, **Markdown**  
Artifact storage: **MinIO** with presigned download URLs

### Attack Surface Graph (Neo4j)

- 30+ node types: Target, Domain, Subdomain, IP, Port, Technology, CVE, Exploit, BloodHound User, Computer, Group, GPO, OU, ACL, Trust
- 40+ relationship types: HAS_SUBDOMAIN, RUNS_SERVICE, HAS_VULNERABILITY, ADMIN_TO, HAS_SESSION, MEMBER_OF
- Interactive 2D/3D force-graph visualization in the browser
- BloodHound attack path overlay — shortest path to Domain Admin
- Real-time updates as scans progress

### Integrations

- **SIEM**: Splunk, Elastic, Microsoft Sentinel, Datadog, Sumo Logic
- **Ticketing**: Jira, ServiceNow (findings export)
- **Notifications**: Webhooks, Slack, Discord
- **Analytics**: ClickHouse for pentest analytics, VictoriaMetrics for time-series
- **MinIO**: Artifact storage with presigned download URLs

### Security Controls

- **TOTP / 2FA** — RFC 6238 TOTP with backup codes
- **Cookie signing** — HMAC-signed secure cookies with SameSite=Strict
- **SSL/TLS config** — TLS 1.2 minimum, configurable cipher suites, HSTS
- **Account lockout** — configurable max attempts and lockout duration
- **IP allowlist** — production IP restriction middleware
- **mTLS** — mutual TLS between backend and all 11 MCP servers
- **Rate limiting** — Redis-backed per-user and per-IP rate limits
- **RBAC** — role-based access control on every data-modifying endpoint

### New Feature Modules (Full v1.0.0 Scope)

#### HTTP Proxy / Interceptor Engine
Full Burp Suite Community Edition equivalent (mitmproxy backend):
- Dynamic CA + leaf cert generation, scope rules, highlight rules
- Request Store: HAR/JSON/CSV export, Redis-backed TTL
- Intruder: Sniper, Battering Ram, Pitchfork, Cluster Bomb
- WebSocket frame capture, replay, and mutation
- Browser Bridge: Chrome/Firefox/system proxy auto-config with PAC file
- 17 REST endpoints at `/api/proxy/*`, 6 agent tools, React dashboard

#### Subdomain Takeover & DNS Tools
- `SubdomainTakeoverTool` — 80+ service fingerprints
- `DanglingCNAMEDetectTool`, `DNSZoneTransferTool`, `DNSCacheSnoopTool`

#### JavaScript Analysis
- `JSEndpointExtractTool`, `JSSecretFinderTool`, `JSLibVulnTool` (Retire.js DB), `SourceMapAnalyzeTool`, `DOMSinkAnalyzerTool`

#### Advanced Recon & OSINT
- `WaybackUrlsTool`, `GAUTool`, `ParamSpiderTool`, `KatanaCrawlerTool`, `WebArchiveSearchTool`
- `ShodanSearchTool`, `ShodanHostTool`, `CensysSearchTool`, `CensysCertSearchTool`, `FOFASearchTool`, `PassiveDNSTool`

#### WAF Detection & Bypass
- `WAFDetectTool` (55 signatures), `WAFBypassTool`, `PayloadEncoderTool`, `WAFFingerprintTool`

#### Deserialization Exploitation
- Java: ysoserial 20 gadget chains; PHP: PHPGGC 20 chains; .NET: 13 chains
- `JavaDeserTool`, `PHPDeserTool`, `DotNetDeserTool`, `DeserScanTool`
- Deserialization MCP server (:8012) with 12 tools

#### Tunneling & Pivoting
- `SOCKSProxyTool`, `PortForwardTool`, `ChiselTool`, `ProxychainsTool`, `SSHTunnelManagerTool`, `NetworkPivotMapTool`

#### BloodHound Integration
- `BloodHoundCollectTool`, `AttackPathQueryTool` (28 Cypher queries), `BloodHoundIngestTool`
- Full AD graph ingestion into Neo4j; 7 new BloodHound node types

#### Extended Credential Suite
- `ResponderTool`, `NTLMRelayTool`, `SecretsDumpTool`, `MimikatzTool`, `DCSyncTool`, `GoldenTicketTool`, `SilverTicketTool`, `HashCrackTool`

#### AutoChain Templates (46+)
- `bugbounty_full`, `ad_full_chain`, `internal_pentest`, `web_app_deep` — plus 42 variants
- Full kill-chain automation from initial recon to domain compromise

#### Worker Node Architecture
- `WorkerServer`, `WorkerClient` (circuit breaker + retry), `JobDispatcher`
- `docker-compose-worker.yml`, mTLS between nodes, Worker Node Guide

#### Browser Automation & OOB
- `BrowserMCPServer` (Playwright, 7 tools, MinIO screenshots)
- `OOBListener` (HTTP/DNS/SMTP), `OOBTool` (4 tools)

#### GraphQL API
- Strawberry GraphQL at `/graphql` — 14 queries, 17 mutations, 3 WebSocket subscriptions

#### Observability & Analytics
- VictoriaMetrics, ClickHouse (pentest analytics), OpenTelemetry tracing, 4 Grafana dashboards

#### SSL / Cookie Security
- `ssl_config.py`: `SSLConfig`, `CookieSigner`, `CookieSecurityConfig`
- 12 new SSL + cookie environment variables

#### Installer & Podman Support
- `scripts/install.sh` / `install-podman.sh` — whiptail TUI, 10-step wizard
- `tui_installer.py` — Python TUI installer with health checks

### User Interface

- **Cyberpunk design system** — dark mode, neon accents, CSS animations
- **Dashboard** with live stats, activity feed, scan timeline, vulnerability charts
- **Command Palette** (Ctrl+K) for keyboard-driven navigation
- **AI Agent Chat** with streaming responses, tool execution cards, approval dialogs
- **Attack Graph** with 3D Neo4j visualization and graph controls
- **Progressive Web App (PWA)** with service worker and offline support

### Testing

| Suite | Count |
|-------|-------|
| Backend pytest | 4,300+ |
| Frontend Jest | 215+ |
| E2E Playwright | 54+ |
| Load tests (k6) | 2 scripts |

### Infrastructure

- **Docker Compose** with 11 services
- **Nginx** with TLS 1.3, HTTP/2, security headers, WebSocket proxy
- **Blue/Green deployment** via GitHub Actions
- **Worker node architecture** with mTLS and circuit breaker
- **Podman** support for rootless / RHEL deployments
- **Observability stack**: Prometheus, Grafana, OpenTelemetry
- **Plugin system** with Docker sandbox isolation

### API Surface

- **REST API** at /api/* — 60+ endpoints
- **GraphQL API** at /graphql — 14 queries, 17 mutations, 3 WebSocket subscriptions
- **WebSocket** at /ws — real-time scan events and agent streaming

### MCP Tool Servers (11 Servers)

| Server | Port | Tools |
|--------|------|-------|
| Naabu | 8000 | Port scanning |
| Curl | 8001 | HTTP requests |
| Nuclei | 8002 | Vulnerability templates |
| Metasploit | 8003 | Exploitation |
| ffuf | 8004 | Fuzzing |
| SQLMap | 8005 | SQL injection |
| Hash Cracker | 8006 | Password cracking |
| Nikto | 8007 | Web server scanning |

---

## Quick Install

Verified install (recommended):

    curl -LO https://github.com/BitR1ft/UniVex/releases/latest/download/install.sh
    curl -LO https://github.com/BitR1ft/UniVex/releases/latest/download/install.sh.sha256
    sha256sum -c install.sh.sha256
    bash install.sh

Or from source:

    git clone https://github.com/BitR1ft/UniVex.git && cd UniVex
    cp .env.example .env
    docker compose up --build

---

## Known Limitations

- Metasploit, Nuclei, and Naabu require the Kali Linux tool container to be running
- Cloud tool scans require valid provider credentials in .env
- The GraphQL subscription endpoint requires a WebSocket-capable proxy in production
- Browser-based tools (Playwright) require the browser container profile

---

## Documentation

| Document | Description |
|----------|-------------|
| README.md | Complete project overview and quick start |
| SETUP.md | Detailed installation and configuration |
| docs/API_REFERENCE.md | Full REST + GraphQL API reference |
| docs/ARCHITECTURE.md | System architecture and data flows |
| docs/INSTALLATION_GUIDE.md | Production deployment guide |
| docs/SECURITY.md | Security controls and responsible disclosure |
| docs/USER_MANUAL.md | Step-by-step usage guide |
| CONTRIBUTING.md | Contribution guide |
| CHANGELOG.md | Full version history |

---

## License

MIT License — see LICENSE for details.

> **Legal Notice**: This tool is provided for authorised security testing and educational
> purposes only. Always obtain written permission before testing any system you do not own.
> The authors accept no liability for misuse.
