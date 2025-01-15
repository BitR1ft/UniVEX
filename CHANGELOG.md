# Changelog

All notable changes to UniVex are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2026-03-28

### Summary

First public release of UniVex — AI-powered, fully autonomous penetration testing platform.
Includes **145+ agent tools**, **13 AI agent roles**, **12+ LLM providers**, **11 MCP servers**,
HTTP proxy/interceptor engine, BloodHound AD attack paths, deserialization exploitation,
tunneling/pivoting, WAF bypass, JavaScript analysis, advanced OSINT, GraphQL API,
4,300+ tests, and **~98% bug bounty tool coverage**.

### Added — AI Agent System
- LangGraph multi-agent system with 13 specialised roles (Planner, Recon, Exploit, WebApp, Report, Refiner, Generator, Adviser, Reflector, Enricher, Coder, Installer, SimpleJSON)
- ML-based intent classification (SVM + TF-IDF) with Keyword, ML, LLM, and Hybrid modes
- Human-in-the-loop approval gates with configurable AUTO_APPROVE_RISK_LEVEL
- Real-time streaming via SSE and WebSocket
- Episodic memory store with Neo4j-backed Graphiti knowledge graph
- Context summariser (auto-compression at 75% token usage)
- Per-agent model configuration via agents.yaml and env vars
- MockLLMProvider, MockToolServer, MockMode for deterministic testing

### Added — LLM Providers (12+)
- OpenAI (GPT-4o, GPT-4-turbo, GPT-3.5-turbo)
- Anthropic (Claude 3.5 Sonnet, Claude 3 Opus)
- Google (Gemini 1.5 Flash, Gemini 1.5 Pro)
- Groq (Llama 3.3 70B, Mixtral 8x7B)
- OpenRouter (100+ models)
- AWS Bedrock (Claude, Titan, Jurassic, Cohere)
- DeepSeek (Chat, Coder)
- Qwen (qwen-max, qwen-plus, qwen-turbo)
- Zhipu AI GLM-4 series
- Moonshot AI Kimi long-context
- vLLM self-hosted cluster (air-gapped)
- ProviderRegistry with YAML-based provider configuration

### Added — Reconnaissance (10 Phases)
- Phase 1: Domain Discovery — subfinder, amass, python-whois, certificate transparency
- Phase 2: Subdomain Takeover — 80+ fingerprints, dangling CNAME, DNS zone transfer
- Phase 3: Port Scanning — Naabu (fast) + Nmap (deep, service detection)
- Phase 4: HTTP Probing — httpx, technology fingerprinting, CDN detection
- Phase 5: Resource Enumeration — ffuf endpoint and resource enumeration
- Phase 6: JavaScript Analysis — endpoint extraction, secret detection, Retire.js vuln DB
- Phase 7: Historical URL Mining — Wayback Machine, GAU, ParamSpider, Katana
- Phase 8: OSINT — Shodan, Censys, FOFA, Passive DNS
- Phase 9: WAF Detection — 55 WAF fingerprints, bypass technique selection
- Phase 10: CVE Enrichment — NVD API, MITRE ATT&CK/CWE/CAPEC mapping

### Added — HTTP Proxy / Interceptor Engine (11 new files)
- `backend/app/proxy/ssl_context.py` — dynamic CA + leaf cert generation per-host
- `backend/app/proxy/request_store.py` — in-memory + Redis request storage, HAR/JSON/CSV export
- `backend/app/proxy/interceptor.py` — mitmproxy wrapper, ScopeFilter, InterceptRule
- `backend/app/proxy/websocket_interceptor.py` — WebSocket frame capture, replay, mutation
- `backend/app/proxy/browser_bridge.py` — Chrome/Firefox/system proxy auto-config with PAC file
- `backend/app/mcp/servers/proxy_server.py` — ProxyMCPServer (:8008), 13 tools
- `backend/app/agent/tools/proxy_tools.py` — HttpInterceptTool, RequestReplayTool, RequestIntruderTool (4 attack modes), RequestComparerTool, TrafficLoggerTool, ScopeManagerTool
- `backend/app/api/proxy.py` — 17 REST endpoints at /api/proxy/*
- `frontend/components/proxy/` — ProxyDashboard, RequestTable, RequestDetail, ReplayPanel, IntruderPanel
- `frontend/hooks/useProxy.ts` — React hook for proxy state management

### Added — Subdomain Takeover & DNS (4 tools)
- `SubdomainTakeoverTool` — 80+ service fingerprints (GitHub Pages, Heroku, S3, Azure, Shopify, Netlify, Vercel, etc.)
- `DanglingCNAMEDetectTool`, `DNSZoneTransferTool`, `DNSCacheSnoopTool`
- `backend/data/subdomain_takeover_fingerprints.json` — 80+ fingerprints

### Added — JavaScript Analysis (5 tools)
- `JSEndpointExtractTool` — API endpoint extraction from JavaScript
- `JSSecretFinderTool` — API keys, tokens, credentials in JS
- `JSLibVulnTool` — vulnerable library detection (Retire.js DB)
- `SourceMapAnalyzeTool` — source map reconstruction
- `DOMSinkAnalyzerTool` — DOM XSS sink analysis
- `backend/data/js_vuln_db.json` — Retire.js-compatible vulnerability database

### Added — Advanced Recon & OSINT (11 tools)
- `WaybackUrlsTool`, `GAUTool`, `ParamSpiderTool`, `KatanaCrawlerTool`, `WebArchiveSearchTool`
- `ShodanSearchTool`, `ShodanHostTool`, `CensysSearchTool`, `CensysCertSearchTool`, `FOFASearchTool`, `PassiveDNSTool`

### Added — WAF Detection & Bypass (4 tools)
- `WAFDetectTool` — 55 WAF signatures (wafw00f-compatible)
- `WAFBypassTool` — automated bypass technique selection
- `PayloadEncoderTool` — URL/HTML/Base64/Unicode/Double-encode
- `WAFFingerprintTool` — detailed WAF fingerprinting with version hints
- `backend/data/waf_fingerprints.json`, `backend/data/waf_bypass_payloads.json`

### Added — Deserialization Exploitation (4 tools + MCP server)
- `JavaDeserTool` — ysoserial (20 gadget chains: CommonsCollections 1-7, Spring, Hibernate, Groovy)
- `PHPDeserTool` — PHPGGC (20 chains: Laravel, Symfony, Yii, Drupal, WordPress)
- `DotNetDeserTool` — .NET gadgets (13 chains: TypeConfuseDelegate, ObjectDataProvider, etc.)
- `DeserScanTool` — automated deserialization endpoint detection
- `backend/app/mcp/servers/deser_server.py` — Deserialization MCP server (:8012), 12 tools
- `backend/data/gadget_chains/java_gadgets.json`, `php_gadgets.json`, `dotnet_gadgets.json`

### Added — Tunneling & Pivoting (6 tools)
- `SOCKSProxyTool` — SOCKS5 proxy via SSH dynamic port forwarding
- `PortForwardTool` — local/remote SSH port forwarding
- `ChiselTool` — HTTP-tunneled SOCKS (firewall bypass)
- `ProxychainsTool` — route any command through proxy chain
- `SSHTunnelManagerTool` — multi-hop SSH tunnel lifecycle management
- `NetworkPivotMapTool` — internal network pivot path visualization

### Added — BloodHound Integration (5 tools)
- `BloodHoundCollectTool` — SharpHound collection, JSON/zip ingestion
- `AttackPathQueryTool` — 28 Cypher queries (shortest path to DA, DCSync rights, AdminTo chains)
- `BloodHoundIngestTool` — full AD graph ingestion into Neo4j
- `BloodHoundUsersTool`, `BloodHoundComputersTool` — AD object querying
- `backend/app/graph/bloodhound_ingest.py` — BloodHound ingestion engine
- `backend/data/bloodhound_queries.json` — 28 curated attack path queries
- 7 new Neo4j node types: BHUser, BHComputer, BHGroup, BHGPO, BHOP, BHDomain, BHTrust

### Added — Extended Credential Suite (8 tools)
- `ResponderTool` — LLMNR/NBT-NS/MDNS poisoning for credential capture
- `NTLMRelayTool` — ntlmrelayx SMB/LDAP relay attacks
- `SecretsDumpTool` — remote SAM/LSA/NTDS secrets extraction
- `MimikatzTool` — local credential extraction (logonpasswords, lsadump, dpapi)
- `DCSyncTool` — targeted DCSync for specific accounts or full domain
- `GoldenTicketTool` — Kerberos Golden Ticket creation
- `SilverTicketTool` — Kerberos Silver Ticket for service impersonation
- `HashCrackTool` — John/Hashcat hash cracking with wordlists

### Added — Exploitation
- Metasploit auto-module selection and execution
- ffuf fuzzing MCP server (port 8004)
- SQLMap injection MCP server (port 8005)
- Nikto web server scanner MCP server (port 8007)
- SearchSploit offline exploit database
- WPScan WordPress vulnerability scanner with CMS chain detection
- LinPEAS/WinPEAS post-exploitation enumeration
- Credential reuse pipeline (hash → SSH / SMB / WinRM)
- Reverse shell generation (bash, Python, PowerShell, Perl, nc)
- FlagCaptureTool for CTF flag reading and MD5 verification

### Added — Web Application Security (35+ Tools)
- XSS, Stored XSS, DOM XSS detection
- CSRF token analysis and bypass
- SSRF probe with OOB callbacks
- IDOR enumeration and BOLA/BFLA detection
- JWT analysis, algorithm confusion, key confusion
- GraphQL introspection, injection, batching attacks
- API security testing (rate limiting, auth bypass, mass assignment)
- OAuth 2.0 flow analysis

### Added — Active Directory (base tools)
- Kerbrute username enumeration, Enum4Linux SMB/LDAP enumeration
- AS-REP roasting (Impacket GetNPUsers), Kerberoasting (Impacket GetUserSPNs)
- Pass-the-Hash via CrackMapExec / Impacket
- LDAP anonymous and authenticated dump, CrackMapExec SMB spray

### Added — Browser Automation & OOB
- `BrowserMCPServer` (:8009) — Playwright browser with MinIO screenshot storage, 7 tools
- `OOBListener` — HTTP/DNS/SMTP out-of-band callback detection
- `OOBTool` — 4 tools for OOB payload delivery and result retrieval

### Added — Worker Node Architecture
- `WorkerServer` — FastAPI microservice for isolated tool execution
- `WorkerClient` — circuit breaker + retry with exponential back-off
- `JobDispatcher` — ALWAYS_REMOTE / LOCAL classification with phase heuristic
- `docker-compose-worker.yml`, mTLS between orchestrator and worker nodes

### Added — Cloud Security (25 Tools)
- AWS: IAM, S3, CloudTrail, Security Groups, Lambda, EC2, Secrets Manager
- Azure: RBAC, Storage, NSG, App Registrations, KeyVault, Defender for Cloud
- GCP: IAM, Cloud Storage, Firewall, Service Accounts, BigQuery, Cloud Functions
- Container: Docker socket exposure, image scanning, privileged containers
- Kubernetes: RBAC, pod security, network policy, secret exposure

### Added — Compliance Engine (6 Frameworks)
- OWASP Top 10 full mapping with evidence
- PCI-DSS 4.0 requirements 6, 10, 11
- NIST SP 800-53 CA/RA/SA/SI families
- ISO 27001 Annex A controls
- SOC 2 CC6/CC7/CC8 criteria
- HIPAA technical safeguards
- REST API at /api/compliance/*

### Added — GraphQL API
- Strawberry GraphQL at /graphql — 14 queries, 17 mutations, 3 WebSocket subscriptions
- DataLoaders for N+1 query prevention
- `strawberry-graphql[fastapi]>=0.235.0` added to requirements

### Added — Observability & Analytics
- ClickHouse analytics (pentest findings, scan duration, tool performance)
- VictoriaMetrics time-series storage
- MinIO artifact storage with presigned URLs
- `clickhouse-driver>=0.2.10`, `miniopy-async>=1.23.4` added to requirements
- Prometheus + Grafana (4 dashboards) + OpenTelemetry tracing

### Added — SSL / Cookie Security
- `backend/app/core/ssl_config.py` — SSLConfig, CookieSigner, CookieSecurityConfig
- Cookie signing: sign_cookie, verify_cookie, set_secure_cookie
- 12 new environment variables for SSL + cookie configuration
- certs/ca volume mount for mTLS certificates

### Added — Report Engine
- Executive Summary, Technical Report, Compliance Report, Campaign Report
- PDF, HTML, Markdown output formats
- MinIO artifact storage with presigned download URLs

### Added — Attack Surface Graph
- 30+ node types, 40+ relationship types
- Interactive 2D/3D force-graph visualization
- BloodHound attack path overlay — shortest path to Domain Admin

### Added — Integrations
- SIEM: Splunk, Elastic, Microsoft Sentinel, Datadog, Sumo Logic
- Ticketing: Jira, ServiceNow
- Notifications: Webhooks, Slack, Discord

### Added — Security Controls
- RFC 6238 TOTP with backup codes
- Cookie signing — HMAC-signed secure cookies with SameSite=Strict
- SSL/TLS config — TLS 1.2 minimum, configurable cipher suites, HSTS
- Account lockout with configurable max attempts
- IP allowlist middleware for production
- Mutual TLS between backend and all 11 MCP servers
- Redis-backed rate limiting, RBAC on all data-modifying endpoints

### Added — User Interface (14+ Dashboard Pages)
- Cyberpunk design system (dark mode, neon accents, CSS animations)
- Dashboard, AI Agent Chat, Attack Graph, Proxy Dashboard, Tools Dashboard
- Command Palette (Ctrl+K), Progressive Web App (PWA)

### Added — AutoChain Templates (46+)
- htb_easy / htb_medium / htb_hard, bugbounty_full, ad_full_chain, internal_pentest, web_app_deep
- 40+ additional variants (cloud, compliance, recon-only, etc.)

### Added — Infrastructure
- Docker Compose with 11 services
- Nginx TLS 1.3, HTTP/2, security headers, WebSocket proxy
- Blue/Green deployment workflow
- Podman support for rootless / RHEL deployments
- TUI installer (whiptail) — `scripts/install.sh`, `scripts/install-podman.sh`
- `tui_installer.py` — Python TUI with 10-step wizard and health checks
- Plugin system with Docker sandbox isolation

### Added — API
- REST API at /api/* with 70+ endpoints (including /api/proxy/*, /api/analytics/*)
- GraphQL API at /graphql with 14 queries, 17 mutations, 3 WebSocket subscriptions
- WebSocket at /ws for real-time events

### Added — MCP Tool Servers (11)
- Naabu (:8000), Curl (:8001), Nuclei (:8002), Metasploit (:8003), ffuf (:8004)
- SQLMap (:8005), Hash Cracker (:8006), Nikto (:8007)
- Proxy (:8008) — HTTP interception (new)
- Browser (:8009) — Playwright automation (new)
- Deser (:8012) — Deserialization exploitation (new)

### Added — Testing
- 4,300+ backend pytest tests
- 215+ frontend Jest tests
- 54+ Playwright E2E tests
- k6 load test scripts
- Developer CLIs: etester, ctester, ftester

### Added — Documentation
- docs/PROXY_GUIDE.md — HTTP proxy/interceptor usage guide
- docs/AD_ATTACK_GUIDE.md — BloodHound + AD attack methodology
- docs/PIVOTING_GUIDE.md — Tunneling and pivoting guide
- docs/WORKER_NODE_GUIDE.md, docs/VLLM_CLUSTER_GUIDE.md, docs/PODMAN_GUIDE.md
- docs/ARCHITECTURE.md, docs/CONFIGURATION_GUIDE.md, docs/OBSERVABILITY.md, docs/SECURITY.md
- bugbounty_tools_comparison.md — ~98% bug bounty tool coverage analysis
- CLAUDE.md — AI coding assistant guide, VS Code workspace configuration

### Added — Developer Tools
- etester: embedding provider test CLI
- ctester: classifier test CLI with 30-task benchmark suite
- ftester: full agent flow tester with MockLLMProvider
- CLAUDE.md AI coding assistant guide
- VS Code workspace configuration
