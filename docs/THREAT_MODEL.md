# UniVex — Threat Model

> Security architecture, STRIDE threat analysis, ATT&CK mapping, implemented
> mitigations, and residual risk register for UniVex v1.0.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Trust Boundaries](#trust-boundaries)
3. [STRIDE Threat Analysis](#stride-threat-analysis)
4. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
5. [Implemented Mitigations](#implemented-mitigations)
6. [Residual Risk Register](#residual-risk-register)
7. [Security Testing Coverage](#security-testing-coverage)
8. [Recommended Hardening Steps](#recommended-hardening-steps)

---

## System Overview

UniVex is an autonomous penetration testing platform. It includes:

- **Next.js Frontend** — Browser-based SPA accessing the API over HTTPS.
- **FastAPI Backend** — REST + WebSocket API server handling authentication,
  authorisation, AI orchestration, and tool dispatch.
- **PostgreSQL** — Stores user accounts, project configuration, audit logs.
- **Neo4j** — Stores the attack graph (nodes, edges, vulnerabilities).
- **AI Agent (LangGraph + GPT-4o)** — Orchestrates recon/exploitation tools via
  a ReAct loop; calls external LLM APIs.
- **Tool Sandbox (Docker)** — Ephemeral Kali Linux containers that execute
  offensive tools (nmap, nuclei, etc.) against *authorised targets only*.
- **CI/CD Pipeline (GitHub Actions)** — Builds, tests, and deploys the system.

### Data Classification

| Data Type | Classification | Examples |
|-----------|---------------|----------|
| User credentials | Secret | Password hashes, JWT secrets |
| API keys | Secret | OpenAI, Anthropic keys |
| Scan findings | Confidential | CVEs, exploitable paths, credentials found |
| Project config | Internal | Target IP, scan parameters |
| Audit logs | Internal | User actions, tool executions |
| Metrics / traces | Internal | Request counts, latencies |
| Documentation | Public | This document |

---

## Trust Boundaries

```

  INTERNET / ATTACKER NETWORK                                      
                                                                   
   Browser (HTTPS) [ BOUNDARY 1: TLS Termination (Nginx) ]  
                                                                   
       
     INTERNAL NETWORK (Docker bridge)                           
                                                                
     Frontend (HTTP) [ BOUNDARY 2: JWT Validation ]       
                                                               
                              Backend                           
                             /    \                             
                [ B3: DB auth ]  [ B4: Tool Sandbox ]           
                  /       \           \                         
            Postgres     Neo4j    Kali Container                
                                                               
                            [ BOUNDARY 5: Target Network ]      
                                 Target System                  
       
                                                                   
  GitHub Actions  [ BOUNDARY 6: GHCR / Registry ]             

```

**Boundaries:**

| # | Boundary | Protection |
|---|----------|-----------|
| 1 | Internet → Nginx | TLS 1.3, HSTS, rate limiting |
| 2 | Frontend → Backend | JWT access tokens, CORS, WAF |
| 3 | Backend → Databases | Password auth, network isolation |
| 4 | Backend → Tool Sandbox | Docker network isolation, resource limits |
| 5 | Tool Sandbox → Target | Scoped to authorised targets only |
| 6 | CI/CD → Registry | GITHUB_TOKEN, OIDC, SBOM |

---

## STRIDE Threat Analysis

### T1: Spoofing

| Threat | Asset | Likelihood | Impact | Mitigation |
|--------|-------|-----------|--------|-----------|
| Credential theft via phishing | User accounts | Medium | High | JWT short TTL (30 min), refresh rotation |
| JWT forgery | API access | Low | Critical | HS256 with 32-byte secret, expiry checks |
| Service impersonation (backend→LLM) | AI decisions | Low | High | API key secrets, OTEL trace IDs |

### T2: Tampering

| Threat | Asset | Likelihood | Impact | Mitigation |
|--------|-------|-----------|--------|-----------|
| SQL injection via API | PostgreSQL | Low | Critical | Parameterised queries (Prisma ORM), WAF |
| Cypher injection via graph queries | Neo4j | Low | Critical | Parameterised Cypher, WAF |
| Prompt injection via user input | AI agent | Medium | High | System prompt hardening, tool allowlist |
| Supply chain attack (pip/npm) | Code | Low | Critical | pip-audit + npm audit in CI, Dependabot |
| Container image tampering | Runtime | Low | Critical | SBOM (Anchore), Trivy scan, GHCR provenance |

### T3: Repudiation

| Threat | Asset | Likelihood | Impact | Mitigation |
|--------|-------|-----------|--------|-----------|
| Denial of action | Audit trail | Medium | Medium | Immutable structured audit log (`core/audit.py`) |
| Log tampering | Audit evidence | Low | High | Logs shipped to external SIEM (configurable) |

### T4: Information Disclosure

| Threat | Asset | Likelihood | Impact | Mitigation |
|--------|-------|-----------|--------|-----------|
| API keys in logs | Secret credentials | Medium | Critical | `core/secrets.py` redacts secrets from logs |
| Scan results cross-tenant | Confidential findings | Low | High | Project-level ownership checks on all queries |
| Stack traces in API errors | Internal structure | Medium | Medium | Production: generic 500 errors; debug=false |
| Secrets in environment | Secret credentials | Medium | High | `.env` in `.gitignore`; Gitleaks in CI |
| DB credentials in Docker image | Secret credentials | Low | Critical | Build args not baked in; runtime env injection |

### T5: Denial of Service

| Threat | Asset | Likelihood | Impact | Mitigation |
|--------|-------|-----------|--------|-----------|
| API flood | Backend availability | Medium | High | Sliding-window rate limiting (`core/rate_limit.py`) |
| Runaway AI agent loop | Backend CPU | Medium | Medium | `AI_MAX_ITERATIONS=20`, `AI_TIMEOUT_SECONDS=300` |
| Tool process fork bomb | Kali sandbox | Low | High | Docker CPU quota, memory limit, timeout |
| Large file upload | Disk / memory | Medium | Medium | `MAX_UPLOAD_MB` env limit, multipart parsing |

### T6: Elevation of Privilege

| Threat | Asset | Likelihood | Impact | Mitigation |
|--------|-------|-----------|--------|-----------|
| Viewer role accessing admin endpoints | RBAC | Low | High | `require_permission()` on every protected route |
| IDOR — accessing another user's project | Data isolation | Low | High | Owner check on every project fetch/mutate |
| Container escape | Host system | Very Low | Critical | Rootless Docker, no privileged containers |
| LLM tool misuse (executing arbitrary commands) | Tool sandbox | Low | Critical | Tool allowlist, pre-execution risk check |

---

## MITRE ATT&CK Mapping

Threats mapped to [MITRE ATT&CK Enterprise v14](https://attack.mitre.org/):

| ATT&CK Technique | ID | Description | Our Control |
|------------------|----|-------------|-------------|
| Valid Accounts | T1078 | Credential theft / reuse | MFA recommendation, refresh rotation |
| Brute Force | T1110 | Login brute force | Rate limit: 5 attempts / 15 min |
| Exploit Public-Facing Application | T1190 | SQLi / XSS | WAF middleware, parameterised queries |
| Supply Chain Compromise | T1195 | Malicious dependency | Dependabot, pip-audit, npm audit |
| Credentials in Files | T1552.001 | `.env` in repo | `.gitignore`, Gitleaks CI scan |
| Container Escape | T1611 | Docker privilege escalation | Rootless, no privileged mode |
| Injection | T1059 | Prompt injection | System prompt hardening |
| Data from Information Repositories | T1213 | Unauthorised data access | RBAC + owner checks |

---

## Implemented Mitigations

### Authentication & Authorisation

- [x] JWT access tokens (30 min TTL) + refresh tokens (7 day TTL)
- [x] bcrypt password hashing with configurable work factor (≥12)
- [x] RBAC with three roles: `admin`, `analyst`, `viewer`
- [x] 13 granular permissions mapped to roles
- [x] Project-level ownership isolation

### Input Validation

- [x] WAF middleware: SQL injection, XSS, path traversal pattern detection
- [x] Pydantic request models: all input parsed and typed before processing
- [x] Zod frontend schemas: client-side validation before submission

### Secrets Management

- [x] `core/secrets.py`: startup validation; secrets never logged
- [x] `.env` in `.gitignore`; Gitleaks runs in CI on every PR
- [x] Rotation schedule documented in OPERATIONS_RUNBOOK.md

### Network Security

- [x] Docker internal network isolation (services not exposed on host by default)
- [x] Nginx TLS termination with HSTS (production)
- [x] CORS restricted to `ALLOWED_ORIGINS`

### Tool Sandbox Security

- [x] Ephemeral containers destroyed after each tool run
- [x] Memory and CPU limits enforced
- [x] Network mode configurable (`bridge` default, not host)
- [x] Tool allowlist — only approved tools can be invoked

### Supply Chain Security

- [x] Dependabot: weekly pip + npm updates, monthly Docker image bumps
- [x] pip-audit + npm audit in CI security pipeline
- [x] SBOM generated for every Docker image (Anchore)
- [x] Trivy container vulnerability scan on every build

### Audit & Observability

- [x] 15-event `AuditAction` enum — every sensitive action logged
- [x] Structured JSON audit log with correlation IDs
- [x] Prometheus metrics + Grafana dashboards
- [x] OpenTelemetry tracing support

---

## Residual Risk Register

| Risk ID | Description | Likelihood | Impact | Residual Risk | Owner | Status |
|---------|-------------|-----------|--------|--------------|-------|--------|
| R-001 | Prompt injection causing out-of-scope scans | Medium | High | Medium | Backend team | 🟡 Monitoring |
| R-002 | LLM provider data leakage (scan findings sent to OpenAI) | Low | High | Low | — |  Accepted |
| R-003 | Zero-day in third-party dependency | Low | Critical | Medium | DevOps | 🟡 Dependabot |
| R-004 | Insider threat (admin user abusing access) | Low | High | Low | — |  Accepted with audit log |
| R-005 | Container escape via kernel vulnerability | Very Low | Critical | Very Low | DevOps |  Accepted |
| R-006 | DDoS against public-facing Nginx | Medium | Medium | Low | — | 🟡 CDN/WAF recommended |

---

## Security Testing Coverage

| Test Type | Location | Scope |
|-----------|---------|-------|
| Unit — RBAC | `tests/test_week25_security.py` | Permission checks, role assignments |
| Unit — WAF | `tests/test_week25_security.py` | SQLi/XSS/path-traversal patterns |
| Unit — Rate limit | `tests/test_week25_security.py` | Sliding window, burst handling |
| Unit — Secrets | `tests/test_week25_security.py` | Secret validation, redaction |
| Chaos — secrets leaking | `tests/test_chaos.py` | Invariant: no secrets in responses |
| CI — dependency audit | `.github/workflows/security.yml` | pip-audit, npm audit |
| CI — SAST | `.github/workflows/security.yml` | Bandit (Python), CodeQL (JS + Python) |
| CI — container scan | `.github/workflows/security.yml` | Trivy SARIF |
| CI — secret scan | `.github/workflows/security.yml` | Gitleaks |

---

## Recommended Hardening Steps

The following are **not yet implemented** but recommended for production hardening:

1. **MFA / TOTP** — Add TOTP as a second factor for admin accounts.
2. **Network Policy** — Use Kubernetes NetworkPolicy (or Docker `--internal` flag)
   to restrict tool sandbox egress to target CIDRs only.
3. **Immutable infrastructure** — Use read-only root filesystems for all containers
   except the tool sandbox.
4. **WAF at network layer** — Deploy Cloudflare or AWS WAF in front of Nginx.
5. **SIEM integration** — Ship audit logs to an external SIEM (Splunk, Elastic).
6. **Penetration test** — Commission a third-party pentest before public launch.
7. **Bug bounty programme** — Establish a responsible disclosure policy.
8. **Content Security Policy** — Add strict CSP headers to the Next.js frontend.

---

*Last updated: March 2026*