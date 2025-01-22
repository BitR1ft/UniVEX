# Security Policy

## Supported Versions

| Version | Status |
|---------|--------|
| 1.x (current) | Active support |

Only the current major version (1.x) receives security patches and new releases.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

UniVex is a penetration testing platform — a vulnerability in the platform itself could be exploited against systems running it. Please use responsible disclosure.

### How to Report

1. **GitHub Private Advisory (preferred):** [Open a private advisory](https://github.com/BitR1ft/UniVex/security/advisories/new)
2. **Email:** Contact the author via the [GitHub profile](https://github.com/BitR1ft)

### What to Include

- Clear description of the vulnerability and its potential impact
- Step-by-step reproduction instructions (proof-of-concept)
- UniVex version, OS, Python version, and deployment method (Docker / manual)
- Relevant log output or error messages
- Your suggested fix (optional but appreciated)

---

## Response Timeline

| Milestone | Target |
|-----------|--------|
| Initial acknowledgement | 48 hours |
| Severity assessment | 5 business days |
| Fix for Critical/High | 14 days |
| Fix for Medium | 30 days |
| Public disclosure | Coordinated with reporter |

We follow a **90-day disclosure window** from first contact. If a fix is not possible within 90 days, we will communicate publicly with mitigations.

---

## Scope

### In Scope

- UniVex backend API (`backend/app/`)
- Authentication and authorization flows (JWT, TOTP, account lockout)
- Agent tool execution and sandboxing (`backend/app/mcp/`, `backend/app/agent/tools/`)
- Frontend security (XSS, CSRF, injection)
- Docker Compose service configuration
- Secrets management (environment variables, config files)
- Dependencies with known CVEs that are actively exploitable in UniVex's context

### Out of Scope

- Security issues in underlying third-party services (Neo4j, PostgreSQL, Redis) not caused by UniVex configuration choices
- Denial-of-service attacks requiring physical access or resources beyond a standard cloud VM
- Social engineering
- Reports from automated scanners without proof-of-concept exploitation

---

## Severity Classification

We use [CVSS v3.1](https://www.first.org/cvss/v3-1/) for scoring:

| CVSS Score | Severity | Example |
|------------|----------|---------|
| 9.0–10.0 | Critical | Unauthenticated RCE, credential exfiltration |
| 7.0–8.9 | High | Auth bypass, privilege escalation |
| 4.0–6.9 | Medium | SSRF, stored XSS, sensitive data leakage |
| 0.1–3.9 | Low | Information disclosure, minor config issues |

---

## Security Architecture

UniVex implements defense-in-depth. Key controls:

| Control | Implementation |
|---------|---------------|
| Authentication | JWT RS256 + TOTP (RFC 6238) + backup codes |
| Account lockout | 5 failed attempts triggers a 15-minute lockout |
| IP allowlist | Production middleware via `IP_ALLOWLIST` env var |
| Cookie security | HMAC-SHA256 signed cookies (`COOKIE_SIGNING_SALT`) |
| mTLS | Mutual TLS between backend and all MCP servers |
| SQL injection | asyncpg parameterized queries only (`$1`, `$2`, ...) |
| Command injection | Tool execution via MCP server abstraction — no `shell=True` |
| Secrets | All secrets loaded from env vars via `pydantic-settings` |
| RBAC | `require_role()` FastAPI dependency on all write endpoints |
| Rate limiting | Per-IP and per-user rate limiting on auth endpoints |
| SAST | CodeQL analysis in CI on every push |
| Dependency scanning | Trivy and Dependabot — weekly |
| Secret scanning | truffleHog on every PR |
| SBOM | Trivy SBOM generation on every release |

---

## Bug Bounty

UniVex does not currently operate a paid bug bounty program. Responsible disclosures are publicly acknowledged (with your permission) in the relevant release notes and CHANGELOG.md.

---

## Contacts

- **GitHub Private Advisory:** [Open an advisory](https://github.com/BitR1ft/UniVex/security/advisories/new) _(preferred)_
- **Author:** [@BitR1ft](https://github.com/BitR1ft)

---

*UniVex Security Policy — v1.0.0 — March 2026*
