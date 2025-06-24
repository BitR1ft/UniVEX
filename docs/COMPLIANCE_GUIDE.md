# UniVex — Compliance Guide

> Author: BitR1FT

This guide explains how UniVex maps penetration testing findings to compliance frameworks and generates compliance reports for OWASP Top 10, PCI-DSS 4.0, NIST 800-53, and CIS Controls v8.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Supported Frameworks](#2-supported-frameworks)
3. [Running a Compliance Scan](#3-running-a-compliance-scan)
4. [OWASP Top 10](#4-owasp-top-10)
5. [PCI-DSS 4.0](#5-pci-dss-40)
6. [NIST SP 800-53](#6-nist-sp-800-53)
7. [CIS Controls v8](#7-cis-controls-v8)
8. [Compliance Reports](#8-compliance-reports)
9. [Continuous Compliance Monitoring](#9-continuous-compliance-monitoring)
10. [Remediation Workflows](#10-remediation-workflows)

---

## 1. Overview

UniVex v1.0.0 includes a compliance mapping engine (`backend/app/compliance/`) that:

1. Takes findings from any scan (web app, cloud, API, container)
2. Maps each finding to relevant compliance controls
3. Calculates a compliance score per framework (0–100%)
4. Generates a compliance report with pass/fail status per control
5. Provides remediation guidance linked to each failed control

### Architecture

```
Scan Results → ComplianceMapper → Framework Evaluators → Score Calculator
                                                        ↓
                              Compliance Report ← Report Generator
```

---

## 2. Supported Frameworks

| Framework | Version | Controls | Coverage |
|-----------|---------|---------|---------|
| **OWASP Top 10** | 2021 | 10 categories | Web app vulnerabilities |
| **PCI-DSS** | v4.0 (2022) | 12 requirements | Payment card security |
| **NIST SP 800-53** | Rev. 5 | 20 control families | Federal/enterprise baseline |
| **CIS Controls** | v8 (2021) | 18 controls | Technical best practices |

---

## 3. Running a Compliance Scan

### Via API

```bash
# Run compliance assessment for a project
curl -X POST http://localhost:8000/api/compliance/{project_id}/run \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "frameworks": ["owasp", "pci_dss", "nist", "cis"],
    "include_recommendations": true
  }'

# Get compliance results
curl http://localhost:8000/api/compliance/{project_id}/results \
  -H "Authorization: Bearer $TOKEN"
```

### Via Agent Chat

```
User: "Run a compliance check for this project against PCI-DSS"
Agent: *executes compliance scan, maps findings, generates score*
Agent: "PCI-DSS compliance score: 72/100. 3 requirements FAILED:
        Req 6.2.4 (SQL injection), Req 6.3.2 (sensitive data), Req 8.3.6 (MFA)"
```

### Response Format

```json
{
  "project_id": "uuid",
  "frameworks": {
    "owasp": {
      "score": 80.0,
      "status": "partial",
      "categories": {
        "A01_broken_access_control": {"status": "failed", "findings": [...]},
        "A02_cryptographic_failures": {"status": "passed", "findings": []},
        "A03_injection": {"status": "failed", "findings": [...]}
      }
    },
    "pci_dss": { "score": 72.0, "status": "partial", "requirements": {...} }
  },
  "overall_score": 76.0,
  "generated_at": "2026-03-21T11:00:00Z"
}
```

---

## 4. OWASP Top 10

### Coverage

| Category | ID | UniVex Tools |
|----------|-----|-------------|
| Broken Access Control | A01:2021 | IDOR tools, auth bypass tools |
| Cryptographic Failures | A02:2021 | TLS scanner, JWT analyzer |
| Injection | A03:2021 | SQLi tools, NoSQL injection, SSTI |
| Insecure Design | A04:2021 | Business logic analyzer |
| Security Misconfiguration | A05:2021 | Cloud tools, K8s scanner |
| Vulnerable Components | A06:2021 | SCA (via nuclei templates) |
| Auth & Session Mgmt | A07:2021 | Session tools, cookie analyzer |
| Software/Data Integrity | A08:2021 | CSRF tools, CI/CD analysis |
| Logging & Monitoring | A09:2021 | Log analysis, blind injection |
| SSRF | A10:2021 | SSRF detection tools |

### Scoring Logic

Each category is scored based on findings:
- **No findings:** 100% (passed)
- **Informational findings only:** 90%
- **Low severity:** 75%
- **Medium severity:** 50%
- **High severity:** 25%
- **Critical severity:** 0%

Overall OWASP score = average of all 10 category scores.

---

## 5. PCI-DSS 4.0

PCI-DSS v4.0 (published March 2022) supersedes v3.2.1 with updated requirements for multi-factor authentication, customised implementation, and targeted risk analysis.

### Requirement Mapping

| PCI-DSS Requirement | Description | UniVex Assessment |
|--------------------|-------------|------------------|
| **Req 1** — Network controls | Firewall/NSG rules | Cloud scanner + port scan |
| **Req 2** — Secure config | Default credentials, unnecessary services | Config scanner |
| **Req 3** — Protect stored account data | Encryption, truncation | Data exposure tools |
| **Req 4** — Protect data in transit | TLS configuration | TLS scanner |
| **Req 5** — Anti-malware | (external tool required) | N/A |
| **Req 6** — Secure software | Vulnerabilities, OWASP coverage | Full web scan |
| **Req 7** — Restrict access | RBAC, least privilege | IAM scanner |
| **Req 8** — User identification | MFA, password policy | Auth scanner |
| **Req 9** — Physical access | (manual assessment) | N/A |
| **Req 10** — Log all access | SIEM, audit logging | Log analysis |
| **Req 11** — Test regularly | Penetration testing | UniVex (this platform) |
| **Req 12** — Info security policy | (documentation review) | N/A |

### Critical PCI-DSS v4.0 Changes

- **Req 6.4.3** — Payment page scripts must be authorized and integrity checked
- **Req 8.3.6** — All non-consumer authentication now requires MFA
- **Req 8.6.1** — System/application accounts managed by policies

---

## 6. NIST SP 800-53

NIST 800-53 Rev. 5 contains 20 control families relevant to federal information systems and contractors.

### Mapped Control Families

| Family | ID | UniVex Coverage |
|--------|-----|----------------|
| Access Control | AC | RBAC test, privilege escalation |
| Audit & Accountability | AU | Log analysis, SIEM integration |
| Configuration Management | CM | Misconfiguration scanning |
| Identification & Authentication | IA | Auth bypass, MFA check |
| Incident Response | IR | (process-level) |
| Risk Assessment | RA | Vulnerability scanning, CVSS scoring |
| System & Communications Protection | SC | TLS, encryption, network segmentation |
| System & Information Integrity | SI | Vulnerability management, SAST |

### Baseline Selection

| Baseline | System Impact | Typical Use |
|----------|-------------|------------|
| LOW | Low | Internal tools, non-sensitive data |
| MODERATE | Moderate | Most enterprise systems |
| HIGH | High | National security, critical infrastructure |

UniVex targets **MODERATE** baseline by default.

---

## 7. CIS Controls v8

CIS Controls v8 consolidates the previous 20 controls into 18, organized by implementation group (IG1/IG2/IG3).

### Control Coverage

| Control | Title | UniVex Assessment |
|---------|-------|-----------------|
| CIS-1 | Inventory of Enterprise Assets | Network discovery |
| CIS-2 | Inventory of Software Assets | Tech detection |
| CIS-3 | Data Protection | Data exposure scanning |
| CIS-4 | Secure Config of Enterprise Assets | Config scanner |
| CIS-5 | Account Management | IAM scanner, auth tools |
| CIS-6 | Access Control Management | RBAC testing, privilege escalation |
| CIS-7 | Continuous Vulnerability Management | Nuclei scanning |
| CIS-8 | Audit Log Management | SIEM integration |
| CIS-9 | Email and Web Browser Protections | (external) |
| CIS-10 | Malware Defenses | (external) |
| CIS-11 | Data Recovery | Backup verification |
| CIS-12 | Network Infrastructure Management | Network analysis |
| CIS-13 | Network Monitoring and Defense | Traffic analysis |
| CIS-14 | Security Awareness | (process-level) |
| CIS-15 | Service Provider Management | Third-party scanning |
| CIS-16 | Application Software Security | Full web app testing |
| CIS-17 | Incident Response | (process-level) |
| CIS-18 | Penetration Testing | UniVex (this platform) |

---

## 8. Compliance Reports

### Generating a Compliance Report

```bash
# Generate PDF compliance report
curl -X POST http://localhost:8000/api/reports/generate \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "project_id": "uuid",
    "type": "compliance",
    "template": "pci_dss",
    "include_evidence": true,
    "include_remediation": true
  }'

# Download the PDF
curl http://localhost:8000/api/reports/{report_id}/pdf \
  -H "Authorization: Bearer $TOKEN" \
  -o compliance-report.pdf
```

### Report Contents

A compliance report includes:

1. **Executive Summary** — Overall score, top failures, risk level
2. **Framework Scorecard** — Visual pass/fail grid per control
3. **Finding Details** — Evidence, CVSS score, affected URLs
4. **Control Mapping** — Finding → framework control cross-reference
5. **Remediation Plan** — Prioritised action items with effort estimates
6. **Attestation Page** — Date, scope, methodology, tester signature line

---

## 9. Continuous Compliance Monitoring

Schedule recurring compliance scans to track posture over time:

```bash
# Schedule weekly PCI-DSS check
curl -X POST http://localhost:8000/api/campaigns \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Weekly PCI-DSS Monitor",
    "type": "compliance",
    "frameworks": ["pci_dss"],
    "targets": [{"url": "https://your-app.com"}],
    "schedule": {
      "type": "recurring",
      "cron": "0 6 * * 1"
    },
    "notifications": {
      "on_regression": true,
      "slack_webhook": "https://hooks.slack.com/..."
    }
  }'
```

A **regression** is triggered when the compliance score drops by more than 5 points between scans.

---

## 10. Remediation Workflows

### Jira Integration

When a compliance check fails, UniVex can automatically create Jira tickets:

```bash
# Configure Jira integration
curl -X POST http://localhost:8000/api/integrations \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "type": "jira",
    "config": {
      "url": "https://your-org.atlassian.net",
      "project_key": "SEC",
      "issue_type": "Bug",
      "token": "your-api-token",
      "auto_create_on_fail": true,
      "frameworks": ["pci_dss"]
    }
  }'
```

### Remediation Priority Matrix

| Severity | Framework | SLA |
|----------|-----------|-----|
| Critical | PCI-DSS Req 6 | 24 hours |
| High | PCI-DSS | 7 days |
| High | OWASP A01/A03/A10 | 7 days |
| Medium | NIST/CIS | 30 days |
| Low | Any | 90 days |

---

*UniVex v1.0.0 — Compliance Guide | BitR1FT*
