"""
AutoChain v2 — owasp_top10 Template

Systematic OWASP Top 10 (2021) coverage template.
Each phase maps to exactly one OWASP category and runs the
appropriate tooling to test for that category.

Categories covered:
  A01 Broken Access Control
  A02 Cryptographic Failures
  A03 Injection
  A04 Insecure Design
  A05 Security Misconfiguration
  A06 Vulnerable and Outdated Components
  A07 Identification & Authentication Failures
  A08 Software & Data Integrity Failures
  A09 Security Logging & Monitoring Failures
  A10 Server-Side Request Forgery
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class OWASPA(str, Enum):
    """OWASP Top 10 (2021) category identifiers."""
    A01_ACCESS_CONTROL = "A01:2021"
    A02_CRYPTO = "A02:2021"
    A03_INJECTION = "A03:2021"
    A04_INSECURE_DESIGN = "A04:2021"
    A05_MISCONFIG = "A05:2021"
    A06_OUTDATED = "A06:2021"
    A07_AUTH = "A07:2021"
    A08_INTEGRITY = "A08:2021"
    A09_LOGGING = "A09:2021"
    A10_SSRF = "A10:2021"


@dataclass
class OWASPTop10Config:
    """Configuration for the OWASP Top 10 template."""
    # A01 Access Control
    test_idor: bool = True
    test_path_traversal: bool = True
    test_privilege_escalation: bool = True

    # A02 Cryptographic Failures
    check_tls_version: bool = True
    check_weak_ciphers: bool = True
    check_hsts: bool = True

    # A03 Injection
    test_sqli: bool = True
    test_nosql: bool = True
    test_cmd: bool = True
    test_ldap: bool = True
    test_xxe: bool = True

    # A04 Insecure Design
    test_csrf: bool = True
    test_open_redirect: bool = True

    # A05 Security Misconfiguration
    check_security_headers: bool = True
    check_directory_listing: bool = True
    check_default_credentials: bool = True

    # A06 Outdated Components
    fingerprint_versions: bool = True
    check_cve_database: bool = True

    # A07 Auth Failures
    test_brute_force: bool = True
    test_weak_passwords: bool = True
    test_session_management: bool = True

    # A08 Software/Data Integrity
    check_subresource_integrity: bool = True
    check_npm_audit: bool = False

    # A09 Logging & Monitoring
    test_log_injection: bool = True
    check_error_disclosure: bool = True

    # A10 SSRF
    test_ssrf: bool = True
    ssrf_blind: bool = True

    # Global
    max_requests_per_second: float = 10.0
    generate_report: bool = True
    report_format: str = "html"


class OWASPTop10Template:
    """
    owasp_top10 — OWASP Top 10 (2021) systematic coverage template.

    Each phase is labelled with its OWASP category, making it trivial
    to produce a compliance-ready report showing which categories were
    tested and what findings were discovered.
    """

    TEMPLATE_ID = "owasp_top10"
    NAME = "OWASP Top 10 Assessment"
    DESCRIPTION = (
        "Systematic OWASP Top 10 (2021) coverage: one phase per category, "
        "purpose-built tooling for each, compliance-ready report output."
    )
    VERSION = "1.0.0"
    ESTIMATED_DURATION_MINUTES = 150

    # Phase definitions: (phase_id, owasp_category)
    PHASES: List[Dict[str, Any]] = [
        {
            "id": "a01_access_control",
            "owasp": OWASPA.A01_ACCESS_CONTROL.value,
            "name": "A01 — Broken Access Control",
            "tools": ["idor_detect_tool", "idor_exploit_tool", "path_traversal_tool", "priv_esc_tool"],
            "description": "Test IDOR, path traversal, directory traversal, and privilege escalation.",
            "estimated_minutes": 20,
        },
        {
            "id": "a02_crypto",
            "owasp": OWASPA.A02_CRYPTO.value,
            "name": "A02 — Cryptographic Failures",
            "tools": ["tls_scan_tool", "ssl_analyzer"],
            "description": "Check TLS version, cipher suites, HSTS, certificate pinning.",
            "estimated_minutes": 10,
        },
        {
            "id": "a03_injection",
            "owasp": OWASPA.A03_INJECTION.value,
            "name": "A03 — Injection",
            "tools": ["sqli_detect_tool", "nosql_inject_tool", "cmd_inject_tool", "ldap_inject_tool", "xxe_inject_tool"],
            "description": "Comprehensive injection testing: SQL, NoSQL, OS command, LDAP, XXE.",
            "estimated_minutes": 25,
        },
        {
            "id": "a04_design",
            "owasp": OWASPA.A04_INSECURE_DESIGN.value,
            "name": "A04 — Insecure Design",
            "tools": ["csrf_detect_tool", "open_redirect_tool"],
            "description": "Detect CSRF vulnerabilities, open redirect chains, business logic flaws.",
            "estimated_minutes": 15,
        },
        {
            "id": "a05_misconfig",
            "owasp": OWASPA.A05_MISCONFIG.value,
            "name": "A05 — Security Misconfiguration",
            "tools": ["security_headers_tool", "dir_listing_tool", "default_creds_tool"],
            "description": "Check security headers (CSP, X-Frame, etc.), directory listing, default credentials.",
            "estimated_minutes": 10,
        },
        {
            "id": "a06_outdated",
            "owasp": OWASPA.A06_OUTDATED.value,
            "name": "A06 — Vulnerable & Outdated Components",
            "tools": ["wappalyzer", "cve_lookup_tool", "nuclei"],
            "description": "Fingerprint technologies, cross-reference with CVE/NVD, run Nuclei CVE templates.",
            "estimated_minutes": 15,
        },
        {
            "id": "a07_auth",
            "owasp": OWASPA.A07_AUTH.value,
            "name": "A07 — Identification & Authentication Failures",
            "tools": ["auth_bypass_tool", "brute_force_tool", "session_puzzling_tool", "jwt_forge_tool"],
            "description": "Brute-force protection, session fixation, weak password policies, JWT flaws.",
            "estimated_minutes": 20,
        },
        {
            "id": "a08_integrity",
            "owasp": OWASPA.A08_INTEGRITY.value,
            "name": "A08 — Software & Data Integrity Failures",
            "tools": ["sri_check_tool", "deserialization_tool"],
            "description": "Check SRI on script/link tags, insecure deserialisation patterns.",
            "estimated_minutes": 10,
        },
        {
            "id": "a09_logging",
            "owasp": OWASPA.A09_LOGGING.value,
            "name": "A09 — Security Logging & Monitoring Failures",
            "tools": ["log_inject_tool", "error_disclosure_tool"],
            "description": "Test log injection, verbose error messages, stack trace disclosure.",
            "estimated_minutes": 10,
        },
        {
            "id": "a10_ssrf",
            "owasp": OWASPA.A10_SSRF.value,
            "name": "A10 — Server-Side Request Forgery",
            "tools": ["ssrf_probe_tool", "ssrf_blind_tool"],
            "description": "Test open SSRF, blind SSRF via DNS/HTTP callbacks, cloud metadata endpoints.",
            "estimated_minutes": 10,
        },
        {
            "id": "report",
            "owasp": None,
            "name": "OWASP Report",
            "tools": ["report_engine"],
            "description": "Generate OWASP Top 10 compliance report with per-category pass/fail status.",
            "estimated_minutes": 5,
        },
    ]

    def __init__(
        self,
        target: str,
        *,
        config: Optional[OWASPTop10Config] = None,
        project_id: Optional[str] = None,
        auto_approve_risk_level: str = "medium",
    ) -> None:
        self.target = target
        self.config = config or OWASPTop10Config()
        self.project_id = project_id
        self.auto_approve_risk_level = auto_approve_risk_level

    def get_scan_plan(self) -> Dict[str, Any]:
        """Return orchestrator-compatible scan plan."""
        enabled_phases = [
            dict(p, config=self._phase_config(p["id"]))
            for p in self.PHASES
            if self._is_phase_enabled(p["id"])
        ]
        return {
            "template_id": self.TEMPLATE_ID,
            "name": self.NAME,
            "description": self.DESCRIPTION,
            "version": self.VERSION,
            "target": self.target,
            "project_id": self.project_id,
            "auto_approve_risk_level": self.auto_approve_risk_level,
            "estimated_duration_minutes": sum(
                p["estimated_minutes"] for p in enabled_phases
            ),
            "phases": enabled_phases,
            "owasp_categories": [
                p["owasp"] for p in enabled_phases if p.get("owasp")
            ],
        }

    def get_compliance_matrix(self) -> Dict[str, Dict[str, Any]]:
        """Return OWASP compliance test matrix with test status."""
        matrix: Dict[str, Dict[str, Any]] = {}
        for phase in self.PHASES:
            if not phase.get("owasp"):
                continue
            owasp_id = phase["owasp"]
            matrix[owasp_id] = {
                "name": phase["name"],
                "tools": phase["tools"],
                "enabled": self._is_phase_enabled(phase["id"]),
                "status": "pending",  # updated to pass/fail at runtime
            }
        return matrix

    def get_all_tools(self) -> List[str]:
        tools: List[str] = []
        seen: set = set()
        for phase in self.PHASES:
            for t in phase.get("tools", []):
                if t not in seen:
                    tools.append(t)
                    seen.add(t)
        return tools

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_phase_enabled(self, phase_id: str) -> bool:
        cfg = self.config
        enabled_map: Dict[str, bool] = {
            "a01_access_control": cfg.test_idor or cfg.test_path_traversal,
            "a02_crypto": cfg.check_tls_version,
            "a03_injection": cfg.test_sqli or cfg.test_nosql,
            "a04_design": cfg.test_csrf,
            "a05_misconfig": cfg.check_security_headers,
            "a06_outdated": cfg.fingerprint_versions,
            "a07_auth": cfg.test_brute_force or cfg.test_session_management,
            "a08_integrity": cfg.check_subresource_integrity,
            "a09_logging": cfg.test_log_injection,
            "a10_ssrf": cfg.test_ssrf,
            "report": cfg.generate_report,
        }
        return enabled_map.get(phase_id, True)

    def _phase_config(self, phase_id: str) -> Dict[str, Any]:
        cfg = self.config
        configs: Dict[str, Dict[str, Any]] = {
            "a01_access_control": {
                "test_idor": cfg.test_idor,
                "test_path_traversal": cfg.test_path_traversal,
                "test_privilege_escalation": cfg.test_privilege_escalation,
            },
            "a02_crypto": {
                "check_tls_version": cfg.check_tls_version,
                "check_weak_ciphers": cfg.check_weak_ciphers,
                "check_hsts": cfg.check_hsts,
            },
            "a03_injection": {
                "sqli": cfg.test_sqli,
                "nosql": cfg.test_nosql,
                "cmd": cfg.test_cmd,
                "ldap": cfg.test_ldap,
                "xxe": cfg.test_xxe,
            },
            "a04_design": {
                "csrf": cfg.test_csrf,
                "open_redirect": cfg.test_open_redirect,
            },
            "a05_misconfig": {
                "security_headers": cfg.check_security_headers,
                "directory_listing": cfg.check_directory_listing,
                "default_credentials": cfg.check_default_credentials,
            },
            "a06_outdated": {
                "fingerprint": cfg.fingerprint_versions,
                "cve_check": cfg.check_cve_database,
            },
            "a07_auth": {
                "brute_force": cfg.test_brute_force,
                "weak_passwords": cfg.test_weak_passwords,
                "session_management": cfg.test_session_management,
            },
            "a08_integrity": {
                "sri": cfg.check_subresource_integrity,
                "npm_audit": cfg.check_npm_audit,
            },
            "a09_logging": {
                "log_injection": cfg.test_log_injection,
                "error_disclosure": cfg.check_error_disclosure,
            },
            "a10_ssrf": {
                "ssrf": cfg.test_ssrf,
                "blind_ssrf": cfg.ssrf_blind,
            },
            "report": {
                "format": cfg.report_format,
                "compliance_matrix": True,
            },
        }
        return configs.get(phase_id, {})
