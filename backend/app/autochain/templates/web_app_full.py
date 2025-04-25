"""
AutoChain v2 — web_app_full Template

Comprehensive web application pentest chain:
  1. Recon (port scan, service detection, tech fingerprint)
  2. Web crawl / spider
  3. XSS scanning
  4. SQL injection scanning
  5. CSRF / SSRF probing
  6. IDOR testing
  7. Authentication bypass testing
  8. API discovery and security testing
  9. Injection testing (NoSQL, SSTI, LDAP, XXE, command injection)
  10. Report generation

Designed for maximum coverage against a single web application target.
Each phase is configurable via the optional `config` override dict.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class WebPhase(str, Enum):
    RECON = "recon"
    CRAWL = "crawl"
    XSS = "xss"
    SQLI = "sqli"
    CSRF_SSRF = "csrf_ssrf"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    API_SECURITY = "api_security"
    INJECTION = "injection"
    REPORT = "report"


@dataclass
class PhaseResult:
    """Result of a single template phase."""
    phase: WebPhase
    success: bool
    findings: List[Dict[str, Any]] = field(default_factory=list)
    tool_outputs: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0

    def finish(self, success: bool, error: Optional[str] = None) -> None:
        self.completed_at = datetime.utcnow()
        self.success = success
        self.error = error
        self.duration_seconds = (self.completed_at - self.started_at).total_seconds()


@dataclass
class TemplateRunResult:
    """Complete run result for the web_app_full template."""
    template_id: str
    target: str
    phases_completed: List[str] = field(default_factory=list)
    phases_failed: List[str] = field(default_factory=list)
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0
    all_findings: List[Dict[str, Any]] = field(default_factory=list)
    phase_results: List[PhaseResult] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    report_path: Optional[str] = None

    def finish(self) -> None:
        self.completed_at = datetime.utcnow()
        self.duration_seconds = (self.completed_at - self.started_at).total_seconds()
        # Aggregate finding counts
        self.total_findings = len(self.all_findings)
        for f in self.all_findings:
            sev = (f.get("severity") or "info").lower()
            if sev == "critical":
                self.critical_findings += 1
            elif sev == "high":
                self.high_findings += 1
            elif sev == "medium":
                self.medium_findings += 1
            elif sev == "low":
                self.low_findings += 1
            else:
                self.info_findings += 1


@dataclass
class WebAppFullConfig:
    """Configuration knobs for the web_app_full template."""
    # Recon
    port_range: str = "top-1000"
    enable_tech_detect: bool = True
    # Crawl
    crawl_depth: int = 3
    crawl_scope: str = "domain"  # domain | subdomain | all
    # XSS
    xss_contexts: List[str] = field(default_factory=lambda: ["html", "attr", "js", "url"])
    xss_use_dom_analysis: bool = True
    # SQLi
    sqli_risk_level: int = 2  # 1-3
    sqli_level: int = 3        # 1-5
    # CSRF/SSRF
    enable_csrf: bool = True
    enable_ssrf: bool = True
    ssrf_protocols: List[str] = field(default_factory=lambda: ["http", "https", "file", "gopher"])
    # IDOR
    idor_max_ids: int = 200
    idor_use_uuids: bool = True
    # Auth bypass
    auth_headers: List[str] = field(
        default_factory=lambda: ["X-Forwarded-For", "X-Original-URL", "X-Rewrite-URL"]
    )
    # API
    openapi_auto_discover: bool = True
    test_graphql: bool = True
    # Injection
    injection_types: List[str] = field(
        default_factory=lambda: ["nosql", "ssti", "ldap", "xxe", "cmd"]
    )
    # Rate limiting
    requests_per_second: float = 10.0
    # Output
    generate_report: bool = True
    report_format: str = "html"  # html | pdf


class WebAppFullTemplate:
    """
    web_app_full — The comprehensive web application pentest template.

    This template defines the ordered attack sequence and produces
    a structured TemplateRunResult that the AutoChain orchestrator
    can persist, stream, or pass to the report engine.

    Usage
    -----
    >>> template = WebAppFullTemplate(target="https://example.com")
    >>> result = await template.run()
    """

    TEMPLATE_ID = "web_app_full"
    NAME = "Web App Full Assessment"
    DESCRIPTION = (
        "Comprehensive web application pentest: recon → crawl → XSS → SQLi "
        "→ CSRF/SSRF → IDOR → auth bypass → API security → injection → report"
    )
    VERSION = "1.0.0"
    ESTIMATED_DURATION_MINUTES = 120

    # Ordered attack phases
    PHASE_ORDER: List[WebPhase] = [
        WebPhase.RECON,
        WebPhase.CRAWL,
        WebPhase.XSS,
        WebPhase.SQLI,
        WebPhase.CSRF_SSRF,
        WebPhase.IDOR,
        WebPhase.AUTH_BYPASS,
        WebPhase.API_SECURITY,
        WebPhase.INJECTION,
        WebPhase.REPORT,
    ]

    # Tools used per phase (informational — actual calls go through MCP)
    PHASE_TOOLS: Dict[WebPhase, List[str]] = {
        WebPhase.RECON: ["naabu", "httpx", "wappalyzer"],
        WebPhase.CRAWL: ["ffuf", "gospider", "hakrawler"],
        WebPhase.XSS: ["dalfox", "xsstrike", "reflected_xss_tool", "dom_xss_tool"],
        WebPhase.SQLI: ["sqlmap", "sqli_detect_tool"],
        WebPhase.CSRF_SSRF: ["csrf_detect_tool", "ssrf_probe_tool", "ssrf_blind_tool"],
        WebPhase.IDOR: ["idor_detect_tool", "idor_exploit_tool"],
        WebPhase.AUTH_BYPASS: ["auth_bypass_tool", "session_puzzling_tool", "rate_limit_bypass_tool"],
        WebPhase.API_SECURITY: ["openapi_parser_tool", "api_fuzz_tool", "cors_misconfig_tool", "api_rate_limit_tool"],
        WebPhase.INJECTION: ["nosql_inject_tool", "ssti_detect_tool", "ldap_inject_tool", "xxe_inject_tool", "cmd_inject_tool"],
        WebPhase.REPORT: ["report_engine"],
    }

    def __init__(
        self,
        target: str,
        *,
        config: Optional[WebAppFullConfig] = None,
        project_id: Optional[str] = None,
        auto_approve_risk_level: str = "medium",
    ) -> None:
        self.target = target
        self.config = config or WebAppFullConfig()
        self.project_id = project_id
        self.auto_approve_risk_level = auto_approve_risk_level
        self._result = TemplateRunResult(template_id=self.TEMPLATE_ID, target=target)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_scan_plan(self) -> Dict[str, Any]:
        """
        Return a structured scan plan dict that describes every phase,
        tool, and configuration value this template will use.

        This is the canonical serialisable representation consumed by
        the AutoChain orchestrator.
        """
        phases = []
        for phase in self.PHASE_ORDER:
            phase_cfg = self._build_phase_config(phase)
            phases.append({
                "phase": phase.value,
                "name": self._phase_display_name(phase),
                "tools": self.PHASE_TOOLS.get(phase, []),
                "config": phase_cfg,
                "on_failure": "continue",
                "description": self._phase_description(phase),
                "estimated_minutes": self._phase_estimate(phase),
            })

        return {
            "template_id": self.TEMPLATE_ID,
            "name": self.NAME,
            "description": self.DESCRIPTION,
            "version": self.VERSION,
            "target": self.target,
            "project_id": self.project_id,
            "auto_approve_risk_level": self.auto_approve_risk_level,
            "estimated_duration_minutes": self.ESTIMATED_DURATION_MINUTES,
            "phases": phases,
            "config": {
                "port_range": self.config.port_range,
                "crawl_depth": self.config.crawl_depth,
                "xss_contexts": self.config.xss_contexts,
                "sqli_risk_level": self.config.sqli_risk_level,
                "enable_csrf": self.config.enable_csrf,
                "enable_ssrf": self.config.enable_ssrf,
                "idor_max_ids": self.config.idor_max_ids,
                "injection_types": self.config.injection_types,
                "requests_per_second": self.config.requests_per_second,
                "generate_report": self.config.generate_report,
                "report_format": self.config.report_format,
            },
        }

    def get_phase_tools(self, phase: WebPhase) -> List[str]:
        """Return the list of tool names for a given phase."""
        return self.PHASE_TOOLS.get(phase, [])

    def get_all_tools(self) -> List[str]:
        """Return deduplicated list of all tools used by this template."""
        tools: List[str] = []
        seen: set = set()
        for phase_tools in self.PHASE_TOOLS.values():
            for t in phase_tools:
                if t not in seen:
                    tools.append(t)
                    seen.add(t)
        return tools

    def get_owasp_coverage(self) -> Dict[str, List[str]]:
        """Map OWASP Top 10 categories to the phases that cover them."""
        return {
            "A01:2021-Broken Access Control": [WebPhase.IDOR.value, WebPhase.AUTH_BYPASS.value],
            "A02:2021-Cryptographic Failures": [WebPhase.RECON.value],
            "A03:2021-Injection": [WebPhase.SQLI.value, WebPhase.INJECTION.value],
            "A04:2021-Insecure Design": [WebPhase.CSRF_SSRF.value, WebPhase.IDOR.value],
            "A05:2021-Security Misconfiguration": [WebPhase.RECON.value, WebPhase.API_SECURITY.value],
            "A06:2021-Vulnerable and Outdated Components": [WebPhase.RECON.value],
            "A07:2021-Identification and Authentication Failures": [WebPhase.AUTH_BYPASS.value],
            "A08:2021-Software and Data Integrity Failures": [WebPhase.CSRF_SSRF.value],
            "A09:2021-Security Logging and Monitoring Failures": [WebPhase.RECON.value],
            "A10:2021-Server-Side Request Forgery": [WebPhase.CSRF_SSRF.value],
            "XSS-Cross-Site Scripting": [WebPhase.XSS.value],
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_phase_config(self, phase: WebPhase) -> Dict[str, Any]:
        cfg = self.config
        if phase == WebPhase.RECON:
            return {
                "ports": cfg.port_range,
                "service_detection": True,
                "tech_detect": cfg.enable_tech_detect,
            }
        elif phase == WebPhase.CRAWL:
            return {"depth": cfg.crawl_depth, "scope": cfg.crawl_scope}
        elif phase == WebPhase.XSS:
            return {
                "contexts": cfg.xss_contexts,
                "dom_analysis": cfg.xss_use_dom_analysis,
                "rate_limit": cfg.requests_per_second,
            }
        elif phase == WebPhase.SQLI:
            return {
                "risk": cfg.sqli_risk_level,
                "level": cfg.sqli_level,
                "rate_limit": cfg.requests_per_second,
            }
        elif phase == WebPhase.CSRF_SSRF:
            return {
                "enable_csrf": cfg.enable_csrf,
                "enable_ssrf": cfg.enable_ssrf,
                "ssrf_protocols": cfg.ssrf_protocols,
            }
        elif phase == WebPhase.IDOR:
            return {
                "max_ids": cfg.idor_max_ids,
                "use_uuids": cfg.idor_use_uuids,
            }
        elif phase == WebPhase.AUTH_BYPASS:
            return {"headers": cfg.auth_headers}
        elif phase == WebPhase.API_SECURITY:
            return {
                "auto_discover": cfg.openapi_auto_discover,
                "test_graphql": cfg.test_graphql,
            }
        elif phase == WebPhase.INJECTION:
            return {"types": cfg.injection_types}
        elif phase == WebPhase.REPORT:
            return {
                "format": cfg.report_format,
                "generate": cfg.generate_report,
            }
        return {}

    @staticmethod
    def _phase_display_name(phase: WebPhase) -> str:
        names = {
            WebPhase.RECON: "Reconnaissance & Fingerprinting",
            WebPhase.CRAWL: "Web Crawl & Spider",
            WebPhase.XSS: "XSS Detection & Exploitation",
            WebPhase.SQLI: "SQL Injection Testing",
            WebPhase.CSRF_SSRF: "CSRF & SSRF Testing",
            WebPhase.IDOR: "IDOR & Access Control Testing",
            WebPhase.AUTH_BYPASS: "Authentication Bypass",
            WebPhase.API_SECURITY: "API Security Testing",
            WebPhase.INJECTION: "Advanced Injection Testing",
            WebPhase.REPORT: "Report Generation",
        }
        return names.get(phase, phase.value)

    @staticmethod
    def _phase_description(phase: WebPhase) -> str:
        descs = {
            WebPhase.RECON: "Port scan, service detection, web tech fingerprinting, subdomain enumeration.",
            WebPhase.CRAWL: "Spider all accessible endpoints, extract links, forms, and JS resources.",
            WebPhase.XSS: "Test reflected, stored, and DOM-based XSS across all discovered endpoints.",
            WebPhase.SQLI: "Automated SQL injection with SQLMap, covering all injection points.",
            WebPhase.CSRF_SSRF: "Detect missing CSRF tokens, weak SameSite cookies, and SSRF vectors.",
            WebPhase.IDOR: "Enumerate and test insecure direct object references via ID manipulation.",
            WebPhase.AUTH_BYPASS: "Test HTTP verb tampering, header injection, session fixation, rate limit bypass.",
            WebPhase.API_SECURITY: "Parse OpenAPI/GraphQL schemas, fuzz endpoints, check CORS, mass assignment.",
            WebPhase.INJECTION: "NoSQL, SSTI, LDAP, XXE, and command injection across all inputs.",
            WebPhase.REPORT: "Aggregate findings, deduplicate, calculate CVSS scores, generate final report.",
        }
        return descs.get(phase, "")

    @staticmethod
    def _phase_estimate(phase: WebPhase) -> int:
        """Estimated minutes per phase."""
        estimates = {
            WebPhase.RECON: 5,
            WebPhase.CRAWL: 10,
            WebPhase.XSS: 20,
            WebPhase.SQLI: 15,
            WebPhase.CSRF_SSRF: 10,
            WebPhase.IDOR: 10,
            WebPhase.AUTH_BYPASS: 10,
            WebPhase.API_SECURITY: 15,
            WebPhase.INJECTION: 20,
            WebPhase.REPORT: 5,
        }
        return estimates.get(phase, 10)
