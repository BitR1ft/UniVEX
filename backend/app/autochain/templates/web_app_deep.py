"""
AutoChain v3 — web_app_deep Template

Deep web application penetration test:
  1.  Spider / crawl — katana, hakrawler, gospider
  2.  JavaScript analysis — endpoint extraction, secrets, source maps, DOM sinks
  3.  WAF detection & bypass — fingerprint vendor, generate bypass payloads
  4.  API discovery — OpenAPI/Swagger, GraphQL introspection, hidden endpoints
  5.  OpenAPI parsing — extract all parameters for targeted testing
  6.  HTTP proxy intercept — capture all traffic for manual review baseline
  7.  XSS — reflected, stored, DOM-based, blind XSS
  8.  SQL injection — error-based, blind, time-based, OOB
  9.  SSRF — blind OOB, cloud metadata, internal service discovery
 10.  CSRF — missing/broken token detection
 11.  IDOR — sequential ID, UUID, parameter pollution
 12.  SSTI — Jinja2, Twig, Freemarker, Mako, Velocity
 13.  XXE — entity injection, SSRF via XXE, OOB exfiltration
 14.  Deserialization — Java/PHP/.NET gadget chains
 15.  Authentication bypass — broken auth, account takeover vectors
 16.  JWT attacks — alg:none, RS256→HS256, key confusion, weak secret
 17.  Report generation — OWASP-mapped deep web app pentest report

Maximises OWASP Top 10 + OWASP WSTG coverage in a single chain.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class WebAppTech(str, Enum):
    """Primary application technology for targeted payloads."""
    UNKNOWN    = "unknown"
    PHP        = "php"
    JAVA       = "java"
    DOTNET     = "dotnet"
    NODEJS     = "nodejs"
    PYTHON     = "python"
    RUBY       = "ruby"
    GO         = "go"


class AuthType(str, Enum):
    """Authentication mechanism present on the target."""
    NONE       = "none"
    BASIC      = "basic"
    FORM       = "form"
    JWT        = "jwt"
    OAUTH2     = "oauth2"
    SAML       = "saml"
    API_KEY    = "api_key"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class WebAppDeepConfig:
    """Configuration for the web_app_deep template."""

    # ── Target context ────────────────────────────────────────────────────
    app_tech: WebAppTech = WebAppTech.UNKNOWN
    auth_type: AuthType = AuthType.NONE
    valid_token: Optional[str] = None          # Bearer / session token for auth testing
    test_unauthenticated: bool = True
    test_authenticated: bool = True

    # ── Crawling ─────────────────────────────────────────────────────────
    crawl_depth: int = 5
    crawl_scope: str = "subdomain"             # subdomain | domain | strict
    crawl_js_forms: bool = True
    crawl_max_urls: int = 10_000

    # ── JavaScript analysis ───────────────────────────────────────────────
    js_extract_endpoints: bool = True
    js_find_secrets: bool = True
    js_source_map: bool = True
    js_dom_sinks: bool = True

    # ── WAF ──────────────────────────────────────────────────────────────
    waf_detect: bool = True
    waf_bypass: bool = True
    waf_bypass_level: int = 3               # 1-5; 5 = most aggressive

    # ── API discovery ────────────────────────────────────────────────────
    api_discover: bool = True
    openapi_url: Optional[str] = None
    graphql_endpoint: Optional[str] = None
    discover_hidden_endpoints: bool = True
    api_wordlist: str = "api_endpoints_wordlist"

    # ── XSS ──────────────────────────────────────────────────────────────
    xss_enabled: bool = True
    xss_reflected: bool = True
    xss_stored: bool = True
    xss_dom: bool = True
    xss_blind: bool = True
    blind_xss_callback: Optional[str] = None

    # ── SQLi ─────────────────────────────────────────────────────────────
    sqli_enabled: bool = True
    sqli_error_based: bool = True
    sqli_blind: bool = True
    sqli_time_based: bool = True
    sqli_oob: bool = True
    sqli_level: int = 3
    sqli_risk: int = 2

    # ── SSRF ─────────────────────────────────────────────────────────────
    ssrf_enabled: bool = True
    ssrf_blind_oob: bool = True
    ssrf_cloud_metadata: bool = True
    ssrf_internal_discovery: bool = True

    # ── CSRF ─────────────────────────────────────────────────────────────
    csrf_enabled: bool = True

    # ── IDOR ─────────────────────────────────────────────────────────────
    idor_enabled: bool = True
    idor_max_ids: int = 200
    idor_uuid: bool = True

    # ── SSTI ─────────────────────────────────────────────────────────────
    ssti_enabled: bool = True
    ssti_engines: List[str] = field(
        default_factory=lambda: ["jinja2", "twig", "freemarker", "velocity", "mako", "pebble"]
    )

    # ── XXE ──────────────────────────────────────────────────────────────
    xxe_enabled: bool = True
    xxe_oob: bool = True
    xxe_ssrf: bool = True

    # ── Deserialization ───────────────────────────────────────────────────
    deser_enabled: bool = True
    deser_java: bool = True
    deser_php: bool = True
    deser_dotnet: bool = True

    # ── Auth bypass ───────────────────────────────────────────────────────
    auth_bypass_enabled: bool = True
    test_default_creds: bool = True
    test_password_reset: bool = True
    test_account_takeover: bool = True

    # ── JWT ──────────────────────────────────────────────────────────────
    jwt_enabled: bool = True
    jwt_alg_none: bool = True
    jwt_key_confusion: bool = True
    jwt_weak_secret: bool = True
    jwt_kid_injection: bool = True

    # ── Output ────────────────────────────────────────────────────────────
    generate_report: bool = True
    report_format: str = "html"
    owasp_mapping: bool = True
    wstg_mapping: bool = True


# ---------------------------------------------------------------------------
# Template
# ---------------------------------------------------------------------------

class WebAppDeepTemplate:
    """
    web_app_deep — Deep web application penetration test chain.

    Comprehensive OWASP Top 10 + WSTG coverage with 17 attack phases.
    Designed for high-value web application targets that require
    thorough coverage beyond standard automated scanning.
    """

    TEMPLATE_ID = "web_app_deep"
    NAME = "Web Application Deep Dive"
    DESCRIPTION = (
        "Deep web app pentest: crawl, JS analysis, WAF bypass, API discovery, "
        "XSS, SQLi, SSRF, CSRF, IDOR, SSTI, XXE, deserialization, auth bypass, "
        "JWT attacks, and OWASP/WSTG-mapped report."
    )
    VERSION = "3.0.0"
    ESTIMATED_DURATION_MINUTES = 240

    PHASE_ORDER: List[str] = [
        "crawl",
        "js_analysis",
        "waf_detect",
        "api_discovery",
        "proxy_intercept",
        "xss",
        "sqli",
        "ssrf",
        "csrf",
        "idor",
        "ssti",
        "xxe",
        "deserialization",
        "auth_bypass",
        "jwt_attacks",
        "report",
    ]

    PHASE_TOOLS: Dict[str, List[str]] = {
        "crawl":          ["katana", "hakrawler", "gospider", "paramspider"],
        "js_analysis":    ["js_endpoint_extract_tool", "js_secret_finder_tool",
                           "source_map_analyze_tool", "dom_sink_analyzer_tool"],
        "waf_detect":     ["waf_detect_tool", "waf_fingerprint_tool", "waf_bypass_tool",
                           "payload_encoder_tool"],
        "api_discovery":  ["ffuf", "kiterunner", "openapi_parse_tool", "graphql_introspect_tool"],
        "proxy_intercept":["http_intercept_tool", "traffic_logger_tool"],
        "xss":            ["dalfox", "xsstrike", "dom_xss_scanner"],
        "sqli":           ["sqlmap", "ghauri"],
        "ssrf":           ["ssrf_probe_tool", "ssrf_blind_tool", "cloud_metadata_tool"],
        "csrf":           ["csrf_scan_tool"],
        "idor":           ["idor_test_tool", "bola_test_tool", "param_pollution_tool"],
        "ssti":           ["tplmap", "ssti_scan_tool"],
        "xxe":            ["xxe_inject_tool"],
        "deserialization":["java_deser_tool", "php_deser_tool", "dotnet_deser_tool",
                           "ysoserial_tool"],
        "auth_bypass":    ["auth_bypass_tool", "default_creds_tool", "password_reset_tool"],
        "jwt_attacks":    ["jwt_tool"],
        "report":         ["report_engine"],
    }

    # OWASP Top 10 2021 mapping
    OWASP_TOP10_MAPPING: Dict[str, List[str]] = {
        "crawl":           [],
        "js_analysis":     ["A05:2021-Security Misconfiguration"],
        "waf_detect":      [],
        "api_discovery":   ["A01:2021-Broken Access Control"],
        "proxy_intercept": [],
        "xss":             ["A03:2021-Injection"],
        "sqli":            ["A03:2021-Injection"],
        "ssrf":            ["A10:2021-Server-Side Request Forgery"],
        "csrf":            ["A01:2021-Broken Access Control"],
        "idor":            ["A01:2021-Broken Access Control"],
        "ssti":            ["A03:2021-Injection"],
        "xxe":             ["A05:2021-Security Misconfiguration"],
        "deserialization": ["A08:2021-Software and Data Integrity Failures"],
        "auth_bypass":     ["A07:2021-Identification and Authentication Failures"],
        "jwt_attacks":     ["A02:2021-Cryptographic Failures",
                            "A07:2021-Identification and Authentication Failures"],
        "report":          [],
    }

    # WSTG mapping
    WSTG_MAPPING: Dict[str, List[str]] = {
        "xss":             ["WSTG-INPV-01", "WSTG-CLNT-01", "WSTG-CLNT-02"],
        "sqli":            ["WSTG-INPV-05"],
        "ssrf":            ["WSTG-INPV-19"],
        "csrf":            ["WSTG-SESS-05"],
        "idor":            ["WSTG-ATHZ-01", "WSTG-ATHZ-04"],
        "ssti":            ["WSTG-INPV-18"],
        "xxe":             ["WSTG-INPV-07"],
        "deserialization": ["WSTG-INPV-11"],
        "auth_bypass":     ["WSTG-ATHN-01", "WSTG-ATHN-04", "WSTG-ATHN-09"],
        "jwt_attacks":     ["WSTG-SESS-10"],
    }

    def __init__(
        self,
        target: str,
        *,
        config: Optional[WebAppDeepConfig] = None,
        project_id: Optional[str] = None,
        auto_approve_risk_level: str = "medium",
    ) -> None:
        self.target = target
        self.config = config or WebAppDeepConfig()
        self.project_id = project_id
        self.auto_approve_risk_level = auto_approve_risk_level

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_scan_plan(self) -> Dict[str, Any]:
        """Return orchestrator-compatible scan plan."""
        phases = []
        for phase_id in self.PHASE_ORDER:
            phases.append({
                "phase": phase_id,
                "name": self._phase_name(phase_id),
                "tools": self.PHASE_TOOLS.get(phase_id, []),
                "config": self._phase_config(phase_id),
                "on_failure": "continue",
                "description": self._phase_description(phase_id),
                "estimated_minutes": self._phase_estimate(phase_id),
                "owasp_mapping": self.OWASP_TOP10_MAPPING.get(phase_id, []),
                "wstg_mapping": self.WSTG_MAPPING.get(phase_id, []),
                "skippable": self._phase_skippable(phase_id),
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
            "app_tech": self.config.app_tech.value,
            "auth_type": self.config.auth_type.value,
            "owasp_top10_mapping": self.OWASP_TOP10_MAPPING,
            "wstg_mapping": self.WSTG_MAPPING,
        }

    def get_all_tools(self) -> List[str]:
        """Return deduplicated list of all tools used."""
        tools: List[str] = []
        seen: set = set()
        for tlist in self.PHASE_TOOLS.values():
            for t in tlist:
                if t not in seen:
                    tools.append(t)
                    seen.add(t)
        return tools

    def get_payload_set(self, phase_id: str) -> List[str]:
        """Return representative payloads for a given attack phase."""
        payloads: Dict[str, List[str]] = {
            "xss":             ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>',
                                "<svg/onload=alert(1)>", "javascript:alert(1)"],
            "sqli":            ["' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT NULL--",
                                "1' AND SLEEP(5)--"],
            "ssrf":            ["http://169.254.169.254/latest/meta-data/",
                                "http://localhost/admin", "file:///etc/passwd"],
            "ssti":            ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"],
            "xxe":             ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'],
            "deserialization": ["ysoserial:CommonsCollections1", "phpggc:Laravel/RCE1"],
        }
        return payloads.get(phase_id, [])

    def get_enabled_phases(self) -> List[str]:
        """Return only phases enabled by config."""
        return [p for p in self.PHASE_ORDER if not self._is_phase_disabled(p)]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_phase_disabled(self, phase_id: str) -> bool:
        cfg = self.config
        disabled_map: Dict[str, bool] = {
            "js_analysis":     not (cfg.js_extract_endpoints or cfg.js_dom_sinks),
            "waf_detect":      not cfg.waf_detect,
            "api_discovery":   not cfg.api_discover,
            "proxy_intercept": False,
            "xss":             not cfg.xss_enabled,
            "sqli":            not cfg.sqli_enabled,
            "ssrf":            not cfg.ssrf_enabled,
            "csrf":            not cfg.csrf_enabled,
            "idor":            not cfg.idor_enabled,
            "ssti":            not cfg.ssti_enabled,
            "xxe":             not cfg.xxe_enabled,
            "deserialization": not cfg.deser_enabled,
            "auth_bypass":     not cfg.auth_bypass_enabled,
            "jwt_attacks":     not cfg.jwt_enabled,
            "report":          not cfg.generate_report,
        }
        return disabled_map.get(phase_id, False)

    def _phase_skippable(self, phase_id: str) -> bool:
        non_skippable = {"crawl", "report"}
        return phase_id not in non_skippable

    def _phase_config(self, phase_id: str) -> Dict[str, Any]:
        cfg = self.config
        configs: Dict[str, Dict[str, Any]] = {
            "crawl": {
                "depth": cfg.crawl_depth,
                "scope": cfg.crawl_scope,
                "js_forms": cfg.crawl_js_forms,
                "max_urls": cfg.crawl_max_urls,
            },
            "js_analysis": {
                "extract_endpoints": cfg.js_extract_endpoints,
                "find_secrets": cfg.js_find_secrets,
                "source_map": cfg.js_source_map,
                "dom_sinks": cfg.js_dom_sinks,
            },
            "waf_detect": {
                "bypass": cfg.waf_bypass,
                "bypass_level": cfg.waf_bypass_level,
            },
            "api_discovery": {
                "openapi_url": cfg.openapi_url,
                "graphql": cfg.graphql_endpoint,
                "hidden": cfg.discover_hidden_endpoints,
                "wordlist": cfg.api_wordlist,
            },
            "proxy_intercept": {
                "capture_all": True,
                "log_traffic": True,
                "token": cfg.valid_token,
            },
            "xss": {
                "reflected": cfg.xss_reflected,
                "stored": cfg.xss_stored,
                "dom": cfg.xss_dom,
                "blind": cfg.xss_blind,
                "blind_callback": cfg.blind_xss_callback,
                "payloads": self.get_payload_set("xss"),
            },
            "sqli": {
                "error_based": cfg.sqli_error_based,
                "blind": cfg.sqli_blind,
                "time_based": cfg.sqli_time_based,
                "oob": cfg.sqli_oob,
                "level": cfg.sqli_level,
                "risk": cfg.sqli_risk,
            },
            "ssrf": {
                "blind_oob": cfg.ssrf_blind_oob,
                "cloud_metadata": cfg.ssrf_cloud_metadata,
                "internal": cfg.ssrf_internal_discovery,
            },
            "csrf": {"detect_missing_token": True, "detect_weak_token": True},
            "idor": {
                "max_ids": cfg.idor_max_ids,
                "uuid": cfg.idor_uuid,
                "sequential": True,
            },
            "ssti": {
                "engines": cfg.ssti_engines,
                "payloads": self.get_payload_set("ssti"),
            },
            "xxe": {
                "oob": cfg.xxe_oob,
                "ssrf": cfg.xxe_ssrf,
                "payloads": self.get_payload_set("xxe"),
            },
            "deserialization": {
                "java": cfg.deser_java,
                "php": cfg.deser_php,
                "dotnet": cfg.deser_dotnet,
                "app_tech": cfg.app_tech.value,
            },
            "auth_bypass": {
                "default_creds": cfg.test_default_creds,
                "password_reset": cfg.test_password_reset,
                "account_takeover": cfg.test_account_takeover,
                "auth_type": cfg.auth_type.value,
            },
            "jwt_attacks": {
                "alg_none": cfg.jwt_alg_none,
                "key_confusion": cfg.jwt_key_confusion,
                "weak_secret": cfg.jwt_weak_secret,
                "kid_injection": cfg.jwt_kid_injection,
                "token": cfg.valid_token,
            },
            "report": {
                "format": cfg.report_format,
                "owasp_mapping": cfg.owasp_mapping,
                "wstg_mapping": cfg.wstg_mapping,
                "include_poc": True,
                "include_remediation": True,
            },
        }
        return configs.get(phase_id, {})

    @staticmethod
    def _phase_name(phase_id: str) -> str:
        names = {
            "crawl":          "Web Crawling & Spidering",
            "js_analysis":    "JavaScript Analysis",
            "waf_detect":     "WAF Detection & Bypass",
            "api_discovery":  "API Discovery",
            "proxy_intercept":"HTTP Proxy Intercept Baseline",
            "xss":            "Cross-Site Scripting (XSS)",
            "sqli":           "SQL Injection",
            "ssrf":           "Server-Side Request Forgery (SSRF)",
            "csrf":           "Cross-Site Request Forgery (CSRF)",
            "idor":           "Insecure Direct Object Reference (IDOR)",
            "ssti":           "Server-Side Template Injection (SSTI)",
            "xxe":            "XML External Entity (XXE)",
            "deserialization":"Deserialization Attacks",
            "auth_bypass":    "Authentication Bypass",
            "jwt_attacks":    "JWT Attacks",
            "report":         "Deep Web App Pentest Report",
        }
        return names.get(phase_id, phase_id)

    @staticmethod
    def _phase_description(phase_id: str) -> str:
        descs = {
            "crawl":          "Crawl target application with katana/hakrawler to discover all endpoints and parameters.",
            "js_analysis":    "Extract endpoints, secrets, source maps, and DOM sinks from JavaScript files.",
            "waf_detect":     "Fingerprint WAF and generate bypass payloads for accurate vulnerability scanning.",
            "api_discovery":  "Discover REST/GraphQL endpoints via OpenAPI, introspection, and brute-force.",
            "proxy_intercept":"Capture baseline traffic via proxy to build a comprehensive request inventory.",
            "xss":            "Test for reflected, stored, DOM-based, and blind XSS across all injection points.",
            "sqli":           "Comprehensive SQL injection testing: error-based, blind, time-based, OOB with sqlmap.",
            "ssrf":           "Probe SSRF vectors including blind OOB, cloud metadata, and internal service discovery.",
            "csrf":           "Detect missing or weak CSRF tokens across all state-changing endpoints.",
            "idor":           "Test for IDOR/BOLA with sequential IDs, UUIDs, and parameter pollution.",
            "ssti":           "Detect and exploit server-side template injection across major template engines.",
            "xxe":            "Test XML endpoints for XXE, SSRF-via-XXE, and OOB exfiltration vectors.",
            "deserialization":"Test Java, PHP, and .NET deserialization endpoints with ysoserial/phpggc gadget chains.",
            "auth_bypass":    "Test authentication for default credentials, password reset flaws, and account takeover.",
            "jwt_attacks":    "Test JWT implementation for alg:none, key confusion, weak secrets, and kid injection.",
            "report":         "Generate OWASP Top 10 and WSTG-mapped deep web app pentest report.",
        }
        return descs.get(phase_id, "")

    @staticmethod
    def _phase_estimate(phase_id: str) -> int:
        estimates = {
            "crawl":          15,
            "js_analysis":    10,
            "waf_detect":      5,
            "api_discovery":  15,
            "proxy_intercept": 5,
            "xss":            20,
            "sqli":           25,
            "ssrf":           15,
            "csrf":           10,
            "idor":           15,
            "ssti":           10,
            "xxe":            10,
            "deserialization":15,
            "auth_bypass":    15,
            "jwt_attacks":    10,
            "report":         10,
        }
        return estimates.get(phase_id, 10)
