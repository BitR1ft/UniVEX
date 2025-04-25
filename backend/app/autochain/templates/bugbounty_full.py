"""
AutoChain v3 — bugbounty_full Template

Complete bug bounty hunting workflow:
  1.  Subdomain enumeration (amass, subfinder, assetfinder, dnsx)
  2.  Subdomain takeover detection (CNAME dangling, service fingerprinting)
  3.  Historical URL mining (Wayback Machine, GAU, Common Crawl)
  4.  JavaScript analysis (endpoint extraction, secret finding, DOM sinks)
  5.  WAF detection & bypass fingerprinting
  6.  Port scanning (naabu — top-1000 + common web)
  7.  HTTP probing & technology detection (httpx, wappalyzer)
  8.  Content discovery (ffuf, gobuster — wordlist-based)
  9.  Nuclei vulnerability scan (CVE, misconfig, default-creds, exposed-panels)
 10.  XSS detection (dalfox, XSStrike)
 11.  SQL injection detection (sqlmap)
 12.  SSRF probing (blind + direct)
 13.  IDOR / BOLA testing
 14.  Open redirect detection
 15.  Report generation (CVSS-scored, Markdown + HTML)

Designed for high-volume bug bounty programs.  All phases are skippable
via the BugBountyConfig dataclass.
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

class BugBountyScope(str, Enum):
    """Scope definition for the bug bounty target."""
    WILDCARD = "wildcard"      # *.example.com — full subdomain enumeration
    SINGLE = "single"          # single domain / host
    IP_RANGE = "ip_range"      # CIDR range (rare in BB, but supported)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class BugBountyConfig:
    """Configuration for the bugbounty_full template."""

    # ── Scope ──────────────────────────────────────────────────────────────
    scope: BugBountyScope = BugBountyScope.WILDCARD
    excluded_subdomains: List[str] = field(default_factory=list)
    rate_limit_rps: int = 150           # requests per second across tools

    # ── Subdomain enumeration ──────────────────────────────────────────────
    subdomain_brute: bool = True
    subdomain_wordlist: str = "subdomains-top1million-110000"
    subdomain_permutation: bool = True   # dnsx permutation
    resolve_dns: bool = True

    # ── Takeover detection ─────────────────────────────────────────────────
    check_subdomain_takeover: bool = True
    check_dangling_cname: bool = True

    # ── Historical URLs ────────────────────────────────────────────────────
    wayback_enabled: bool = True
    gau_enabled: bool = True
    common_crawl_enabled: bool = True
    max_historical_urls: int = 50_000

    # ── JavaScript analysis ────────────────────────────────────────────────
    js_endpoint_extract: bool = True
    js_secret_finder: bool = True
    js_source_map: bool = True
    js_dom_sink_analysis: bool = True

    # ── WAF ────────────────────────────────────────────────────────────────
    waf_detect: bool = True
    waf_bypass_attempt: bool = True

    # ── Port scanning ──────────────────────────────────────────────────────
    port_scan_enabled: bool = True
    port_scan_top_n: int = 1000
    port_scan_extra_ports: List[int] = field(
        default_factory=lambda: [8080, 8443, 8888, 9090, 3000, 4000, 5000]
    )

    # ── HTTP probe ─────────────────────────────────────────────────────────
    http_probe_enabled: bool = True
    tech_detect: bool = True

    # ── Content discovery ─────────────────────────────────────────────────
    content_discovery_enabled: bool = True
    content_wordlist: str = "directory-list-2.3-medium"
    content_extensions: List[str] = field(
        default_factory=lambda: ["php", "asp", "aspx", "jsp", "json", "xml", "bak", "old", "txt"]
    )

    # ── Nuclei ─────────────────────────────────────────────────────────────
    nuclei_enabled: bool = True
    nuclei_severity: List[str] = field(
        default_factory=lambda: ["critical", "high", "medium"]
    )
    nuclei_templates: List[str] = field(
        default_factory=lambda: [
            "cves", "vulnerabilities", "misconfiguration",
            "default-logins", "exposed-panels", "takeovers",
            "technologies",
        ]
    )

    # ── Injection & Logic ──────────────────────────────────────────────────
    xss_enabled: bool = True
    sqli_enabled: bool = True
    ssrf_enabled: bool = True
    idor_enabled: bool = True
    open_redirect_enabled: bool = True

    # ── Output ─────────────────────────────────────────────────────────────
    generate_report: bool = True
    report_format: str = "html"
    min_severity_report: str = "low"    # include findings >= this severity


# ---------------------------------------------------------------------------
# Template
# ---------------------------------------------------------------------------

class BugBountyFullTemplate:
    """
    bugbounty_full — Complete bug bounty hunting AutoChain v3 template.

    Covers the entire modern bug bounty methodology from passive recon
    through active exploitation and report generation.  Suitable for:
    - HackerOne / Bugcrowd programs
    - Private VDPs (Vulnerability Disclosure Programmes)
    - Self-hosted programs (Intigriti, YesWeHack)
    """

    TEMPLATE_ID = "bugbounty_full"
    NAME = "Bug Bounty Full Chain"
    DESCRIPTION = (
        "End-to-end bug bounty hunting: subdomain enumeration, takeover "
        "detection, historical URL mining, JS analysis, WAF fingerprinting, "
        "port scan, Nuclei, XSS/SQLi/SSRF/IDOR, and report generation."
    )
    VERSION = "3.0.0"
    ESTIMATED_DURATION_MINUTES = 180

    PHASE_ORDER: List[str] = [
        "subdomain_enum",
        "subdomain_takeover",
        "historical_urls",
        "js_analysis",
        "waf_detect",
        "port_scan",
        "http_probe",
        "content_discovery",
        "nuclei_scan",
        "xss",
        "sqli",
        "ssrf",
        "idor",
        "open_redirect",
        "report",
    ]

    PHASE_TOOLS: Dict[str, List[str]] = {
        "subdomain_enum":      ["amass", "subfinder", "assetfinder", "dnsx", "massdns"],
        "subdomain_takeover":  ["subjack", "nuclei", "subdomain_takeover_tool", "dangling_cname_tool"],
        "historical_urls":     ["wayback_urls_tool", "gau_tool", "common_crawl_tool"],
        "js_analysis":         ["js_endpoint_extract_tool", "js_secret_finder_tool",
                                "source_map_analyze_tool", "dom_sink_analyzer_tool"],
        "waf_detect":          ["waf_detect_tool", "waf_fingerprint_tool"],
        "port_scan":           ["naabu", "masscan"],
        "http_probe":          ["httpx", "wappalyzer"],
        "content_discovery":   ["ffuf", "gobuster", "feroxbuster"],
        "nuclei_scan":         ["nuclei"],
        "xss":                 ["dalfox", "xsstrike"],
        "sqli":                ["sqlmap"],
        "ssrf":                ["ssrf_probe_tool", "ssrf_blind_tool"],
        "idor":                ["idor_test_tool", "bola_test_tool"],
        "open_redirect":       ["open_redirect_tool"],
        "report":              ["report_engine"],
    }

    # Severity CVSS mapping used by report engine
    SEVERITY_CVSS: Dict[str, str] = {
        "critical": "9.0-10.0",
        "high":     "7.0-8.9",
        "medium":   "4.0-6.9",
        "low":      "1.0-3.9",
        "info":     "0.0",
    }

    # Common bug bounty out-of-scope patterns
    OUT_OF_SCOPE_PATTERNS: List[str] = [
        "*.internal.*",
        "localhost",
        "127.0.0.1",
        "::1",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ]

    def __init__(
        self,
        target: str,
        *,
        config: Optional[BugBountyConfig] = None,
        project_id: Optional[str] = None,
        auto_approve_risk_level: str = "medium",
    ) -> None:
        self.target = target
        self.config = config or BugBountyConfig()
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
            "scope": self.config.scope.value,
            "excluded_subdomains": self.config.excluded_subdomains,
            "severity_cvss": self.SEVERITY_CVSS,
            "out_of_scope_patterns": self.OUT_OF_SCOPE_PATTERNS,
            "rate_limit_rps": self.config.rate_limit_rps,
        }

    def get_all_tools(self) -> List[str]:
        """Return deduplicated list of all tools used across all phases."""
        tools: List[str] = []
        seen: set = set()
        for tlist in self.PHASE_TOOLS.values():
            for t in tlist:
                if t not in seen:
                    tools.append(t)
                    seen.add(t)
        return tools

    def get_nuclei_command(self) -> Dict[str, Any]:
        """Build nuclei invocation parameters."""
        return {
            "targets": [self.target],
            "templates": self.config.nuclei_templates,
            "severity": self.config.nuclei_severity,
            "rate_limit": self.config.rate_limit_rps,
            "output_format": "json",
        }

    def get_enabled_phases(self) -> List[str]:
        """Return only phases that are enabled by current config."""
        enabled = []
        for phase_id in self.PHASE_ORDER:
            if not self._is_phase_disabled(phase_id):
                enabled.append(phase_id)
        return enabled

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_phase_disabled(self, phase_id: str) -> bool:
        cfg = self.config
        disabled_map: Dict[str, bool] = {
            "subdomain_takeover":  not cfg.check_subdomain_takeover,
            "historical_urls":     not (cfg.wayback_enabled or cfg.gau_enabled or cfg.common_crawl_enabled),
            "js_analysis":         not (cfg.js_endpoint_extract or cfg.js_secret_finder),
            "waf_detect":          not cfg.waf_detect,
            "port_scan":           not cfg.port_scan_enabled,
            "http_probe":          not cfg.http_probe_enabled,
            "content_discovery":   not cfg.content_discovery_enabled,
            "nuclei_scan":         not cfg.nuclei_enabled,
            "xss":                 not cfg.xss_enabled,
            "sqli":                not cfg.sqli_enabled,
            "ssrf":                not cfg.ssrf_enabled,
            "idor":                not cfg.idor_enabled,
            "open_redirect":       not cfg.open_redirect_enabled,
            "report":              not cfg.generate_report,
        }
        return disabled_map.get(phase_id, False)

    def _phase_skippable(self, phase_id: str) -> bool:
        non_skippable = {"subdomain_enum", "http_probe", "report"}
        return phase_id not in non_skippable

    def _phase_config(self, phase_id: str) -> Dict[str, Any]:
        cfg = self.config
        configs: Dict[str, Dict[str, Any]] = {
            "subdomain_enum": {
                "scope": cfg.scope.value,
                "brute": cfg.subdomain_brute,
                "wordlist": cfg.subdomain_wordlist,
                "permutation": cfg.subdomain_permutation,
                "resolve_dns": cfg.resolve_dns,
                "excluded": cfg.excluded_subdomains,
            },
            "subdomain_takeover": {
                "check_takeover": cfg.check_subdomain_takeover,
                "check_dangling_cname": cfg.check_dangling_cname,
            },
            "historical_urls": {
                "wayback": cfg.wayback_enabled,
                "gau": cfg.gau_enabled,
                "common_crawl": cfg.common_crawl_enabled,
                "max_urls": cfg.max_historical_urls,
            },
            "js_analysis": {
                "extract_endpoints": cfg.js_endpoint_extract,
                "find_secrets": cfg.js_secret_finder,
                "source_map": cfg.js_source_map,
                "dom_sinks": cfg.js_dom_sink_analysis,
            },
            "waf_detect": {
                "fingerprint": cfg.waf_detect,
                "bypass_attempt": cfg.waf_bypass_attempt,
            },
            "port_scan": {
                "top_n": cfg.port_scan_top_n,
                "extra_ports": cfg.port_scan_extra_ports,
                "rate": cfg.rate_limit_rps,
            },
            "http_probe": {
                "tech_detect": cfg.tech_detect,
                "follow_redirects": True,
                "status_codes": [200, 301, 302, 401, 403, 500],
            },
            "content_discovery": {
                "wordlist": cfg.content_wordlist,
                "extensions": cfg.content_extensions,
                "threads": 50,
                "rate": cfg.rate_limit_rps,
            },
            "nuclei_scan": self.get_nuclei_command(),
            "xss": {"tool": "dalfox", "blind_xss": True, "dom_based": True},
            "sqli": {"tool": "sqlmap", "level": 3, "risk": 2, "forms": True},
            "ssrf": {"blind_oob": True, "cloud_metadata": True},
            "idor": {"id_range": 100, "test_uuid": True, "test_sequential": True},
            "open_redirect": {"payloads": ["//evil.com", "https://evil.com"], "follow": False},
            "report": {
                "format": cfg.report_format,
                "min_severity": cfg.min_severity_report,
                "include_poc": True,
                "include_remediation": True,
                "cvss_scoring": True,
            },
        }
        return configs.get(phase_id, {})

    @staticmethod
    def _phase_name(phase_id: str) -> str:
        names = {
            "subdomain_enum":     "Subdomain Enumeration",
            "subdomain_takeover": "Subdomain Takeover Detection",
            "historical_urls":    "Historical URL Mining",
            "js_analysis":        "JavaScript Analysis",
            "waf_detect":         "WAF Detection & Fingerprinting",
            "port_scan":          "Port Scanning",
            "http_probe":         "HTTP Probing & Tech Detection",
            "content_discovery":  "Content Discovery",
            "nuclei_scan":        "Nuclei Vulnerability Scan",
            "xss":                "XSS Detection",
            "sqli":               "SQL Injection Detection",
            "ssrf":               "SSRF Probing",
            "idor":               "IDOR / BOLA Testing",
            "open_redirect":      "Open Redirect Detection",
            "report":             "Bug Bounty Report",
        }
        return names.get(phase_id, phase_id)

    @staticmethod
    def _phase_description(phase_id: str) -> str:
        descs = {
            "subdomain_enum":     "Enumerate subdomains via passive (APIs) + active (brute-force/permutation) sources.",
            "subdomain_takeover": "Detect dangling CNAMEs and unclaimed cloud/SaaS service endpoints.",
            "historical_urls":    "Mine Wayback Machine, GAU, and Common Crawl for historical endpoints and parameters.",
            "js_analysis":        "Extract endpoints, secrets, source maps, and DOM sink vulnerabilities from JS files.",
            "waf_detect":         "Fingerprint WAF vendor and bypass rules to ensure scan accuracy.",
            "port_scan":          "Fast port scan with naabu/masscan to discover non-standard web services.",
            "http_probe":         "HTTP probe all hosts with httpx; detect technologies, response codes, titles.",
            "content_discovery":  "Directory and file brute-force with ffuf/feroxbuster across all live hosts.",
            "nuclei_scan":        "Template-based vulnerability scanning: CVEs, misconfigs, exposed panels.",
            "xss":                "Cross-site scripting detection with dalfox (DOM, reflected, blind XSS).",
            "sqli":               "SQL injection detection with sqlmap across all discovered forms and params.",
            "ssrf":               "Server-side request forgery probing — blind OOB and cloud metadata targets.",
            "idor":               "Insecure Direct Object Reference / BOLA testing with sequential and UUID IDs.",
            "open_redirect":      "Open redirect detection across all URL parameters.",
            "report":             "Generate CVSS-scored bug bounty report with PoC and remediation guidance.",
        }
        return descs.get(phase_id, "")

    @staticmethod
    def _phase_estimate(phase_id: str) -> int:
        estimates = {
            "subdomain_enum":     20,
            "subdomain_takeover": 10,
            "historical_urls":    15,
            "js_analysis":        10,
            "waf_detect":          5,
            "port_scan":          15,
            "http_probe":          5,
            "content_discovery":  20,
            "nuclei_scan":        30,
            "xss":                15,
            "sqli":               15,
            "ssrf":               10,
            "idor":                5,
            "open_redirect":       5,
            "report":              5,
        }
        return estimates.get(phase_id, 5)
