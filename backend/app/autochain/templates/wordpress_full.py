"""
AutoChain v2 — wordpress_full Template

Comprehensive WordPress security assessment chain:
  1. WordPress fingerprinting (version, theme, plugins)
  2. Plugin vulnerability scanning (WPScan)
  3. Theme vulnerability scanning
  4. User enumeration
  5. Authentication testing (XML-RPC, REST API)
  6. File inclusion / path traversal
  7. SQL injection via WordPress inputs
  8. File upload vulnerability testing
  9. PHP code execution / RCE testing
 10. Privilege escalation / configuration review
 11. Report generation
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class WordPressConfig:
    """Configuration for the WordPress pentest template."""
    # Fingerprinting
    detect_plugins: bool = True
    detect_themes: bool = True
    aggressive_detection: bool = False

    # WPScan
    wpscan_api_token: Optional[str] = None
    enumerate_users: bool = True
    enumerate_media: bool = False
    max_users: int = 25

    # Auth
    test_xmlrpc: bool = True
    test_rest_api: bool = True
    brute_force_users: bool = False        # Default off — requires explicit consent
    wordlist: str = "common_passwords"

    # File inclusion
    test_lfi: bool = True
    test_rfi: bool = True
    lfi_depth: int = 8

    # Injection
    test_sqli_forms: bool = True
    test_sqli_rest_api: bool = True

    # File upload
    test_file_upload: bool = True
    upload_extensions: List[str] = field(default_factory=lambda: ["php", "phtml", "php5"])

    # RCE
    test_rce: bool = True
    test_deserialization: bool = True

    # Output
    generate_report: bool = True
    report_format: str = "html"


class WordPressFullTemplate:
    """
    wordpress_full — Comprehensive WordPress security assessment template.

    Covers the most common WordPress attack vectors:
    - Vulnerable plugins / themes (CVE-based)
    - XML-RPC brute force / DDoS amplification
    - REST API information disclosure and auth bypass
    - Local and remote file inclusion
    - SQL injection via shortcodes, forms, and REST endpoints
    - File upload bypass
    - PHP code execution
    - Privilege escalation via WP user roles
    """

    TEMPLATE_ID = "wordpress_full"
    NAME = "WordPress Full Assessment"
    DESCRIPTION = (
        "Comprehensive WordPress security assessment: fingerprinting, "
        "plugin/theme CVE checks, XML-RPC, REST API, LFI/RFI, SQLi, "
        "file upload, RCE, and privilege escalation."
    )
    VERSION = "1.0.0"
    ESTIMATED_DURATION_MINUTES = 90

    PHASE_ORDER: List[str] = [
        "fingerprint",
        "plugin_scan",
        "theme_scan",
        "user_enum",
        "auth_testing",
        "file_inclusion",
        "sqli",
        "file_upload",
        "rce",
        "priv_esc",
        "report",
    ]

    PHASE_TOOLS: Dict[str, List[str]] = {
        "fingerprint": ["wpscan", "httpx", "wappalyzer"],
        "plugin_scan": ["wpscan", "nuclei", "cve_lookup_tool"],
        "theme_scan": ["wpscan", "nuclei"],
        "user_enum": ["wpscan", "wp_user_enum_tool"],
        "auth_testing": ["xmlrpc_tool", "wp_rest_auth_tool", "brute_force_tool"],
        "file_inclusion": ["lfi_detect_tool", "rfi_detect_tool"],
        "sqli": ["sqli_detect_tool", "sqlmap"],
        "file_upload": ["file_upload_tool"],
        "rce": ["rce_detect_tool", "deserialization_tool"],
        "priv_esc": ["wp_role_enum_tool"],
        "report": ["report_engine"],
    }

    # WordPress-specific CVE categories
    COMMON_WP_CVES: List[Dict[str, str]] = [
        {"plugin": "contact-form-7", "type": "arbitrary_file_upload"},
        {"plugin": "woocommerce", "type": "sqli"},
        {"plugin": "yoast-seo", "type": "xss"},
        {"plugin": "elementor", "type": "stored_xss"},
        {"plugin": "wpforms-lite", "type": "csrf"},
        {"plugin": "wordfence", "type": "auth_bypass"},
        {"core": "xmlrpc.php", "type": "brute_force"},
        {"core": "wp-json", "type": "info_disclosure"},
    ]

    def __init__(
        self,
        target: str,
        *,
        config: Optional[WordPressConfig] = None,
        project_id: Optional[str] = None,
        auto_approve_risk_level: str = "medium",
    ) -> None:
        self.target = target
        self.config = config or WordPressConfig()
        self.project_id = project_id
        self.auto_approve_risk_level = auto_approve_risk_level

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
            "wordpress_specific": {
                "common_cves": self.COMMON_WP_CVES,
                "xmlrpc_enabled_check": True,
                "readme_disclosure_check": True,
                "wp_admin_access_check": True,
                "wp_login_protection_check": True,
            },
        }

    def get_all_tools(self) -> List[str]:
        tools: List[str] = []
        seen: set = set()
        for tlist in self.PHASE_TOOLS.values():
            for t in tlist:
                if t not in seen:
                    tools.append(t)
                    seen.add(t)
        return tools

    def get_owasp_coverage(self) -> Dict[str, str]:
        return {
            "A01:2021-Broken Access Control": "priv_esc, auth_testing",
            "A03:2021-Injection": "sqli, file_inclusion",
            "A05:2021-Security Misconfiguration": "fingerprint, plugin_scan",
            "A06:2021-Vulnerable and Outdated Components": "plugin_scan, theme_scan",
            "A07:2021-Identification and Authentication Failures": "auth_testing, user_enum",
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _phase_config(self, phase_id: str) -> Dict[str, Any]:
        cfg = self.config
        configs: Dict[str, Dict[str, Any]] = {
            "fingerprint": {
                "detect_plugins": cfg.detect_plugins,
                "detect_themes": cfg.detect_themes,
                "aggressive": cfg.aggressive_detection,
            },
            "plugin_scan": {
                "api_token": cfg.wpscan_api_token,
                "aggressive": cfg.aggressive_detection,
                "cve_lookup": True,
            },
            "theme_scan": {"api_token": cfg.wpscan_api_token},
            "user_enum": {
                "max_users": cfg.max_users,
                "enumerate_media": cfg.enumerate_media,
            },
            "auth_testing": {
                "xmlrpc": cfg.test_xmlrpc,
                "rest_api": cfg.test_rest_api,
                "brute_force": cfg.brute_force_users,
                "wordlist": cfg.wordlist,
            },
            "file_inclusion": {
                "lfi": cfg.test_lfi,
                "rfi": cfg.test_rfi,
                "depth": cfg.lfi_depth,
            },
            "sqli": {
                "forms": cfg.test_sqli_forms,
                "rest_api": cfg.test_sqli_rest_api,
            },
            "file_upload": {
                "enabled": cfg.test_file_upload,
                "extensions": cfg.upload_extensions,
            },
            "rce": {
                "enabled": cfg.test_rce,
                "deserialization": cfg.test_deserialization,
            },
            "priv_esc": {"role_enum": True},
            "report": {"format": cfg.report_format},
        }
        return configs.get(phase_id, {})

    @staticmethod
    def _phase_name(phase_id: str) -> str:
        names = {
            "fingerprint": "WordPress Fingerprinting",
            "plugin_scan": "Plugin Vulnerability Scan",
            "theme_scan": "Theme Vulnerability Scan",
            "user_enum": "User Enumeration",
            "auth_testing": "Authentication Testing",
            "file_inclusion": "File Inclusion Testing (LFI/RFI)",
            "sqli": "SQL Injection Testing",
            "file_upload": "File Upload Bypass",
            "rce": "Remote Code Execution Testing",
            "priv_esc": "Privilege Escalation",
            "report": "Report Generation",
        }
        return names.get(phase_id, phase_id)

    @staticmethod
    def _phase_description(phase_id: str) -> str:
        descs = {
            "fingerprint": "Detect WP version, installed plugins, active theme, configuration leaks.",
            "plugin_scan": "Cross-reference installed plugins with WPScan vulnerability DB and CVE/NVD.",
            "theme_scan": "Cross-reference active theme with known CVEs and common theme vulnerabilities.",
            "user_enum": "Enumerate WP users via author archive, REST API /wp-json/wp/v2/users.",
            "auth_testing": "Test XML-RPC multicall brute force, REST API auth bypass, login protection.",
            "file_inclusion": "Test LFI/RFI via plugin/theme parameters, wp-load.php includes.",
            "sqli": "Test SQL injection in WP forms, search, comments, and REST API endpoints.",
            "file_upload": "Test file upload bypass via MIME spoofing, extension tricks, .htaccess upload.",
            "rce": "Test PHP code execution via eval injection, serialised object injection.",
            "priv_esc": "Test WP user role escalation: subscriber → author → admin paths.",
            "report": "Produce detailed WordPress security assessment report with remediation.",
        }
        return descs.get(phase_id, "")

    @staticmethod
    def _phase_estimate(phase_id: str) -> int:
        estimates = {
            "fingerprint": 5,
            "plugin_scan": 15,
            "theme_scan": 5,
            "user_enum": 5,
            "auth_testing": 10,
            "file_inclusion": 10,
            "sqli": 10,
            "file_upload": 5,
            "rce": 10,
            "priv_esc": 5,
            "report": 5,
        }
        return estimates.get(phase_id, 5)
