"""
OWASP Top 10 (2021) control definitions.

Each OwaspControl contains metadata and keyword lists used by the
ComplianceMapper to automatically map pentest findings to the
appropriate OWASP category.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class OwaspControl:
    control_id: str
    title: str
    description: str
    cwe_ids: List[int]
    risk_level: str
    test_techniques: List[str]
    finding_keywords: List[str]


OWASP_TOP10_CONTROLS: Dict[str, OwaspControl] = {
    "A01": OwaspControl(
        control_id="A01",
        title="Broken Access Control",
        description=(
            "Restrictions on what authenticated users are allowed to do are "
            "often not properly enforced. Attackers can exploit these flaws to "
            "access unauthorized functionality and/or data."
        ),
        cwe_ids=[200, 201, 269, 284, 285, 352, 359, 732, 862, 863, 918],
        risk_level="critical",
        test_techniques=[
            "Test horizontal and vertical privilege escalation",
            "Check IDOR vulnerabilities on object references",
            "Verify CORS policy enforcement",
            "Test JWT token manipulation",
            "Check missing function-level access controls",
            "Test CSRF protection",
        ],
        finding_keywords=[
            "access control", "broken access", "privilege escalation",
            "idor", "insecure direct object", "unauthorized access",
            "missing authorization", "horizontal privilege", "vertical privilege",
            "directory traversal", "path traversal", "force browsing",
            "jwt manipulation", "token forgery", "csrf", "cors misconfiguration",
            "object reference", "acl bypass", "permission bypass",
        ],
    ),
    "A02": OwaspControl(
        control_id="A02",
        title="Cryptographic Failures",
        description=(
            "Failures related to cryptography (or lack thereof) which often "
            "lead to exposure of sensitive data or system compromise."
        ),
        cwe_ids=[261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 338],
        risk_level="high",
        test_techniques=[
            "Check for transmission of sensitive data in clear text",
            "Test for weak or deprecated cryptographic algorithms",
            "Verify certificate validation",
            "Check for hard-coded cryptographic keys",
            "Test for insufficient key length",
            "Verify proper use of salted hashes for passwords",
        ],
        finding_keywords=[
            "cryptographic failure", "weak encryption", "weak cipher",
            "plaintext", "clear text", "unencrypted", "ssl", "tls",
            "md5", "sha1", "des", "rc4", "weak hash", "no encryption",
            "certificate", "self-signed", "expired certificate",
            "hard-coded key", "hardcoded secret", "key exposure",
            "sensitive data exposure", "password in plaintext",
        ],
    ),
    "A03": OwaspControl(
        control_id="A03",
        title="Injection",
        description=(
            "Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, "
            "occur when untrusted data is sent to an interpreter as part of "
            "a command or query."
        ),
        cwe_ids=[20, 74, 77, 78, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 116, 943],
        risk_level="critical",
        test_techniques=[
            "Test all input fields for SQL injection",
            "Check for command injection in OS-level operations",
            "Test LDAP injection on directory lookups",
            "Check XML/XPath injection in parsers",
            "Test template injection in server-side rendering",
            "Verify parameterised query usage",
        ],
        finding_keywords=[
            "injection", "sql injection", "sqli", "nosql injection",
            "command injection", "os injection", "ldap injection",
            "xpath injection", "xml injection", "template injection",
            "ssti", "code injection", "remote code execution", "rce",
            "stored procedure injection", "blind sql", "union based",
            "error based injection", "time based blind",
        ],
    ),
    "A04": OwaspControl(
        control_id="A04",
        title="Insecure Design",
        description=(
            "Risks related to design and architectural flaws, with a call for "
            "more use of threat modeling, secure design patterns, and reference "
            "architectures."
        ),
        cwe_ids=[73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 434, 444],
        risk_level="high",
        test_techniques=[
            "Review application architecture for design flaws",
            "Perform threat modeling",
            "Check business logic for abuse cases",
            "Test rate limiting and anti-automation controls",
            "Verify separation of privilege in design",
        ],
        finding_keywords=[
            "insecure design", "design flaw", "architectural flaw",
            "business logic", "logic flaw", "abuse case", "rate limit",
            "no rate limiting", "anti-automation", "workflow bypass",
            "missing validation", "trust boundary", "insecure workflow",
        ],
    ),
    "A05": OwaspControl(
        control_id="A05",
        title="Security Misconfiguration",
        description=(
            "Security misconfiguration is the most commonly seen issue. This "
            "is commonly a result of insecure default configurations, incomplete "
            "or ad hoc configurations, open cloud storage, misconfigured HTTP "
            "headers, or verbose error messages."
        ),
        cwe_ids=[2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 538, 541, 547, 611, 614, 756, 776, 942],
        risk_level="high",
        test_techniques=[
            "Check for default credentials on all services",
            "Review security headers (CSP, HSTS, X-Frame-Options, etc.)",
            "Verify error messages do not leak sensitive info",
            "Check for unnecessary features/services enabled",
            "Test for open cloud storage buckets",
            "Review XML external entity processing",
        ],
        finding_keywords=[
            "misconfiguration", "security misconfiguration", "default credentials",
            "default password", "verbose error", "stack trace", "debug mode",
            "missing security header", "csp", "hsts", "x-frame-options",
            "x-content-type", "open bucket", "s3 bucket", "exposed admin",
            "unnecessary service", "xxe", "xml external entity",
            "directory listing", "exposed configuration",
        ],
    ),
    "A06": OwaspControl(
        control_id="A06",
        title="Vulnerable and Outdated Components",
        description=(
            "Components such as libraries, frameworks, and other software "
            "modules run with the same privileges as the application. If a "
            "vulnerable component is exploited, such an attack can facilitate "
            "serious data loss or server takeover."
        ),
        cwe_ids=[1104],
        risk_level="high",
        test_techniques=[
            "Enumerate all third-party components and their versions",
            "Check CVE databases for known vulnerabilities",
            "Verify patch management processes",
            "Test for exploitation of known CVEs",
            "Check for use of abandoned/unmaintained libraries",
        ],
        finding_keywords=[
            "outdated component", "vulnerable component", "outdated library",
            "known vulnerability", "cve", "patch", "unpatched", "end of life",
            "eol software", "deprecated library", "third-party vulnerability",
            "dependency vulnerability", "supply chain", "npm audit",
            "outdated framework", "old version",
        ],
    ),
    "A07": OwaspControl(
        control_id="A07",
        title="Identification and Authentication Failures",
        description=(
            "Application functions related to authentication and session "
            "management are often implemented incorrectly, allowing attackers "
            "to compromise passwords, keys, or session tokens."
        ),
        cwe_ids=[255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 522, 523, 613, 620, 640, 798, 940, 1216],
        risk_level="critical",
        test_techniques=[
            "Test for weak/default passwords",
            "Check session token entropy and predictability",
            "Verify multi-factor authentication enforcement",
            "Test account lockout mechanism",
            "Check for credential stuffing protection",
            "Test password reset mechanism security",
            "Verify session invalidation on logout",
        ],
        finding_keywords=[
            "authentication failure", "weak password", "default password",
            "credential stuffing", "brute force", "account lockout",
            "session fixation", "session hijacking", "insecure session",
            "missing mfa", "no multi-factor", "weak token", "predictable token",
            "password policy", "broken authentication", "insecure login",
            "password reset", "forgot password", "enumeration",
        ],
    ),
    "A08": OwaspControl(
        control_id="A08",
        title="Software and Data Integrity Failures",
        description=(
            "Software and data integrity failures relate to code and "
            "infrastructure that does not protect against integrity violations. "
            "An example is where an application relies upon plugins, libraries, "
            "or modules from untrusted sources, repositories, and content "
            "delivery networks."
        ),
        cwe_ids=[345, 353, 426, 494, 502, 565, 784, 829, 830],
        risk_level="high",
        test_techniques=[
            "Check for insecure deserialization vulnerabilities",
            "Verify integrity of software update mechanisms",
            "Test CI/CD pipeline security",
            "Check for unsigned code execution",
            "Test for object injection via deserialization",
        ],
        finding_keywords=[
            "deserialization", "insecure deserialization", "object injection",
            "integrity failure", "unsigned code", "untrusted source",
            "supply chain attack", "ci/cd", "pipeline security",
            "update mechanism", "auto-update", "code signing",
            "malicious plugin", "dependency confusion",
        ],
    ),
    "A09": OwaspControl(
        control_id="A09",
        title="Security Logging and Monitoring Failures",
        description=(
            "Insufficient logging and monitoring, coupled with missing or "
            "ineffective integration with incident response, allows attackers "
            "to further attack systems, maintain persistence, pivot to more "
            "systems, and tamper, extract, or destroy data."
        ),
        cwe_ids=[117, 223, 532, 778],
        risk_level="medium",
        test_techniques=[
            "Verify logging of authentication events",
            "Check logging of high-value transactions",
            "Test alerting on suspicious activity",
            "Verify log integrity protection",
            "Check for sensitive data in logs",
            "Review incident response procedures",
        ],
        finding_keywords=[
            "logging failure", "insufficient logging", "missing logging",
            "no audit log", "monitoring failure", "no monitoring",
            "log injection", "sensitive data in log", "missing alerts",
            "no incident response", "audit trail", "log tampering",
            "security event", "failed login not logged",
        ],
    ),
    "A10": OwaspControl(
        control_id="A10",
        title="Server-Side Request Forgery (SSRF)",
        description=(
            "SSRF flaws occur whenever a web application is fetching a remote "
            "resource without validating the user-supplied URL. It allows an "
            "attacker to coerce the application to send a crafted request to "
            "an unexpected destination, even when protected by a firewall, VPN, "
            "or another type of network access control list."
        ),
        cwe_ids=[918],
        risk_level="high",
        test_techniques=[
            "Test URL fetching functionality with internal addresses",
            "Check for SSRF in file import/export features",
            "Test webhook functionality for SSRF",
            "Verify URL allow-listing implementation",
            "Test for blind SSRF via out-of-band channels",
        ],
        finding_keywords=[
            "ssrf", "server-side request forgery", "server side request forgery",
            "internal request", "internal network access", "metadata endpoint",
            "169.254.169.254", "cloud metadata", "internal service access",
            "url fetch", "webhook ssrf", "blind ssrf",
        ],
    ),
}


def map_finding_to_owasp(finding_title: str, finding_description: str) -> List[str]:
    """Return list of applicable OWASP Top 10 control IDs for a finding."""
    combined = (finding_title + " " + finding_description).lower()
    matched: List[str] = []
    for control_id, control in OWASP_TOP10_CONTROLS.items():
        for keyword in control.finding_keywords:
            if keyword in combined:
                matched.append(control_id)
                break
    return matched
