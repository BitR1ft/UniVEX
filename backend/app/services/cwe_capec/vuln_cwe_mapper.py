"""
Vulnerability → CWE Mapper

Extracts and maps CWE identifiers from:
- CVE descriptions (regex patterns for "CWE-NNN" mentions)
- EnrichedCVE.cwe_ids (already populated by NVD)
- Known CVE → CWE mappings from the built-in knowledge base

Then applies them to Finding objects for vulnerability categorisation.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

_CWE_IN_TEXT_RE = re.compile(r"\bCWE-(\d+)\b", re.IGNORECASE)

# Heuristic CVE description → CWE mapping for common vulnerability types
_KEYWORD_TO_CWE: Dict[str, str] = {
    "sql injection": "CWE-89",
    "sqli": "CWE-89",
    "cross-site scripting": "CWE-79",
    "xss": "CWE-79",
    "cross-site request forgery": "CWE-352",
    "csrf": "CWE-352",
    "path traversal": "CWE-22",
    "directory traversal": "CWE-22",
    "command injection": "CWE-78",
    "os command injection": "CWE-78",
    "code injection": "CWE-94",
    "remote code execution": "CWE-94",
    "server-side request forgery": "CWE-918",
    "ssrf": "CWE-918",
    "xml external entity": "CWE-611",
    "xxe": "CWE-611",
    "deserialization": "CWE-502",
    "unsafe deserialization": "CWE-502",
    "authentication bypass": "CWE-287",
    "improper authentication": "CWE-287",
    "information disclosure": "CWE-200",
    "sensitive information": "CWE-200",
    "open redirect": "CWE-601",
    "resource consumption": "CWE-400",
    "denial of service": "CWE-400",
    "input validation": "CWE-20",
}


def extract_cwe_from_text(text: str) -> List[str]:
    """
    Extract CWE identifiers from a free-text description.

    Matches both explicit ``CWE-NNN`` patterns and well-known vulnerability
    keywords (case-insensitive).
    """
    found: Set[str] = set()
    text_lower = text.lower()

    # Explicit CWE patterns
    for m in _CWE_IN_TEXT_RE.finditer(text):
        found.add(f"CWE-{m.group(1)}")

    # Keyword heuristics
    for keyword, cwe_id in _KEYWORD_TO_CWE.items():
        if keyword in text_lower:
            found.add(cwe_id)

    return sorted(found)


def apply_cwe_to_finding(finding: Any, cwe_ids: Optional[List[str]] = None) -> Any:
    """
    Merge *cwe_ids* into a Finding object.

    If *cwe_ids* is ``None``, CWE IDs are inferred from the finding's
    description and name using :func:`extract_cwe_from_text`.

    Returns the mutated finding.
    """
    if cwe_ids is None:
        combined_text = " ".join(filter(None, [finding.name, finding.description or ""]))
        cwe_ids = extract_cwe_from_text(combined_text)

    for cwe in cwe_ids:
        if cwe not in finding.cwe_ids:
            finding.cwe_ids.append(cwe)

    return finding


def categorise_finding_by_cwe(cwe_ids: List[str]) -> Optional[str]:
    """
    Return a high-level vulnerability category for a list of CWE IDs.

    Uses the most specific CWE to drive categorisation.
    """
    _CWE_CATEGORIES: Dict[str, str] = {
        "CWE-89": "Injection",
        "CWE-79": "XSS",
        "CWE-78": "Injection",
        "CWE-94": "Injection",
        "CWE-352": "CSRF",
        "CWE-22": "Path Traversal",
        "CWE-918": "SSRF",
        "CWE-611": "XXE",
        "CWE-502": "Deserialization",
        "CWE-287": "Authentication",
        "CWE-307": "Authentication",
        "CWE-200": "Information Disclosure",
        "CWE-400": "DoS",
        "CWE-20": "Input Validation",
    }
    for cwe in cwe_ids:
        cat = _CWE_CATEGORIES.get(cwe.upper())
        if cat:
            return cat
    return None
