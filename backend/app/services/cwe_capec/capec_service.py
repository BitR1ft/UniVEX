"""
CAPEC Database Service

Provides an in-memory CAPEC lookup service populated from the MITRE CAPEC XML
database or a built-in minimal offline dataset (fallback).

Official source:
    https://capec.mitre.org/data/xml/capec_latest.xml

Usage::

    svc = CAPECService()
    await svc.load()           # parse XML or use built-in fallback

    entry = svc.lookup("CAPEC-66")
    # CAPECEntry(id="CAPEC-66", name="SQL Injection", ...)
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)

_CAPEC_NS = "http://capec.mitre.org/capec-3"
_CAPEC_ID_RE = re.compile(r"^(?:CAPEC-)?(\d+)$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class CAPECEntry:
    """A single CAPEC attack pattern entry."""
    id: str                            # e.g. "CAPEC-66"
    name: str
    description: Optional[str] = None
    abstraction: Optional[str] = None  # Meta, Standard, Detailed
    status: Optional[str] = None
    likelihood: Optional[str] = None   # Low, Medium, High
    severity: Optional[str] = None     # Low, Medium, High, Very High
    related_cwe_ids: List[str] = field(default_factory=list)
    related_capec_ids: List[str] = field(default_factory=list)
    attack_steps: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Minimal offline CAPEC dataset (fallback)
# ---------------------------------------------------------------------------

_BUILTIN_CAPECS: Dict[str, CAPECEntry] = {
    "CAPEC-7": CAPECEntry("CAPEC-7", "Blind SQL Injection", "Blind SQL Injection results from an insufficient mitigation for SQL Injection. Although suppressed, the database still executes the SQL query.", related_cwe_ids=["CWE-89"], severity="High"),
    "CAPEC-62": CAPECEntry("CAPEC-62", "Cross-Site Request Forgery", "An attacker crafts malicious web links and distributes them (via web pages, email, etc.), typically in a targeted manner, hoping to induce users to click on the link and execute the malicious action against some third-party application.", related_cwe_ids=["CWE-352"], severity="High"),
    "CAPEC-66": CAPECEntry("CAPEC-66", "SQL Injection", "This attack exploits target software that constructs SQL statements based on user input.", related_cwe_ids=["CWE-89"], severity="High"),
    "CAPEC-86": CAPECEntry("CAPEC-86", "XSS Through HTTP Request Headers", "An adversary crafts malicious content in HTTP request headers, which is then reflected in a server response, leading to XSS.", related_cwe_ids=["CWE-79"], severity="High"),
    "CAPEC-198": CAPECEntry("CAPEC-198", "XSS Targeting HTML Attributes", "An adversary injects script into an HTML attribute, allowing execution of script code.", related_cwe_ids=["CWE-79"], severity="Medium"),
    "CAPEC-242": CAPECEntry("CAPEC-242", "Code Injection", "An adversary exploits a weakness in input validation on the target to inject new code into that which is currently executing in the application.", related_cwe_ids=["CWE-94"], severity="High"),
    "CAPEC-664": CAPECEntry("CAPEC-664", "Server-Side Request Forgery", "An adversary is able to induce an application to make an arbitrary request to a third-party system.", related_cwe_ids=["CWE-918"], severity="High"),
    "CAPEC-17": CAPECEntry("CAPEC-17", "Using Malicious Files", "An attack of this type exploits a system's trust in configuration and resource files.", severity="Medium"),
    "CAPEC-1": CAPECEntry("CAPEC-1", "Accessing Functionality Not Properly Constrained by ACLs", "In applications, particularly web applications, access to functionality is mitigated by an authorization framework.", severity="High"),
    "CAPEC-115": CAPECEntry("CAPEC-115", "Authentication Bypass", "An attacker gains access to application, service, or device with the privileges of an authorized or privileged user by evading or circumventing an authentication mechanism.", related_cwe_ids=["CWE-287"], severity="High"),
}


# ---------------------------------------------------------------------------
# CAPECService
# ---------------------------------------------------------------------------

class CAPECService:
    """
    In-memory CAPEC attack pattern lookup service.

    Loads data from an XML file (if provided) and falls back to the
    built-in minimal dataset.
    """

    def __init__(self, xml_path: Optional[str] = None) -> None:
        self._xml_path = xml_path
        self._db: Dict[str, CAPECEntry] = {}

    async def load(self) -> None:
        """Load CAPEC data from XML or fall back to built-in dataset."""
        if self._xml_path and Path(self._xml_path).exists():
            try:
                self._db = _parse_capec_xml(self._xml_path)
                logger.info("CAPEC: loaded %d entries from %s", len(self._db), self._xml_path)
                return
            except Exception as exc:
                logger.warning("CAPEC XML parse failed (%s), using built-in dataset", exc)

        self._db = dict(_BUILTIN_CAPECS)
        logger.info("CAPEC: loaded %d built-in entries", len(self._db))

    def lookup(self, capec_ref: str) -> Optional[CAPECEntry]:
        """
        Look up a CAPEC entry by ID.

        Accepts ``"CAPEC-66"``, ``"66"``, or ``"capec-66"`` (case-insensitive).
        """
        m = _CAPEC_ID_RE.match(capec_ref.strip())
        if not m:
            return None
        key = f"CAPEC-{m.group(1)}"
        return self._db.get(key)

    def all(self) -> List[CAPECEntry]:
        return list(self._db.values())

    def count(self) -> int:
        return len(self._db)

    def is_loaded(self) -> bool:
        return bool(self._db)

    def by_cwe(self, cwe_id: str) -> List[CAPECEntry]:
        """Return all CAPEC entries related to a given CWE ID."""
        normalised = cwe_id.upper().strip()
        if not normalised.startswith("CWE-"):
            normalised = f"CWE-{normalised}"
        return [e for e in self._db.values() if normalised in e.related_cwe_ids]


# ---------------------------------------------------------------------------
# XML parser
# ---------------------------------------------------------------------------

def _parse_capec_xml(path: str) -> Dict[str, CAPECEntry]:
    """Parse the official MITRE CAPEC XML and return a CAPECEntry dict."""
    tree = ET.parse(path)
    root = tree.getroot()
    ns = {"capec": _CAPEC_NS}
    entries: Dict[str, CAPECEntry] = {}

    patterns = root.find("capec:Attack_Patterns", ns) or root

    for pattern in patterns.findall(".//capec:Attack_Pattern", ns) or root.findall(".//Attack_Pattern"):
        capec_id = f"CAPEC-{pattern.get('ID', '')}"
        name = pattern.get("Name", "")
        abstraction = pattern.get("Abstraction")
        status = pattern.get("Status")
        likelihood = pattern.get("Likelihood_Of_Attack")
        severity = pattern.get("Typical_Severity")

        desc_el = (
            pattern.find("capec:Description", ns)
            or pattern.find("Description")
        )
        description = (desc_el.text or "").strip() if desc_el is not None else None

        # Related CWEs
        related_cwe: List[str] = []
        for rel in (pattern.findall(".//capec:Related_Weakness", ns) or pattern.findall(".//Related_Weakness")):
            cwe_num = rel.get("CWE_ID")
            if cwe_num:
                related_cwe.append(f"CWE-{cwe_num}")

        # Related CAPEC IDs
        related_capec: List[str] = []
        for rel in (pattern.findall(".//capec:Related_Attack_Pattern", ns) or pattern.findall(".//Related_Attack_Pattern")):
            capec_num = rel.get("CAPEC_ID")
            if capec_num:
                related_capec.append(f"CAPEC-{capec_num}")

        entries[capec_id] = CAPECEntry(
            id=capec_id,
            name=name,
            description=description,
            abstraction=abstraction,
            status=status,
            likelihood=likelihood,
            severity=severity,
            related_cwe_ids=related_cwe,
            related_capec_ids=related_capec,
        )

    return entries
