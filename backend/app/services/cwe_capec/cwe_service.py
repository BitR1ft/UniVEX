"""
CWE Database Service

Provides an in-memory CWE lookup service populated from the MITRE CWE XML
database or a built-in minimal offline dataset (fallback).

The XML format used is the official MITRE CWE List XML:
    https://cwe.mitre.org/data/xml/cwec_latest.xml.zip

Usage::

    svc = CWEService()
    await svc.load()           # parse XML or use built-in fallback

    entry = svc.lookup("CWE-79")
    # CWEEntry(id="CWE-79", name="Improper Neutralization of Input …", ...)
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)

_CWE_NS = "http://cwe.mitre.org/cwe-6"
_CWE_ID_RE = re.compile(r"^(?:CWE-)?(\d+)$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class CWEEntry:
    """A single CWE entry from the MITRE CWE database."""
    id: str                            # e.g. "CWE-79"
    name: str
    description: Optional[str] = None
    extended_description: Optional[str] = None
    abstraction: Optional[str] = None  # Base, Class, Variant, Compound, Pillar
    structure: Optional[str] = None    # Simple, Chain, Composite
    status: Optional[str] = None       # Draft, Incomplete, Stable, Obsolete, Deprecated
    likelihood: Optional[str] = None   # Low, Medium, High
    related_cwe_ids: List[str] = field(default_factory=list)
    capec_ids: List[str] = field(default_factory=list)
    cve_examples: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Minimal offline CWE dataset (fallback when no XML available)
# ---------------------------------------------------------------------------

_BUILTIN_CWES: Dict[str, CWEEntry] = {
    "CWE-20": CWEEntry("CWE-20", "Improper Input Validation", "The product does not validate or incorrectly validates input that can affect the control flow or data flow of a program."),
    "CWE-22": CWEEntry("CWE-22", "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", "The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory."),
    "CWE-78": CWEEntry("CWE-78", "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", "The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component."),
    "CWE-79": CWEEntry("CWE-79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.", capec_ids=["CAPEC-86", "CAPEC-198"]),
    "CWE-89": CWEEntry("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.", capec_ids=["CAPEC-66", "CAPEC-7"]),
    "CWE-94": CWEEntry("CWE-94", "Improper Control of Generation of Code ('Code Injection')", "The software constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.", capec_ids=["CAPEC-242"]),
    "CWE-200": CWEEntry("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor", "The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information."),
    "CWE-287": CWEEntry("CWE-287", "Improper Authentication", "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct."),
    "CWE-307": CWEEntry("CWE-307", "Improper Restriction of Excessive Authentication Attempts", "The software does not implement sufficient measures to prevent multiple failed authentication attempts within a short time frame."),
    "CWE-352": CWEEntry("CWE-352", "Cross-Site Request Forgery (CSRF)", "The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.", capec_ids=["CAPEC-62"]),
    "CWE-400": CWEEntry("CWE-400", "Uncontrolled Resource Consumption", "The software does not properly control the allocation and maintenance of a limited resource, thereby enabling an actor to influence the amount of resources consumed."),
    "CWE-502": CWEEntry("CWE-502", "Deserialization of Untrusted Data", "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid."),
    "CWE-611": CWEEntry("CWE-611", "Improper Restriction of XML External Entity Reference", "The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control."),
    "CWE-918": CWEEntry("CWE-918", "Server-Side Request Forgery (SSRF)", "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.", capec_ids=["CAPEC-664"]),
}


# ---------------------------------------------------------------------------
# CWEService
# ---------------------------------------------------------------------------

class CWEService:
    """
    In-memory CWE lookup service.

    Loads data from an XML file (if provided) and falls back to the
    built-in minimal dataset.
    """

    def __init__(self, xml_path: Optional[str] = None) -> None:
        self._xml_path = xml_path
        self._db: Dict[str, CWEEntry] = {}

    async def load(self) -> None:
        """Load CWE data from XML or fall back to built-in dataset."""
        if self._xml_path and Path(self._xml_path).exists():
            try:
                self._db = _parse_cwe_xml(self._xml_path)
                logger.info("CWE: loaded %d entries from %s", len(self._db), self._xml_path)
                return
            except Exception as exc:
                logger.warning("CWE XML parse failed (%s), using built-in dataset", exc)

        self._db = dict(_BUILTIN_CWES)
        logger.info("CWE: loaded %d built-in entries", len(self._db))

    def lookup(self, cwe_ref: str) -> Optional[CWEEntry]:
        """
        Look up a CWE by ID string.

        Accepts ``"CWE-79"``, ``"79"``, or ``"cwe-79"`` (case-insensitive).
        """
        m = _CWE_ID_RE.match(cwe_ref.strip())
        if not m:
            return None
        key = f"CWE-{m.group(1)}"
        return self._db.get(key)

    def all(self) -> List[CWEEntry]:
        return list(self._db.values())

    def count(self) -> int:
        return len(self._db)

    def is_loaded(self) -> bool:
        return bool(self._db)


# ---------------------------------------------------------------------------
# XML parser
# ---------------------------------------------------------------------------

def _parse_cwe_xml(path: str) -> Dict[str, CWEEntry]:
    """Parse the official MITRE CWE XML and return a CWEEntry dict."""
    tree = ET.parse(path)
    root = tree.getroot()
    ns = {"cwe": _CWE_NS}
    entries: Dict[str, CWEEntry] = {}

    weaknesses = root.find("cwe:Weaknesses", ns) or root

    for weakness in weaknesses.findall(".//cwe:Weakness", ns) or root.findall(".//Weakness"):
        cwe_id = f"CWE-{weakness.get('ID', '')}"
        name = weakness.get("Name", "")
        abstraction = weakness.get("Abstraction")
        structure = weakness.get("Structure")
        status = weakness.get("Status")

        desc_el = weakness.find("cwe:Description", ns) or weakness.find("Description")
        description = (desc_el.text or "").strip() if desc_el is not None else None

        ext_el = weakness.find("cwe:Extended_Description", ns) or weakness.find("Extended_Description")
        extended = (ext_el.text or "").strip() if ext_el is not None else None

        # Related CWEs
        related_ids: List[str] = []
        for rel in (weakness.findall(".//cwe:Related_Weakness", ns) or weakness.findall(".//Related_Weakness")):
            rid = rel.get("CWE_ID")
            if rid:
                related_ids.append(f"CWE-{rid}")

        # CAPEC IDs
        capec_ids: List[str] = []
        for ta in (weakness.findall(".//cwe:Tax_Map", ns) or weakness.findall(".//Tax_Map")):
            if ta.get("Taxonomy_Name") == "CAPEC":
                entry_id = ta.get("Entry_ID")
                if entry_id:
                    capec_ids.append(f"CAPEC-{entry_id}")

        entries[cwe_id] = CWEEntry(
            id=cwe_id,
            name=name,
            description=description,
            extended_description=extended,
            abstraction=abstraction,
            structure=structure,
            status=status,
            related_cwe_ids=related_ids,
            capec_ids=capec_ids,
        )

    return entries
