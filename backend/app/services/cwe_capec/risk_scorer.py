"""
Risk Scoring Implementation

Combines CVSS base score, exploit availability, and exposure context into
a single normalised risk score (0.0–10.0) for vulnerability findings.

Algorithm
---------

    risk_score = base_score × exploit_multiplier × exposure_multiplier

Where:
    base_score          = CVSS v3 base score (0–10), defaulting to severity mapping
    exploit_multiplier  = 1.0 (no exploit) → 1.4 (weaponised exploit)
    exposure_multiplier = 0.8 (internal only) → 1.2 (internet-facing)

The final score is capped at 10.0 and normalised to one decimal place.

Severity Normalisation
----------------------
Tool-specific severity strings are mapped to :class:`~app.recon.canonical_schemas.Severity`
using :func:`normalise_severity`.

Risk Prioritisation
-------------------
:func:`prioritise_findings` sorts a list of findings by descending risk score
and optionally annotates each with its priority rank and risk score.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.recon.canonical_schemas import Severity


# ---------------------------------------------------------------------------
# Exploit multiplier map
# ---------------------------------------------------------------------------

_EXPLOIT_MULTIPLIER: Dict[Optional[str], float] = {
    None: 1.0,
    "": 1.0,
    "proof-of-concept": 1.2,
    "functional": 1.3,
    "weaponised": 1.4,
}

# ---------------------------------------------------------------------------
# Exposure multiplier map
# ---------------------------------------------------------------------------

_EXPOSURE_MULTIPLIER: Dict[str, float] = {
    "internal": 0.8,
    "intranet": 0.85,
    "vpn": 0.9,
    "staging": 0.95,
    "internet": 1.1,
    "external": 1.1,
    "cloud": 1.2,
    "unknown": 1.0,
}

# ---------------------------------------------------------------------------
# CVSS-less severity → base score fallback
# ---------------------------------------------------------------------------

_SEVERITY_BASE_SCORE: Dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
    "unknown": 1.0,
}


# ---------------------------------------------------------------------------
# Core scoring function
# ---------------------------------------------------------------------------

def compute_risk_score(
    cvss_score: Optional[float],
    severity: str = "unknown",
    exploit_maturity: Optional[str] = None,
    exposure: str = "unknown",
) -> float:
    """
    Compute a risk score between 0.0 and 10.0.

    Args:
        cvss_score:      CVSS v3 base score, or ``None`` to fall back to severity.
        severity:        Severity label (``"critical"``, ``"high"``, …).
        exploit_maturity: Exploit availability: ``None``, ``"proof-of-concept"``,
                          ``"functional"``, or ``"weaponised"``.
        exposure:        Target exposure context: ``"internet"``, ``"internal"``, etc.

    Returns:
        Float risk score in ``[0.0, 10.0]``.
    """
    base = cvss_score if cvss_score is not None else _SEVERITY_BASE_SCORE.get(severity.lower(), 1.0)
    exploit_mult = _EXPLOIT_MULTIPLIER.get(exploit_maturity, 1.0)
    exposure_mult = _EXPOSURE_MULTIPLIER.get(exposure.lower(), 1.0)

    raw = base * exploit_mult * exposure_mult
    return round(min(raw, 10.0), 1)


def score_finding(finding: Any, exposure: str = "unknown") -> float:
    """
    Derive a risk score for a single Finding object.

    Reads CVSS score, severity, and exploit info from the finding and
    its ``cve_enrichment`` extra key (populated by the enrichment pipeline).
    """
    cvss = finding.cvss_score
    severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)

    enrichment = finding.extra.get("cve_enrichment", {})
    exploit_info = enrichment.get("exploit_info", {})
    maturity = exploit_info.get("maturity") if exploit_info.get("available") else None

    return compute_risk_score(cvss, severity, maturity, exposure)


# ---------------------------------------------------------------------------
# Severity normalisation
# ---------------------------------------------------------------------------

_SEVERITY_ALIASES: Dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
    "c": Severity.CRITICAL,
    "high": Severity.HIGH,
    "h": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "med": Severity.MEDIUM,
    "m": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "l": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
    "i": Severity.INFO,
    "note": Severity.INFO,
    "unknown": Severity.UNKNOWN,
}


def normalise_severity(raw: str) -> Severity:
    """
    Map a tool-specific severity string to a canonical :class:`Severity` enum.

    Case-insensitive.  Unknown values map to :attr:`Severity.UNKNOWN`.
    """
    key = raw.strip().lower() if raw else ""
    return _SEVERITY_ALIASES.get(key, Severity.UNKNOWN)


# ---------------------------------------------------------------------------
# Prioritisation
# ---------------------------------------------------------------------------

def prioritise_findings(
    findings: List[Any],
    exposure: str = "unknown",
    annotate: bool = True,
) -> List[Any]:
    """
    Sort findings by descending risk score and optionally annotate each
    with its rank and computed risk score.

    Args:
        findings:  List of Finding objects.
        exposure:  Exposure context applied to all findings (can be
                   overridden per-finding if ``extra["exposure"]`` is set).
        annotate:  If ``True``, write ``risk_score`` and ``priority_rank``
                   into each finding's ``extra`` dict.

    Returns:
        Sorted list of findings (new list; originals are also mutated if
        *annotate* is ``True``).
    """
    scored: List[tuple] = []

    for finding in findings:
        exp = finding.extra.get("exposure", exposure)
        risk = score_finding(finding, exposure=exp)
        scored.append((risk, finding))

    scored.sort(key=lambda t: t[0], reverse=True)

    result = []
    for rank, (risk, finding) in enumerate(scored, start=1):
        if annotate:
            finding.extra["risk_score"] = risk
            finding.extra["priority_rank"] = rank
        result.append(finding)

    return result
