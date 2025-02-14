"""
CWE & CAPEC Mapping sub-package.

Provides:
    CWEService          – in-memory CWE lookup (XML or built-in)
    CWEEntry            – CWE data model
    CAPECService        – in-memory CAPEC lookup (XML or built-in)
    CAPECEntry          – CAPEC data model
    CWECAPECMapper      – bidirectional CWE↔CAPEC relationship graph
    vuln_cwe_mapper     – CWE extraction / Finding categorisation helpers
    RiskScorer functions – risk scoring, severity normalisation, prioritisation
    UpdateScheduler     – APScheduler-based auto-update jobs with audit logging
"""
from app.services.cwe_capec.cwe_service import CWEService, CWEEntry
from app.services.cwe_capec.capec_service import CAPECService, CAPECEntry
from app.services.cwe_capec.cwe_capec_mapper import CWECAPECMapper
from app.services.cwe_capec.risk_scorer import (
    compute_risk_score,
    normalise_severity,
    prioritise_findings,
    score_finding,
)
from app.services.cwe_capec.update_scheduler import UpdateScheduler, read_audit_log

__all__ = [
    "CWEService",
    "CWEEntry",
    "CAPECService",
    "CAPECEntry",
    "CWECAPECMapper",
    "compute_risk_score",
    "normalise_severity",
    "prioritise_findings",
    "score_finding",
    "UpdateScheduler",
    "read_audit_log",
]
