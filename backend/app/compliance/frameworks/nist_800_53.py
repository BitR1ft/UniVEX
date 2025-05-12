"""
NIST 800-53 Rev 5 control family definitions.

Covers all 20 control families used by the ComplianceMapper to
map pentest findings to NIST SP 800-53 controls.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class NISTKeyControl:
    control_id: str
    title: str
    description: str


@dataclass
class NISTFamily:
    family_id: str
    title: str
    description: str
    key_controls: List[NISTKeyControl]
    finding_keywords: List[str]


NIST_CONTROLS: Dict[str, NISTFamily] = {
    "AC": NISTFamily(
        family_id="AC",
        title="Access Control",
        description=(
            "The Access Control family addresses the need to limit system access "
            "to authorized users, processes acting on behalf of authorized users, "
            "and devices."
        ),
        key_controls=[
            NISTKeyControl("AC-1", "Access Control Policy and Procedures", "Establish access control policy and procedures"),
            NISTKeyControl("AC-2", "Account Management", "Manage information system accounts"),
            NISTKeyControl("AC-3", "Access Enforcement", "Enforce approved authorizations for access"),
            NISTKeyControl("AC-4", "Information Flow Enforcement", "Enforce approved authorizations for information flow"),
            NISTKeyControl("AC-6", "Least Privilege", "Employ the principle of least privilege"),
            NISTKeyControl("AC-7", "Unsuccessful Logon Attempts", "Enforce a limit of consecutive failed logon attempts"),
            NISTKeyControl("AC-17", "Remote Access", "Establish and document usage restrictions for remote access"),
        ],
        finding_keywords=[
            "access control", "unauthorized access", "privilege escalation",
            "least privilege", "overprivileged", "account management",
            "remote access", "idor", "broken access", "horizontal privilege",
            "vertical privilege", "rbac", "acl bypass",
        ],
    ),
    "AT": NISTFamily(
        family_id="AT",
        title="Awareness and Training",
        description=(
            "The Awareness and Training family addresses the need to ensure "
            "that personnel are aware of the security risks associated with "
            "their activities and trained to carry out their assigned duties."
        ),
        key_controls=[
            NISTKeyControl("AT-1", "Security Awareness and Training Policy and Procedures", "Establish security awareness and training policy"),
            NISTKeyControl("AT-2", "Security Awareness Training", "Provide basic security awareness training"),
            NISTKeyControl("AT-3", "Role-Based Security Training", "Provide role-based security training"),
        ],
        finding_keywords=[
            "security awareness", "security training", "phishing",
            "social engineering", "user education", "insider threat awareness",
        ],
    ),
    "AU": NISTFamily(
        family_id="AU",
        title="Audit and Accountability",
        description=(
            "The Audit and Accountability family addresses the need to create, "
            "protect, and retain system audit records to enable the monitoring, "
            "analysis, investigation, and reporting of unlawful or unauthorized "
            "system activity."
        ),
        key_controls=[
            NISTKeyControl("AU-1", "Audit and Accountability Policy and Procedures", "Establish audit policy"),
            NISTKeyControl("AU-2", "Event Logging", "Identify events requiring audit logging"),
            NISTKeyControl("AU-3", "Content of Audit Records", "Ensure audit records contain sufficient information"),
            NISTKeyControl("AU-6", "Audit Record Review, Analysis, and Reporting", "Review and analyze audit records"),
            NISTKeyControl("AU-9", "Protection of Audit Information", "Protect audit information from unauthorized access"),
            NISTKeyControl("AU-12", "Audit Record Generation", "Provide audit record generation capability"),
        ],
        finding_keywords=[
            "audit log", "logging", "no logging", "insufficient logging",
            "missing audit", "log review", "log monitoring", "audit trail",
            "log tampering", "siem", "event logging", "access logging",
            "security event", "failed login not logged",
        ],
    ),
    "CA": NISTFamily(
        family_id="CA",
        title="Assessment, Authorization, and Monitoring",
        description=(
            "The CA family addresses the need to continually assess the "
            "security controls in organizational systems to determine if the "
            "controls are effective."
        ),
        key_controls=[
            NISTKeyControl("CA-2", "Control Assessments", "Assess security controls in organizational systems"),
            NISTKeyControl("CA-7", "Continuous Monitoring", "Develop a system-level continuous monitoring strategy"),
            NISTKeyControl("CA-8", "Penetration Testing", "Conduct penetration testing on organizational systems"),
        ],
        finding_keywords=[
            "penetration test", "security assessment", "continuous monitoring",
            "risk assessment", "control assessment", "vulnerability assessment",
        ],
    ),
    "CM": NISTFamily(
        family_id="CM",
        title="Configuration Management",
        description=(
            "The Configuration Management family addresses the need to establish "
            "and maintain baseline configurations and inventories of organizational "
            "systems throughout the respective system development life cycles."
        ),
        key_controls=[
            NISTKeyControl("CM-2", "Baseline Configuration", "Establish and maintain baseline configurations"),
            NISTKeyControl("CM-6", "Configuration Settings", "Establish and document configuration settings"),
            NISTKeyControl("CM-7", "Least Functionality", "Configure the system to provide only essential capabilities"),
            NISTKeyControl("CM-8", "System Component Inventory", "Develop and maintain system component inventory"),
        ],
        finding_keywords=[
            "misconfiguration", "default configuration", "configuration management",
            "hardening", "baseline", "unnecessary service", "system inventory",
            "configuration drift", "security misconfiguration",
        ],
    ),
    "CP": NISTFamily(
        family_id="CP",
        title="Contingency Planning",
        description=(
            "The Contingency Planning family addresses the need to establish, "
            "maintain, and effectively implement plans for emergency response, "
            "backup operations, and post-disaster recovery."
        ),
        key_controls=[
            NISTKeyControl("CP-2", "Contingency Plan", "Develop a contingency plan for the system"),
            NISTKeyControl("CP-9", "System Backup", "Conduct backups of system-level information"),
        ],
        finding_keywords=[
            "backup", "disaster recovery", "business continuity",
            "contingency plan", "no backup", "recovery",
        ],
    ),
    "IA": NISTFamily(
        family_id="IA",
        title="Identification and Authentication",
        description=(
            "The Identification and Authentication family addresses the need "
            "to identify and authenticate users, processes, or devices before "
            "allowing them to access organizational systems."
        ),
        key_controls=[
            NISTKeyControl("IA-1", "Identification and Authentication Policy and Procedures", "Establish identification and authentication policy"),
            NISTKeyControl("IA-2", "Identification and Authentication (Organizational Users)", "Uniquely identify and authenticate organizational users"),
            NISTKeyControl("IA-5", "Authenticator Management", "Manage system authenticators"),
            NISTKeyControl("IA-6", "Authentication Feedback", "Obscure feedback of authentication information"),
            NISTKeyControl("IA-8", "Identification and Authentication (Non-Organizational Users)", "Uniquely identify and authenticate non-organizational users"),
            NISTKeyControl("IA-12", "Identity Proofing", "Implement identity proofing requirements"),
        ],
        finding_keywords=[
            "authentication", "weak authentication", "broken authentication",
            "weak password", "default password", "missing mfa", "multi-factor",
            "credential", "password policy", "session fixation", "session hijacking",
            "brute force", "account lockout", "password complexity",
            "insecure login", "user enumeration",
        ],
    ),
    "IR": NISTFamily(
        family_id="IR",
        title="Incident Response",
        description=(
            "The Incident Response family addresses the need to establish "
            "an operational incident handling capability for organizational "
            "systems that includes preparation, detection, analysis, containment, "
            "recovery, and user response activities."
        ),
        key_controls=[
            NISTKeyControl("IR-1", "Incident Response Policy and Procedures", "Establish incident response policy"),
            NISTKeyControl("IR-4", "Incident Handling", "Implement an incident handling capability"),
            NISTKeyControl("IR-6", "Incident Reporting", "Require personnel to report suspected security incidents"),
        ],
        finding_keywords=[
            "incident response", "no incident response", "breach response",
            "security incident", "incident handling", "missing alerts",
        ],
    ),
    "MA": NISTFamily(
        family_id="MA",
        title="Maintenance",
        description=(
            "The Maintenance family addresses the need to perform maintenance "
            "on organizational systems, including controls on the tools, "
            "techniques, mechanisms, and personnel that carry out maintenance."
        ),
        key_controls=[
            NISTKeyControl("MA-2", "Controlled Maintenance", "Schedule, perform, document, and review maintenance"),
            NISTKeyControl("MA-6", "Timely Maintenance", "Obtain maintenance support for key system components"),
        ],
        finding_keywords=[
            "patch management", "maintenance", "unpatched", "end of life",
            "eol software", "outdated software",
        ],
    ),
    "MP": NISTFamily(
        family_id="MP",
        title="Media Protection",
        description=(
            "The Media Protection family addresses the need to protect system "
            "media, both digital and non-digital, limit access to information "
            "on system media to authorized users, and sanitize or destroy "
            "system media before disposal or reuse."
        ),
        key_controls=[
            NISTKeyControl("MP-2", "Media Access", "Restrict access to digital and non-digital media"),
            NISTKeyControl("MP-6", "Media Sanitization", "Sanitize system media before disposal"),
        ],
        finding_keywords=[
            "media disposal", "data destruction", "sensitive media",
            "removable media", "usb", "physical media",
        ],
    ),
    "PE": NISTFamily(
        family_id="PE",
        title="Physical and Environmental Protection",
        description=(
            "The Physical and Environmental Protection family addresses the "
            "need to limit physical access to organizational systems to "
            "authorized individuals."
        ),
        key_controls=[
            NISTKeyControl("PE-2", "Physical Access Authorizations", "Develop and maintain access authorization list"),
            NISTKeyControl("PE-3", "Physical Access Control", "Enforce physical access authorizations"),
        ],
        finding_keywords=[
            "physical access", "physical security", "tailgating", "data center",
            "badge access", "physical control",
        ],
    ),
    "PL": NISTFamily(
        family_id="PL",
        title="Planning",
        description=(
            "The Planning family addresses the need to develop, document, "
            "periodically update, and implement security plans for organizational "
            "systems that describe the security controls in place or planned for "
            "the systems."
        ),
        key_controls=[
            NISTKeyControl("PL-1", "Planning Policy and Procedures", "Establish planning policy"),
            NISTKeyControl("PL-2", "System Security and Privacy Plans", "Develop security and privacy plans"),
        ],
        finding_keywords=[
            "security plan", "system security plan", "planning",
        ],
    ),
    "PM": NISTFamily(
        family_id="PM",
        title="Program Management",
        description=(
            "The Program Management family addresses the need for organization-wide "
            "information security program management controls that are independent "
            "of any particular system."
        ),
        key_controls=[
            NISTKeyControl("PM-1", "Information Security Program Plan", "Develop and maintain information security program plan"),
            NISTKeyControl("PM-9", "Risk Management Strategy", "Develop and implement risk management strategy"),
        ],
        finding_keywords=[
            "security program", "risk management strategy", "information security management",
        ],
    ),
    "PS": NISTFamily(
        family_id="PS",
        title="Personnel Security",
        description=(
            "The Personnel Security family addresses the need to ensure that "
            "individuals occupying positions of responsibility within organizations "
            "are trustworthy and meet established security criteria."
        ),
        key_controls=[
            NISTKeyControl("PS-3", "Personnel Screening", "Screen individuals prior to authorizing access"),
            NISTKeyControl("PS-4", "Personnel Termination", "Verify termination procedures include access revocation"),
        ],
        finding_keywords=[
            "insider threat", "personnel security", "background check",
            "terminated employee", "access revocation",
        ],
    ),
    "RA": NISTFamily(
        family_id="RA",
        title="Risk Assessment",
        description=(
            "The Risk Assessment family addresses the need to periodically "
            "assess the risk to organizational operations and assets, individuals, "
            "other organizations, and the Nation, resulting from the operation "
            "of organizational systems."
        ),
        key_controls=[
            NISTKeyControl("RA-3", "Risk Assessment", "Conduct risk assessment"),
            NISTKeyControl("RA-5", "Vulnerability Monitoring and Scanning", "Monitor and scan for vulnerabilities"),
        ],
        finding_keywords=[
            "risk assessment", "vulnerability scan", "vulnerability management",
            "risk analysis", "threat assessment",
        ],
    ),
    "SA": NISTFamily(
        family_id="SA",
        title="System and Services Acquisition",
        description=(
            "The System and Services Acquisition family addresses the need "
            "to allocate sufficient resources to protect organizational systems, "
            "employ system development life cycle processes that incorporate "
            "information security considerations."
        ),
        key_controls=[
            NISTKeyControl("SA-3", "System Development Life Cycle", "Incorporate security into the SDLC"),
            NISTKeyControl("SA-8", "Security and Privacy Engineering Principles", "Apply security engineering principles"),
            NISTKeyControl("SA-11", "Developer Testing and Evaluation", "Require developer security testing"),
        ],
        finding_keywords=[
            "sdlc", "secure development", "supply chain", "third party",
            "vendor security", "developer testing", "security requirements",
        ],
    ),
    "SC": NISTFamily(
        family_id="SC",
        title="System and Communications Protection",
        description=(
            "The System and Communications Protection family addresses the "
            "need to implement security safeguards to protect organizational "
            "systems and the information in those systems from unauthorized "
            "disclosure."
        ),
        key_controls=[
            NISTKeyControl("SC-5", "Denial of Service Protection", "Implement denial-of-service attack protection"),
            NISTKeyControl("SC-8", "Transmission Confidentiality and Integrity", "Implement cryptographic mechanisms during transmission"),
            NISTKeyControl("SC-12", "Cryptographic Key Establishment and Management", "Establish and manage cryptographic keys"),
            NISTKeyControl("SC-28", "Protection of Information at Rest", "Implement cryptographic mechanisms at rest"),
        ],
        finding_keywords=[
            "encryption", "weak encryption", "transmission security", "ssl", "tls",
            "cryptography", "key management", "denial of service", "dos",
            "network protection", "communication security", "data at rest",
        ],
    ),
    "SI": NISTFamily(
        family_id="SI",
        title="System and Information Integrity",
        description=(
            "The System and Information family addresses the need to identify, "
            "report, and correct information and system flaws in a timely manner, "
            "provide protection from malicious code, and monitor system security "
            "alerts and advisories."
        ),
        key_controls=[
            NISTKeyControl("SI-2", "Flaw Remediation", "Identify, report, and correct system flaws"),
            NISTKeyControl("SI-3", "Malicious Code Protection", "Implement malicious code protection"),
            NISTKeyControl("SI-4", "System Monitoring", "Monitor the system to detect attacks and indicators"),
            NISTKeyControl("SI-7", "Software, Firmware, and Information Integrity", "Employ integrity verification tools"),
            NISTKeyControl("SI-10", "Information Input Validation", "Check information inputs for validity"),
        ],
        finding_keywords=[
            "injection", "sql injection", "xss", "cross-site scripting",
            "input validation", "malware", "malicious code", "system monitoring",
            "integrity check", "flaw remediation", "patch", "unpatched",
            "rce", "remote code execution",
        ],
    ),
    "SR": NISTFamily(
        family_id="SR",
        title="Supply Chain Risk Management",
        description=(
            "The Supply Chain Risk Management family addresses the need to "
            "protect against supply chain risks by employing security measures "
            "throughout the system development life cycle."
        ),
        key_controls=[
            NISTKeyControl("SR-3", "Supply Chain Controls and Processes", "Establish supply chain controls"),
            NISTKeyControl("SR-6", "Supplier Assessments and Reviews", "Assess and review suppliers"),
        ],
        finding_keywords=[
            "supply chain", "supplier", "third party component", "dependency",
            "open source", "library vulnerability", "software bill of materials",
        ],
    ),
    "PT": NISTFamily(
        family_id="PT",
        title="PII Processing and Transparency",
        description=(
            "The PII Processing and Transparency family addresses the need "
            "to implement privacy controls to enable organizations to manage "
            "PII consistent with applicable privacy requirements."
        ),
        key_controls=[
            NISTKeyControl("PT-1", "Policy and Procedures", "Establish PII processing policy"),
            NISTKeyControl("PT-2", "Authority to Process Personally Identifiable Information", "Identify legal authority to process PII"),
            NISTKeyControl("PT-7", "Specific Categories of Personally Identifiable Information", "Apply additional protections for specific PII categories"),
        ],
        finding_keywords=[
            "pii", "personal data", "personally identifiable", "gdpr",
            "privacy", "data protection", "sensitive personal information",
        ],
    ),
}


def map_finding_to_nist(finding_title: str, finding_description: str) -> List[str]:
    """Return list of applicable NIST 800-53 family IDs for a finding."""
    combined = (finding_title + " " + finding_description).lower()
    matched: List[str] = []
    for family_id, family in NIST_CONTROLS.items():
        for keyword in family.finding_keywords:
            if keyword in combined:
                matched.append(family_id)
                break
    return matched
