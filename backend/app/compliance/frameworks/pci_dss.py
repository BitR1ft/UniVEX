"""
PCI-DSS v4.0 control definitions.

Covers all 12 Requirements with sub-requirements used by the
ComplianceMapper to map pentest findings to PCI-DSS controls.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class SubRequirement:
    id: str
    title: str


@dataclass
class PCIDSSRequirement:
    req_id: str
    title: str
    description: str
    sub_requirements: List[SubRequirement]
    finding_keywords: List[str]


PCI_DSS_CONTROLS: Dict[str, PCIDSSRequirement] = {
    "1": PCIDSSRequirement(
        req_id="1",
        title="Install and Maintain Network Security Controls",
        description=(
            "Network security controls (NSCs) are network policy enforcement "
            "points that control network traffic between two or more logical or "
            "physical network segments."
        ),
        sub_requirements=[
            SubRequirement("1.1", "Processes and mechanisms for installing and maintaining network security controls are defined and understood"),
            SubRequirement("1.2", "Network security controls (NSCs) are configured and maintained"),
            SubRequirement("1.3", "Network access to and from the cardholder data environment is restricted"),
            SubRequirement("1.4", "Network connections between trusted and untrusted networks are controlled"),
            SubRequirement("1.5", "Risks to the CDE from computing devices that are able to connect to both untrusted networks and the CDE are mitigated"),
        ],
        finding_keywords=[
            "firewall", "network segmentation", "network control",
            "open port", "unnecessary port", "ingress filtering", "egress filtering",
            "dmz", "untrusted network", "cardholder data environment", "cde",
            "network policy", "acl", "network access control",
        ],
    ),
    "2": PCIDSSRequirement(
        req_id="2",
        title="Apply Secure Configurations to All System Components",
        description=(
            "Malicious individuals, both external and internal to an entity, "
            "often use default passwords and other vendor default settings to "
            "compromise systems."
        ),
        sub_requirements=[
            SubRequirement("2.1", "Processes and mechanisms for applying secure configurations to all system components are defined and understood"),
            SubRequirement("2.2", "System components are configured and managed securely"),
            SubRequirement("2.3", "Wireless environments are configured and managed securely"),
        ],
        finding_keywords=[
            "default credential", "default password", "default configuration",
            "hardening", "secure configuration", "unnecessary service",
            "vendor default", "system hardening", "baseline configuration",
            "configuration management", "cis benchmark",
        ],
    ),
    "3": PCIDSSRequirement(
        req_id="3",
        title="Protect Stored Account Data",
        description=(
            "Protection methods such as encryption, truncation, masking, and "
            "hashing are critical components of primary account number (PAN) "
            "protection."
        ),
        sub_requirements=[
            SubRequirement("3.1", "Processes and mechanisms for protecting stored account data are defined and understood"),
            SubRequirement("3.2", "Storage of account data is kept to a minimum"),
            SubRequirement("3.3", "Sensitive authentication data (SAD) is not stored after authorization"),
            SubRequirement("3.4", "Access to displays of full PAN and ability to copy cardholder data are restricted"),
            SubRequirement("3.5", "Primary account number (PAN) is secured wherever it is stored"),
            SubRequirement("3.6", "Cryptographic keys used to protect stored account data are secured"),
            SubRequirement("3.7", "Where cryptography is used to protect stored account data, key management processes and procedures covering all aspects of the key lifecycle are defined and implemented"),
        ],
        finding_keywords=[
            "stored pan", "account data", "cardholder data", "credit card",
            "payment card", "unencrypted pan", "clear text pan",
            "sad storage", "sensitive authentication", "cvv stored",
            "track data", "magnetic stripe", "key management",
        ],
    ),
    "4": PCIDSSRequirement(
        req_id="4",
        title="Protect Cardholder Data with Strong Cryptography During Transmission",
        description=(
            "Sensitive information must be encrypted during transmission over "
            "public networks because it is easy and common for a malicious "
            "individual to intercept and/or divert data while in transit."
        ),
        sub_requirements=[
            SubRequirement("4.1", "Processes and mechanisms for protecting cardholder data with strong cryptography during transmission over open, public networks are defined and documented"),
            SubRequirement("4.2", "PAN is protected with strong cryptography during transmission"),
        ],
        finding_keywords=[
            "transmission", "in transit", "data in transit", "plaintext transmission",
            "unencrypted transmission", "weak tls", "ssl", "tls 1.0", "tls 1.1",
            "weak cipher suite", "public network", "clear text transmission",
            "http instead of https", "no tls",
        ],
    ),
    "5": PCIDSSRequirement(
        req_id="5",
        title="Protect All Systems and Networks from Malicious Software",
        description=(
            "Malicious software (malware) is software or firmware designed to "
            "infiltrate or damage a computer system without the owner's knowledge "
            "or consent."
        ),
        sub_requirements=[
            SubRequirement("5.1", "Processes and mechanisms for protecting all systems and networks from malicious software are defined and understood"),
            SubRequirement("5.2", "Malicious software (malware) is prevented, or detected and addressed"),
            SubRequirement("5.3", "Anti-malware mechanisms and processes are active, maintained, and monitored"),
            SubRequirement("5.4", "Anti-phishing mechanisms protect users against phishing attacks"),
        ],
        finding_keywords=[
            "malware", "anti-virus", "antivirus", "anti-malware",
            "malicious software", "virus", "ransomware", "trojan",
            "phishing", "no antivirus", "endpoint protection", "edr",
        ],
    ),
    "6": PCIDSSRequirement(
        req_id="6",
        title="Develop and Maintain Secure Systems and Software",
        description=(
            "Security vulnerabilities in systems and applications may allow "
            "criminals to access PAN and other cardholder data. Many of these "
            "vulnerabilities are eliminated by installing vendor-provided "
            "security patches."
        ),
        sub_requirements=[
            SubRequirement("6.1", "Processes and mechanisms for developing and maintaining secure systems and software are defined and understood"),
            SubRequirement("6.2", "Bespoke and custom software are developed securely"),
            SubRequirement("6.3", "Security vulnerabilities are identified and addressed"),
            SubRequirement("6.4", "Public-facing web applications are protected against attacks"),
            SubRequirement("6.5", "Changes to all system components are managed securely"),
        ],
        finding_keywords=[
            "patch", "unpatched", "vulnerability management", "secure development",
            "sdlc", "code review", "web application firewall", "waf",
            "injection", "xss", "cross-site scripting", "csrf",
            "secure coding", "penetration test", "application vulnerability",
        ],
    ),
    "7": PCIDSSRequirement(
        req_id="7",
        title="Restrict Access to System Components and Cardholder Data by Business Need to Know",
        description=(
            "To ensure critical data can only be accessed by authorized "
            "personnel, systems and processes must be in place to limit access "
            "based on need to know and according to job responsibilities."
        ),
        sub_requirements=[
            SubRequirement("7.1", "Processes and mechanisms for restricting access to system components and cardholder data by business need to know are defined and understood"),
            SubRequirement("7.2", "Access to system components and data is appropriately defined and assigned"),
            SubRequirement("7.3", "Access to system components and data is managed via an access control system"),
        ],
        finding_keywords=[
            "least privilege", "need to know", "overprivileged", "excessive access",
            "access control", "role based access", "rbac", "access review",
            "privilege management", "unauthorized access to cardholder",
        ],
    ),
    "8": PCIDSSRequirement(
        req_id="8",
        title="Identify Users and Authenticate Access to System Components",
        description=(
            "Assigning a unique identification (ID) to each person with access "
            "ensures that each individual is uniquely accountable for their "
            "actions."
        ),
        sub_requirements=[
            SubRequirement("8.1", "Processes and mechanisms for identifying users and authenticating access to system components are defined and understood"),
            SubRequirement("8.2", "User identification and related accounts for users and administrators are strictly managed throughout an account's lifecycle"),
            SubRequirement("8.3", "User authentication for users and administrators is established and managed"),
            SubRequirement("8.4", "Multi-factor authentication (MFA) is implemented to secure access into the CDE"),
            SubRequirement("8.5", "Multi-factor authentication (MFA) systems are configured to prevent misuse"),
            SubRequirement("8.6", "Use of application and system accounts and associated authentication factors is strictly managed"),
        ],
        finding_keywords=[
            "authentication", "weak authentication", "missing mfa", "multi-factor",
            "password policy", "shared account", "generic account",
            "service account", "user identification", "account management",
            "brute force", "credential", "password complexity", "account lockout",
        ],
    ),
    "9": PCIDSSRequirement(
        req_id="9",
        title="Restrict Physical Access to Cardholder Data",
        description=(
            "Any physical access to data or systems that house cardholder data "
            "provides the opportunity for individuals to access devices or data "
            "and to remove systems or hardcopies, and should be appropriately "
            "restricted."
        ),
        sub_requirements=[
            SubRequirement("9.1", "Processes and mechanisms for restricting physical access to cardholder data are defined and understood"),
            SubRequirement("9.2", "Physical access controls manage entry into facilities and systems containing cardholder data"),
            SubRequirement("9.3", "Physical access for personnel and visitors is authorized and managed"),
            SubRequirement("9.4", "Media with cardholder data is securely stored, accessed, distributed, and destroyed"),
            SubRequirement("9.5", "Point-of-interaction (POI) devices are protected from tampering and unauthorized substitution"),
        ],
        finding_keywords=[
            "physical access", "physical security", "tailgating", "piggybacking",
            "data center access", "media disposal", "card skimmer", "poi device",
            "point of interaction", "physical tamper", "badge access",
        ],
    ),
    "10": PCIDSSRequirement(
        req_id="10",
        title="Log and Monitor All Access to System Components and Cardholder Data",
        description=(
            "Logging mechanisms and the ability to track user activities are "
            "critical in preventing, detecting, or minimizing the impact of a "
            "data compromise."
        ),
        sub_requirements=[
            SubRequirement("10.1", "Processes and mechanisms for logging and monitoring all access to system components and cardholder data are defined and documented"),
            SubRequirement("10.2", "Audit logs capture all events subject to logging requirements"),
            SubRequirement("10.3", "Audit logs are protected from destruction and unauthorized modifications"),
            SubRequirement("10.4", "Audit logs are reviewed to identify anomalies or suspicious activity"),
            SubRequirement("10.5", "Retain audit log history for at least 12 months, with at least the most recent three months available for immediate analysis"),
            SubRequirement("10.6", "Time-synchronization mechanisms support consistent time settings across all systems"),
            SubRequirement("10.7", "Failures of critical security controls are detected, reported, and responded to promptly"),
        ],
        finding_keywords=[
            "audit log", "logging", "log monitoring", "no logging",
            "insufficient logging", "log review", "siem", "log retention",
            "time synchronization", "ntp", "log tampering", "audit trail",
            "access logging", "failed login", "event monitoring",
        ],
    ),
    "11": PCIDSSRequirement(
        req_id="11",
        title="Test Security of Systems and Networks Regularly",
        description=(
            "Vulnerabilities are being continuously discovered by malicious "
            "individuals and researchers, and being introduced by new software. "
            "System components, processes, and bespoke and custom software "
            "should be tested frequently to ensure security controls continue "
            "to reflect a changing environment."
        ),
        sub_requirements=[
            SubRequirement("11.1", "Processes and mechanisms for regularly testing security of systems and networks are defined and understood"),
            SubRequirement("11.2", "Wireless access points are identified and monitored, and unauthorized wireless access points are addressed"),
            SubRequirement("11.3", "External and internal vulnerabilities are regularly identified, prioritized, and addressed"),
            SubRequirement("11.4", "External and internal penetration testing is regularly performed, and exploitable vulnerabilities and security weaknesses are corrected"),
            SubRequirement("11.5", "Network intrusions and unexpected file changes are detected and responded to"),
            SubRequirement("11.6", "Unauthorized changes on payment pages are detected and responded to"),
        ],
        finding_keywords=[
            "penetration test", "vulnerability scan", "security test",
            "wireless scan", "rogue access point", "intrusion detection",
            "ids", "ips", "file integrity", "fim", "change detection",
        ],
    ),
    "12": PCIDSSRequirement(
        req_id="12",
        title="Support Information Security with Organizational Policies and Programs",
        description=(
            "A strong security policy sets the security tone for the whole "
            "entity and informs personnel what is expected of them."
        ),
        sub_requirements=[
            SubRequirement("12.1", "A comprehensive information security policy that governs and provides direction for protection of the entity's information assets is known and current"),
            SubRequirement("12.2", "Acceptable use policies for end-user technologies are defined and implemented"),
            SubRequirement("12.3", "Risks to the cardholder data environment are formally identified, evaluated, and managed"),
            SubRequirement("12.4", "PCI DSS compliance is managed"),
            SubRequirement("12.5", "PCI DSS scope is documented and validated"),
            SubRequirement("12.6", "Security awareness education is an ongoing activity"),
            SubRequirement("12.7", "Personnel are screened to reduce risks from insider threats"),
            SubRequirement("12.8", "Risk to information assets associated with third-party service provider (TPSP) relationships is managed"),
            SubRequirement("12.9", "Third-party service providers (TPSPs) support their customers' PCI DSS compliance"),
            SubRequirement("12.10", "Suspected and confirmed security incidents that could impact the CDE are responded to immediately"),
        ],
        finding_keywords=[
            "security policy", "information security policy", "security awareness",
            "security training", "risk assessment", "third party risk",
            "vendor management", "incident response", "policy violation",
            "security program", "data classification",
        ],
    ),
}


def map_finding_to_pci_dss(finding_title: str, finding_description: str) -> List[str]:
    """Return list of applicable PCI-DSS requirement IDs for a finding."""
    combined = (finding_title + " " + finding_description).lower()
    matched: List[str] = []
    for req_id, req in PCI_DSS_CONTROLS.items():
        for keyword in req.finding_keywords:
            if keyword in combined:
                matched.append(req_id)
                break
    return matched
