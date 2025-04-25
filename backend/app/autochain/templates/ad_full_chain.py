"""
AutoChain v3 — ad_full_chain Template

Comprehensive Active Directory penetration test chain:
  1.  Network scan — host discovery & port scan (nmap/naabu)
  2.  SMB enumeration — shares, users, sessions, null sessions
  3.  LDAP enumeration — domain users, groups, GPOs, trusts
  4.  Kerbrute — username enumeration & AS-REP roastable users
  5.  AS-REP Roasting — collect hashes for accounts without pre-auth
  6.  Kerberoasting — request TGS tickets for SPNs → offline cracking
  7.  Hash cracking — hashcat / john with custom wordlists + rules
  8.  BloodHound collection — SharpHound / BloodHound.py
  9.  Attack path analysis — BloodHound shortest path queries
 10.  Privilege escalation — local admin → domain escalation vectors
 11.  DCSync — domain controller replication dump (krbtgt hash)
 12.  Golden ticket creation — long-lived forged Kerberos TGT
 13.  Silver ticket creation — service-specific Kerberos tickets
 14.  Report generation — AD-specific findings with CVSS scores

Covers the full MITRE ATT&CK for Active Directory attack chain.
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

class ADPhase(str, Enum):
    NETWORK_SCAN     = "network_scan"
    SMB_ENUM         = "smb_enum"
    LDAP_ENUM        = "ldap_enum"
    KERBRUTE         = "kerbrute"
    ASREP_ROAST      = "asrep_roast"
    KERBEROAST       = "kerberoast"
    HASH_CRACK       = "hash_crack"
    BLOODHOUND       = "bloodhound"
    ATTACK_PATH      = "attack_path"
    PRIV_ESC         = "priv_esc"
    DCSYNC           = "dcsync"
    GOLDEN_TICKET    = "golden_ticket"
    SILVER_TICKET    = "silver_ticket"
    REPORT           = "report"


class HashType(str, Enum):
    NTLM       = "ntlm"
    NET_NTLMV2 = "netntlmv2"
    KERBEROS   = "kerberos"
    AS_REP     = "as_rep"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class ADFullChainConfig:
    """Configuration for the ad_full_chain template."""

    # ── Credentials / Context ─────────────────────────────────────────────
    domain: Optional[str] = None              # e.g. CORP.LOCAL
    dc_ip: Optional[str] = None              # Domain Controller IP
    username: Optional[str] = None           # Initial foothold account
    password: Optional[str] = None           # Avoid storing; use env var
    nt_hash: Optional[str] = None            # Pass-the-hash alternative
    use_kerberos: bool = False               # Use Kerberos instead of NTLM

    # ── Network scanning ─────────────────────────────────────────────────
    network_range: Optional[str] = None      # e.g. 10.10.10.0/24
    scan_all_ports: bool = False
    port_scan_top_n: int = 1000
    smb_ports: List[int] = field(default_factory=lambda: [139, 445])
    ldap_ports: List[int] = field(default_factory=lambda: [389, 636, 3268, 3269])

    # ── SMB ──────────────────────────────────────────────────────────────
    smb_null_session: bool = True
    smb_enum_shares: bool = True
    smb_enum_users: bool = True
    smb_enum_groups: bool = True
    smb_relay_detect: bool = True

    # ── LDAP ─────────────────────────────────────────────────────────────
    ldap_anonymous_bind: bool = True
    ldap_enum_users: bool = True
    ldap_enum_groups: bool = True
    ldap_enum_gpos: bool = True
    ldap_enum_trusts: bool = True
    ldap_enum_acls: bool = True

    # ── Kerbrute ─────────────────────────────────────────────────────────
    kerbrute_enabled: bool = True
    kerbrute_user_wordlist: str = "xato-net-10-million-usernames"

    # ── AS-REP Roasting ───────────────────────────────────────────────────
    asrep_roast_enabled: bool = True

    # ── Kerberoasting ────────────────────────────────────────────────────
    kerberoast_enabled: bool = True
    kerberoast_all_spns: bool = True

    # ── Hash cracking ────────────────────────────────────────────────────
    hash_crack_enabled: bool = True
    crack_wordlist: str = "rockyou"
    crack_rules: List[str] = field(default_factory=lambda: ["best64", "KoreLogic"])
    crack_mask: str = "?u?l?l?l?l?l?d?d"
    crack_timeout_minutes: int = 30

    # ── BloodHound ───────────────────────────────────────────────────────
    bloodhound_enabled: bool = True
    bloodhound_collection_method: str = "All"   # All|DCOnly|ComputerOnly|Session
    bloodhound_stealth: bool = False

    # ── Attack paths ─────────────────────────────────────────────────────
    attack_path_enabled: bool = True
    attack_path_max_hops: int = 10

    # ── Privilege escalation ─────────────────────────────────────────────
    priv_esc_enabled: bool = True

    # ── DCSync ───────────────────────────────────────────────────────────
    dcsync_enabled: bool = True
    dcsync_all_users: bool = False   # True dumps all; False dumps krbtgt + admins

    # ── Tickets ─────────────────────────────────────────────────────────
    golden_ticket_enabled: bool = True
    silver_ticket_enabled: bool = True

    # ── Output ───────────────────────────────────────────────────────────
    generate_report: bool = True
    report_format: str = "html"


# ---------------------------------------------------------------------------
# Template
# ---------------------------------------------------------------------------

class ADFullChainTemplate:
    """
    ad_full_chain — Comprehensive Active Directory penetration test chain.

    Covers the full kill chain from unauthenticated network scanning through
    domain compromise, credential extraction, and ticket forging.

    Compatible with BloodHound CE, Impacket, Kerbrute, CrackMapExec.
    """

    TEMPLATE_ID = "ad_full_chain"
    NAME = "Active Directory Full Chain"
    DESCRIPTION = (
        "Comprehensive AD penetration test: network discovery, SMB/LDAP "
        "enumeration, Kerbrute, AS-REP Roast, Kerberoast, hash cracking, "
        "BloodHound attack paths, DCSync, and Golden/Silver ticket forging."
    )
    VERSION = "3.0.0"
    ESTIMATED_DURATION_MINUTES = 240

    PHASE_ORDER: List[str] = [
        "network_scan",
        "smb_enum",
        "ldap_enum",
        "kerbrute",
        "asrep_roast",
        "kerberoast",
        "hash_crack",
        "bloodhound",
        "attack_path",
        "priv_esc",
        "dcsync",
        "golden_ticket",
        "silver_ticket",
        "report",
    ]

    PHASE_TOOLS: Dict[str, List[str]] = {
        "network_scan":   ["naabu", "nmap", "masscan"],
        "smb_enum":       ["crackmapexec", "enum4linux", "smbclient", "responder"],
        "ldap_enum":      ["ldapdomaindump", "windapsearch", "bloodhound_ldap_tool"],
        "kerbrute":       ["kerbrute"],
        "asrep_roast":    ["impacket_getnpusers", "rubeus"],
        "kerberoast":     ["impacket_getuserspns", "rubeus"],
        "hash_crack":     ["hashcat", "john"],
        "bloodhound":     ["bloodhound_collect_tool", "sharphound", "bloodhound_py"],
        "attack_path":    ["bloodhound_query_tool", "neo4j_cypher_tool"],
        "priv_esc":       ["crackmapexec", "impacket_secretsdump", "winpeas"],
        "dcsync":         ["dcsync_tool", "impacket_secretsdump", "mimikatz"],
        "golden_ticket":  ["golden_ticket_tool", "impacket_ticketer", "mimikatz"],
        "silver_ticket":  ["silver_ticket_tool", "impacket_ticketer"],
        "report":         ["report_engine"],
    }

    # MITRE ATT&CK technique mappings
    MITRE_MAPPING: Dict[str, List[str]] = {
        "network_scan":   ["T1046"],
        "smb_enum":       ["T1135", "T1087.002"],
        "ldap_enum":      ["T1018", "T1069.002", "T1087.002"],
        "kerbrute":       ["T1110.003"],
        "asrep_roast":    ["T1558.004"],
        "kerberoast":     ["T1558.003"],
        "hash_crack":     ["T1110.002"],
        "bloodhound":     ["T1069.002", "T1087.002", "T1615"],
        "attack_path":    ["T1078", "T1484"],
        "priv_esc":       ["T1068", "T1078.002"],
        "dcsync":         ["T1003.006"],
        "golden_ticket":  ["T1558.001"],
        "silver_ticket":  ["T1558.002"],
        "report":         [],
    }

    def __init__(
        self,
        target: str,
        *,
        config: Optional[ADFullChainConfig] = None,
        project_id: Optional[str] = None,
        auto_approve_risk_level: str = "high",
    ) -> None:
        self.target = target
        self.config = config or ADFullChainConfig()
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
                "mitre_techniques": self.MITRE_MAPPING.get(phase_id, []),
                "requires_credentials": self._phase_requires_creds(phase_id),
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
            "domain": self.config.domain,
            "dc_ip": self.config.dc_ip,
            "mitre_mapping": self.MITRE_MAPPING,
        }

    def get_all_tools(self) -> List[str]:
        """Return deduplicated list of all tools used."""
        tools: List[str] = []
        seen: set = set()
        for tlist in self.PHASE_TOOLS.values():
            for t in tlist:
                if t not in seen:
                    tools.append(t)
                    seen.add(t)
        return tools

    def get_attack_path_queries(self) -> List[Dict[str, str]]:
        """Return default BloodHound attack path queries for this chain."""
        return [
            {
                "name": "Shortest path to Domain Admin",
                "query": "MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name:'DOMAIN ADMINS@{domain}'})) RETURN p",
            },
            {
                "name": "Users with DCSync rights",
                "query": "MATCH (n)-[:DCSync|AllExtendedRights|GenericAll]->(d:Domain) RETURN n.name,labels(n)",
            },
            {
                "name": "Kerberoastable users in DA path",
                "query": "MATCH (u:User {hasspn:true}) MATCH p=shortestPath((u)-[*1..]->(g:Group {name:'DOMAIN ADMINS@{domain}'})) RETURN p",
            },
            {
                "name": "AS-REP roastable users",
                "query": "MATCH (u:User {dontreqpreauth:true}) RETURN u.name,u.enabled",
            },
            {
                "name": "Computers with unconstrained delegation",
                "query": "MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name",
            },
        ]

    def get_enabled_phases(self) -> List[str]:
        """Return only phases enabled by config."""
        return [p for p in self.PHASE_ORDER if not self._is_phase_disabled(p)]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_phase_disabled(self, phase_id: str) -> bool:
        cfg = self.config
        disabled_map: Dict[str, bool] = {
            "kerbrute":      not cfg.kerbrute_enabled,
            "asrep_roast":   not cfg.asrep_roast_enabled,
            "kerberoast":    not cfg.kerberoast_enabled,
            "hash_crack":    not cfg.hash_crack_enabled,
            "bloodhound":    not cfg.bloodhound_enabled,
            "attack_path":   not cfg.attack_path_enabled,
            "priv_esc":      not cfg.priv_esc_enabled,
            "dcsync":        not cfg.dcsync_enabled,
            "golden_ticket": not cfg.golden_ticket_enabled,
            "silver_ticket": not cfg.silver_ticket_enabled,
            "report":        not cfg.generate_report,
        }
        return disabled_map.get(phase_id, False)

    @staticmethod
    def _phase_requires_creds(phase_id: str) -> bool:
        requires = {
            "kerberoast", "priv_esc", "dcsync", "golden_ticket", "silver_ticket",
        }
        return phase_id in requires

    def _phase_config(self, phase_id: str) -> Dict[str, Any]:
        cfg = self.config
        base_auth = {
            "domain": cfg.domain,
            "dc_ip": cfg.dc_ip,
            "username": cfg.username,
            "nt_hash": cfg.nt_hash,
            "use_kerberos": cfg.use_kerberos,
        }
        configs: Dict[str, Dict[str, Any]] = {
            "network_scan": {
                "target": self.target,
                "range": cfg.network_range,
                "top_n": cfg.port_scan_top_n,
                "all_ports": cfg.scan_all_ports,
            },
            "smb_enum": {
                **base_auth,
                "null_session": cfg.smb_null_session,
                "shares": cfg.smb_enum_shares,
                "users": cfg.smb_enum_users,
                "groups": cfg.smb_enum_groups,
                "relay_detect": cfg.smb_relay_detect,
                "ports": cfg.smb_ports,
            },
            "ldap_enum": {
                **base_auth,
                "anonymous_bind": cfg.ldap_anonymous_bind,
                "users": cfg.ldap_enum_users,
                "groups": cfg.ldap_enum_groups,
                "gpos": cfg.ldap_enum_gpos,
                "trusts": cfg.ldap_enum_trusts,
                "acls": cfg.ldap_enum_acls,
                "ports": cfg.ldap_ports,
            },
            "kerbrute": {
                "domain": cfg.domain,
                "dc_ip": cfg.dc_ip,
                "wordlist": cfg.kerbrute_user_wordlist,
            },
            "asrep_roast": {**base_auth, "all_users": True},
            "kerberoast": {**base_auth, "all_spns": cfg.kerberoast_all_spns},
            "hash_crack": {
                "wordlist": cfg.crack_wordlist,
                "rules": cfg.crack_rules,
                "mask": cfg.crack_mask,
                "timeout_minutes": cfg.crack_timeout_minutes,
                "modes": [HashType.NTLM.value, HashType.AS_REP.value, HashType.KERBEROS.value],
            },
            "bloodhound": {
                **base_auth,
                "method": cfg.bloodhound_collection_method,
                "stealth": cfg.bloodhound_stealth,
            },
            "attack_path": {
                "domain": cfg.domain,
                "queries": self.get_attack_path_queries(),
                "max_hops": cfg.attack_path_max_hops,
            },
            "priv_esc": {**base_auth},
            "dcsync": {
                **base_auth,
                "all_users": cfg.dcsync_all_users,
                "target_user": "krbtgt",
            },
            "golden_ticket": {**base_auth, "domain": cfg.domain},
            "silver_ticket": {**base_auth, "domain": cfg.domain},
            "report": {
                "format": cfg.report_format,
                "include_mitre": True,
                "include_poc": True,
                "include_remediation": True,
            },
        }
        return configs.get(phase_id, {})

    @staticmethod
    def _phase_name(phase_id: str) -> str:
        names = {
            "network_scan":   "Network Discovery & Port Scan",
            "smb_enum":       "SMB Enumeration",
            "ldap_enum":      "LDAP Enumeration",
            "kerbrute":       "Username Enumeration (Kerbrute)",
            "asrep_roast":    "AS-REP Roasting",
            "kerberoast":     "Kerberoasting",
            "hash_crack":     "Offline Hash Cracking",
            "bloodhound":     "BloodHound Collection",
            "attack_path":    "Attack Path Analysis",
            "priv_esc":       "Privilege Escalation",
            "dcsync":         "DCSync (Domain Secret Dump)",
            "golden_ticket":  "Golden Ticket Forging",
            "silver_ticket":  "Silver Ticket Forging",
            "report":         "AD Penetration Test Report",
        }
        return names.get(phase_id, phase_id)

    @staticmethod
    def _phase_description(phase_id: str) -> str:
        descs = {
            "network_scan":   "Discover live hosts and open ports across the target AD network range.",
            "smb_enum":       "Enumerate SMB shares, sessions, users, and test for null sessions and relay vectors.",
            "ldap_enum":      "Extract domain users, groups, GPOs, trusts, and ACLs via LDAP/LDAPS.",
            "kerbrute":       "Username enumeration and AS-REP roastable account detection via Kerberos pre-auth.",
            "asrep_roast":    "Collect AS-REP hashes for accounts with Kerberos pre-authentication disabled.",
            "kerberoast":     "Request TGS tickets for SPN-registered accounts for offline cracking.",
            "hash_crack":     "Offline cracking of NTLM, AS-REP, and Kerberos hashes with hashcat/john.",
            "bloodhound":     "Collect AD relationship data with SharpHound/BloodHound.py for graph analysis.",
            "attack_path":    "Analyse BloodHound graph for shortest attack paths to Domain Admin.",
            "priv_esc":       "Escalate from initial foothold to local admin and domain escalation.",
            "dcsync":         "Dump domain secrets (NTDS.dit) via DCSync replication abuse.",
            "golden_ticket":  "Forge Golden Ticket TGT using krbtgt hash for persistent domain access.",
            "silver_ticket":  "Forge Silver Tickets for specific services without touching the DC.",
            "report":         "Generate MITRE ATT&CK-mapped AD pentest report with full findings.",
        }
        return descs.get(phase_id, "")

    @staticmethod
    def _phase_estimate(phase_id: str) -> int:
        estimates = {
            "network_scan":   15,
            "smb_enum":       15,
            "ldap_enum":      15,
            "kerbrute":       10,
            "asrep_roast":     5,
            "kerberoast":      5,
            "hash_crack":     30,
            "bloodhound":     20,
            "attack_path":    10,
            "priv_esc":       20,
            "dcsync":          5,
            "golden_ticket":   5,
            "silver_ticket":   5,
            "report":         10,
        }
        return estimates.get(phase_id, 5)
