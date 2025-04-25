"""
ReconToExploitMapper

Converts structured recon output (port scan results, service versions,
Nuclei vulnerability findings) into a ranked list of ExploitCandidates.

Mapping logic
-------------
1. For each open port + service banner:
     a. Look up the service name in SERVICE_EXPLOIT_MAP for known quick-wins.
     b. Search Metasploit for matching modules (via MCPClient on port 8003).
2. For each Nuclei finding that includes a CVE ID:
     a. Use the CVSS score already present in the finding.
     b. Search Metasploit for the CVE to check module availability.
3. Score each candidate:
     final_score = min(base_score + (2 if msf_available else 0), 10)
4. Return candidates sorted descending by final_score.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from .schemas import ExploitCandidate

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Static knowledge base: service → best Metasploit module + payload hint
# ---------------------------------------------------------------------------

# Maps lowercase service names (or banner fragments) to (module_path, payload_hint, default_cvss)
SERVICE_EXPLOIT_MAP: Dict[str, Dict[str, Any]] = {
    # FTP
    "vsftpd 2.3.4": {
        "module_path": "exploit/unix/ftp/vsftpd_234_backdoor",
        "payload_hint": "cmd/unix/interact",
        "cvss": 10.0,
        "cve_id": "CVE-2011-2523",
        "description": "vsftpd 2.3.4 backdoor command execution",
    },
    "proftpd 1.3.3": {
        "module_path": "exploit/unix/ftp/proftpd_133c_backdoor",
        "payload_hint": "cmd/unix/interact",
        "cvss": 10.0,
        "cve_id": None,
        "description": "ProFTPD 1.3.3c backdoor",
    },
    # SSH
    "openssh 7.2": {
        "module_path": "auxiliary/scanner/ssh/ssh_login",
        "payload_hint": None,
        "cvss": 5.0,
        "cve_id": "CVE-2016-6515",
        "description": "OpenSSH 7.2p2 user enumeration / auth bypass",
    },
    # SMB / Windows
    "smb": {
        "module_path": "exploit/windows/smb/ms17_010_eternalblue",
        "payload_hint": "windows/x64/meterpreter/reverse_tcp",
        "cvss": 9.3,
        "cve_id": "CVE-2017-0144",
        "description": "EternalBlue SMB remote code execution",
    },
    "microsoft-ds": {
        "module_path": "exploit/windows/smb/ms17_010_eternalblue",
        "payload_hint": "windows/x64/meterpreter/reverse_tcp",
        "cvss": 9.3,
        "cve_id": "CVE-2017-0144",
        "description": "EternalBlue SMB remote code execution",
    },
    # Samba
    "samba 3.": {
        "module_path": "exploit/multi/samba/usermap_script",
        "payload_hint": "cmd/unix/interact",
        "cvss": 10.0,
        "cve_id": "CVE-2007-2447",
        "description": "Samba 3.x username map script RCE",
    },
    # HTTP / Web
    "apache 2.4.49": {
        "module_path": "exploit/multi/http/apache_normalize_path_rce",
        "payload_hint": "linux/x64/meterpreter/reverse_tcp",
        "cvss": 9.8,
        "cve_id": "CVE-2021-41773",
        "description": "Apache 2.4.49 path traversal and RCE",
    },
    "struts": {
        "module_path": "exploit/multi/http/struts2_content_type_ognl",
        "payload_hint": "linux/x64/meterpreter/reverse_tcp",
        "cvss": 10.0,
        "cve_id": "CVE-2017-5638",
        "description": "Apache Struts2 Content-Type OGNL injection",
    },
    # MySQL
    "mysql": {
        "module_path": "exploit/multi/mysql/mysql_udf_payload",
        "payload_hint": "linux/x64/meterpreter/reverse_tcp",
        "cvss": 6.5,
        "cve_id": None,
        "description": "MySQL UDF dynamic library injection",
    },
    # Distcc
    "distccd": {
        "module_path": "exploit/unix/misc/distcc_exec",
        "payload_hint": "cmd/unix/reverse",
        "cvss": 9.3,
        "cve_id": "CVE-2004-2687",
        "description": "DistCC Daemon command execution",
    },
    # IRC (UnrealIRCd)
    "unreal ircd": {
        "module_path": "exploit/unix/irc/unreal_ircd_3281_backdoor",
        "payload_hint": "cmd/unix/reverse",
        "cvss": 10.0,
        "cve_id": "CVE-2010-2075",
        "description": "UnrealIRCd 3.2.8.1 backdoor",
    },
    # Shellshock
    "shellshock": {
        "module_path": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
        "payload_hint": "linux/x86/meterpreter/reverse_tcp",
        "cvss": 10.0,
        "cve_id": "CVE-2014-6271",
        "description": "Bash Shellshock environment variable injection",
    },
}

# CVE → Metasploit module quick lookup (supplement to Metasploit search)
CVE_MODULE_MAP: Dict[str, Dict[str, Any]] = {
    "CVE-2021-44228": {
        "module_path": "exploit/multi/http/log4shell_header_injection",
        "payload_hint": "java/meterpreter/reverse_tcp",
        "description": "Log4Shell JNDI injection",
    },
    "CVE-2021-41773": {
        "module_path": "exploit/multi/http/apache_normalize_path_rce",
        "payload_hint": "linux/x64/meterpreter/reverse_tcp",
        "description": "Apache 2.4.49 path traversal RCE",
    },
    "CVE-2017-0144": {
        "module_path": "exploit/windows/smb/ms17_010_eternalblue",
        "payload_hint": "windows/x64/meterpreter/reverse_tcp",
        "description": "EternalBlue",
    },
    "CVE-2017-5638": {
        "module_path": "exploit/multi/http/struts2_content_type_ognl",
        "payload_hint": "linux/x64/meterpreter/reverse_tcp",
        "description": "Apache Struts2 OGNL injection",
    },
    "CVE-2011-2523": {
        "module_path": "exploit/unix/ftp/vsftpd_234_backdoor",
        "payload_hint": "cmd/unix/interact",
        "description": "vsftpd 2.3.4 backdoor",
    },
    "CVE-2007-2447": {
        "module_path": "exploit/multi/samba/usermap_script",
        "payload_hint": "cmd/unix/interact",
        "description": "Samba usermap_script RCE",
    },
    "CVE-2004-2687": {
        "module_path": "exploit/unix/misc/distcc_exec",
        "payload_hint": "cmd/unix/reverse",
        "description": "DistCC Daemon RCE",
    },
    "CVE-2010-2075": {
        "module_path": "exploit/unix/irc/unreal_ircd_3281_backdoor",
        "payload_hint": "cmd/unix/reverse",
        "description": "UnrealIRCd backdoor",
    },
}

# Risk level assigned based on CVSS score ranges
def _cvss_to_risk(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


class ReconToExploitMapper:
    """
    Converts port scan and vulnerability scan results into a ranked list
    of ExploitCandidates suitable for automated exploitation.
    """

    def __init__(self, msf_server_url: str = "http://kali-tools:8003"):
        self._msf_url = msf_server_url

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_exploit_candidates(
        self,
        port_scan_result: List[Dict[str, Any]],
        nuclei_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> List[ExploitCandidate]:
        """
        Build a ranked list of ExploitCandidates from recon data.

        Parameters
        ----------
        port_scan_result : list of dicts
            Each dict must have at minimum:
              ``port`` (int), ``service`` (str, optional), ``version`` (str, optional)
        nuclei_findings : list of dicts, optional
            Nuclei output with at minimum:
              ``template_id`` (str), ``severity`` (str), ``matched_at`` (str)
              ``cve_id`` (str, optional), ``cvss_score`` (float, optional)

        Returns
        -------
        List[ExploitCandidate]
            Sorted descending by ``final_score``.
        """
        candidates: List[ExploitCandidate] = []

        # --- Phase 1: map port/service → known exploits ---
        candidates.extend(self._candidates_from_ports(port_scan_result))

        # --- Phase 2: map Nuclei CVEs → Metasploit modules ---
        if nuclei_findings:
            candidates.extend(self._candidates_from_nuclei(nuclei_findings))

        # Deduplicate by module_path (keep highest score)
        candidates = self._deduplicate(candidates)

        # Sort by final_score descending
        candidates.sort(key=lambda c: c.final_score, reverse=True)

        logger.info(
            "ReconToExploitMapper: generated %d exploit candidates", len(candidates)
        )
        return candidates

    def map_service_to_module(
        self, service: str, version: str = ""
    ) -> Optional[Dict[str, Any]]:
        """
        Look up a service name + optional version in SERVICE_EXPLOIT_MAP.

        Returns the matching entry dict or None.
        """
        key = f"{service.lower()} {version.lower()}".strip()

        # Try progressively shorter keys
        for map_key, entry in SERVICE_EXPLOIT_MAP.items():
            if key.startswith(map_key) or service.lower() == map_key:
                return entry
        return None

    def map_cve_to_module(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Return the static CVE→module entry, or None."""
        return CVE_MODULE_MAP.get(cve_id.upper())

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _candidates_from_ports(
        self, ports: List[Dict[str, Any]]
    ) -> List[ExploitCandidate]:
        candidates: List[ExploitCandidate] = []

        for port_info in ports:
            port = port_info.get("port", 0)
            service = port_info.get("service", "")
            version = port_info.get("version", "")

            entry = self.map_service_to_module(service, version)
            if entry is None:
                continue

            cvss = float(entry.get("cvss", 5.0))
            msf_available = bool(entry.get("module_path"))
            final_score = min(cvss + (2.0 if msf_available else 0.0), 10.0)

            candidates.append(
                ExploitCandidate(
                    cve_id=entry.get("cve_id"),
                    service=service or "unknown",
                    port=port,
                    module_path=entry.get("module_path"),
                    payload_hint=entry.get("payload_hint"),
                    base_score=cvss,
                    msf_available=msf_available,
                    final_score=final_score,
                    source="service_map",
                    risk_level=_cvss_to_risk(cvss),
                    description=entry.get("description", ""),
                )
            )

        return candidates

    def _candidates_from_nuclei(
        self, findings: List[Dict[str, Any]]
    ) -> List[ExploitCandidate]:
        candidates: List[ExploitCandidate] = []

        for finding in findings:
            cve_id = finding.get("cve_id") or self._extract_cve(
                finding.get("template_id", "")
            )
            if not cve_id:
                continue

            cvss = float(finding.get("cvss_score", 0.0))
            if cvss == 0.0:
                cvss = self._severity_to_cvss(finding.get("severity", "medium"))

            module_entry = self.map_cve_to_module(cve_id)
            msf_available = module_entry is not None
            module_path = module_entry.get("module_path") if module_entry else None
            payload_hint = module_entry.get("payload_hint") if module_entry else None
            description = (
                module_entry.get("description", "")
                if module_entry
                else finding.get("template_name", "")
            )

            final_score = min(cvss + (2.0 if msf_available else 0.0), 10.0)

            # Best-effort port from matched_at URL
            port = self._extract_port(finding.get("matched_at", ""))

            candidates.append(
                ExploitCandidate(
                    cve_id=cve_id,
                    service=finding.get("service", "http"),
                    port=port,
                    module_path=module_path,
                    payload_hint=payload_hint,
                    base_score=cvss,
                    msf_available=msf_available,
                    final_score=final_score,
                    source="nuclei",
                    risk_level=_cvss_to_risk(cvss),
                    description=description,
                )
            )

        return candidates

    @staticmethod
    def _deduplicate(
        candidates: List[ExploitCandidate],
    ) -> List[ExploitCandidate]:
        """Keep only the highest-scoring candidate per module_path."""
        seen: Dict[Optional[str], ExploitCandidate] = {}
        for c in candidates:
            key = c.module_path or f"no_module_{c.cve_id}_{c.port}"
            existing = seen.get(key)
            if existing is None or c.final_score > existing.final_score:
                seen[key] = c
        return list(seen.values())

    @staticmethod
    def _extract_cve(template_id: str) -> Optional[str]:
        """Extract a CVE ID from a Nuclei template ID like 'cve-2021-44228'."""
        match = re.search(r"CVE[-_]\d{4}[-_]\d+", template_id, re.IGNORECASE)
        if match:
            return match.group(0).upper().replace("_", "-")
        return None

    @staticmethod
    def _severity_to_cvss(severity: str) -> float:
        mapping = {
            "critical": 9.5,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
            "info": 0.0,
        }
        return mapping.get(severity.lower(), 5.0)

    @staticmethod
    def _extract_port(matched_at: str) -> int:
        """Try to extract the port number from a URL string."""
        match = re.search(r":(\d{1,5})(?:/|$)", matched_at)
        if match:
            return int(match.group(1))
        if matched_at.startswith("https"):
            return 443
        if matched_at.startswith("http"):
            return 80
        return 0
