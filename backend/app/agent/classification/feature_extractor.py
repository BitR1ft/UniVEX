"""
Feature Extractor

Converts raw attack scenario text into feature vectors for the ML classifier.

Two feature strategies:
1. TF-IDF bag-of-words (lightweight, no GPU required)
2. sentence-transformers semantic embeddings (higher accuracy, optional)

The extractor also pulls structured features:
  - service names and version numbers
  - port numbers
  - CVE IDs
  - attack technique keywords (MITRE ATT&CK)

These structured features are concatenated with the text embedding for
the final feature vector fed to the SVM / Random Forest classifier.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known attack technique keywords mapped to MITRE ATT&CK categories
# ---------------------------------------------------------------------------

TECHNIQUE_KEYWORDS: Dict[str, List[str]] = {
    "cve_exploitation": [
        "cve", "exploit", "rce", "remote code execution", "vulnerability",
        "shellshock", "heartbleed", "eternalblue", "log4j", "log4shell",
        "spring4shell", "zerologon", "zero-day", "0day",
        "advisory", "patch", "unpatched", "proof of concept", "poc",
        "vsftpd", "proftpd", "samba cve", "searchsploit", "metasploit module",
    ],
    "brute_force": [
        "brute force", "brute-force", "bruteforce", "dictionary attack",
        "wordlist", "rockyou", "crack hash", "john the ripper",
        "hashcat", "hydra", "medusa", "hash cracking",
        "crack the password", "crack password", "password crack",
    ],
    "web_app_attack": [
        "sqli", "sql injection", "xss", "cross-site scripting", "csrf", "ssrf",
        "lfi", "rfi", "ssti", "xxe", "command injection",
        "ffuf", "gobuster", "dirb", "nikto", "wpscan", "feroxbuster",
        "directory fuzz", "fuzz web", "admin panel", "web shell upload",
    ],
    "privilege_escalation": [
        "privesc", "priv esc", "privilege escalation", "escalate privileges",
        "suid binary", "sudo exploit", "linpeas", "winpeas", "getsystem",
        "gtfobins", "uac bypass", "token impersonation", "juicy potato",
        "printspoofer", "alwaysinstallelevated",
    ],
    "lateral_movement": [
        "lateral movement", "move laterally", "lateral to",
        "psexec", "wmiexec", "ssh hop", "kerberoast", "asreproast",
        "pass the hash", "pth", "impacket wmi", "crackmapexec smb",
        "bloodhound", "sharphound", "ldap enum", "active directory attack",
        "domain controller", "silver ticket", "golden ticket",
        "dcsync", "ntlm relay", "enum4linux",
    ],
    "password_spray": [
        "password spray", "spraying passwords", "credential stuffing",
        "default credentials", "kerbrute userenum", "o365 spray",
    ],
    "social_engineering": [
        "phishing", "spear phishing", "pretexting", "vishing",
        "gophish", "social engineering",
    ],
    "network_pivot": [
        "network pivot", "chisel tunnel", "ligolo", "socat forward",
        "socks proxy", "proxychains", "ssh tunnel", "port forward",
        "portfwd", "double pivot",
    ],
    "file_exfiltration": [
        "exfiltrate", "data exfil", "dump lsass", "hashdump",
        "shadow file", "sam database", "secretsdump", "mimikatz",
        "capture flag", "root.txt", "user.txt",
    ],
    "persistence": [
        "for persistence", "install a backdoor", "install backdoor",
        "web shell install", "cron job backdoor", "scheduled task",
        "registry persistence", "startup folder", "implant install",
        "authorized_keys", "systemd service backdoor",
    ],
}

# Port-to-category hints
PORT_CATEGORY_MAP: Dict[int, str] = {
    21: "cve_exploitation",   # FTP
    22: "brute_force",        # SSH
    23: "brute_force",        # Telnet
    25: "social_engineering", # SMTP
    80: "web_app_attack",     # HTTP
    110: "brute_force",       # POP3
    139: "lateral_movement",  # NetBIOS
    143: "brute_force",       # IMAP
    389: "lateral_movement",  # LDAP
    443: "web_app_attack",    # HTTPS
    445: "lateral_movement",  # SMB
    1433: "web_app_attack",   # MSSQL
    1521: "web_app_attack",   # Oracle
    3306: "web_app_attack",   # MySQL
    3389: "brute_force",      # RDP
    5432: "web_app_attack",   # PostgreSQL
    5985: "lateral_movement", # WinRM
    6379: "cve_exploitation", # Redis
    8080: "web_app_attack",   # HTTP alt
    8443: "web_app_attack",   # HTTPS alt
    27017: "cve_exploitation",# MongoDB
    88: "lateral_movement",   # Kerberos
    464: "lateral_movement",  # Kerberos kpasswd
    636: "lateral_movement",  # LDAPS
}


class FeatureExtractor:
    """
    Converts attack scenario text into feature vectors.

    Features
    --------
    1. TF-IDF n-gram features (1-gram and 2-gram, max 5000 features)
    2. Structured keyword presence features (one-hot per category)
    3. CVE count feature
    4. Port number features (presence of known port numbers)
    """

    def __init__(self, use_tfidf: bool = True, use_sentence_transformers: bool = False):
        self._use_tfidf = use_tfidf
        self._use_st = use_sentence_transformers
        self._tfidf: Any = None
        self._st_model: Any = None
        self._categories = sorted(TECHNIQUE_KEYWORDS.keys())
        self._ports = sorted(PORT_CATEGORY_MAP.keys())

    # ------------------------------------------------------------------
    # Initialize text vectorizers (must be called before transform())
    # ------------------------------------------------------------------

    def fit(self, texts: List[str]) -> "FeatureExtractor":
        """Fit the TF-IDF vectorizer on the training corpus."""
        if self._use_tfidf:
            from sklearn.feature_extraction.text import TfidfVectorizer

            self._tfidf = TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=5000,
                sublinear_tf=True,
                strip_accents="unicode",
                analyzer="word",
                token_pattern=r"(?u)\b[a-zA-Z0-9_\-\.]{2,}\b",
            )
            self._tfidf.fit(texts)
            logger.info("TF-IDF fitted on %d documents", len(texts))

        if self._use_st:
            try:
                from sentence_transformers import SentenceTransformer

                self._st_model = SentenceTransformer("all-MiniLM-L6-v2")
                logger.info("Sentence-transformers model loaded")
            except ImportError:
                logger.warning("sentence-transformers not installed; falling back to TF-IDF only")
                self._use_st = False

        return self

    def transform(self, texts: List[str]) -> np.ndarray:
        """
        Transform a list of texts into a 2D feature matrix.

        Returns shape (n_samples, n_features).
        """
        parts: List[np.ndarray] = []

        # --- TF-IDF ---
        if self._use_tfidf and self._tfidf is not None:
            tfidf_mat = self._tfidf.transform(texts).toarray()
            parts.append(tfidf_mat)

        # --- sentence-transformers ---
        if self._use_st and self._st_model is not None:
            embeddings = self._st_model.encode(texts, show_progress_bar=False)
            parts.append(embeddings)

        # --- Structured keyword features ---
        kw_feats = self._keyword_features(texts)
        parts.append(kw_feats)

        if not parts:
            raise RuntimeError("No feature extractor is configured. Call fit() first.")

        return np.hstack(parts)

    def fit_transform(self, texts: List[str]) -> np.ndarray:
        self.fit(texts)
        return self.transform(texts)

    # ------------------------------------------------------------------
    # Structured feature helpers
    # ------------------------------------------------------------------

    def _keyword_features(self, texts: List[str]) -> np.ndarray:
        """One-hot keyword features + CVE count + port presence."""
        n = len(texts)
        n_cats = len(self._categories)
        n_ports = len(self._ports)

        # category keyword hits + cve count + port bits
        matrix = np.zeros((n, n_cats + 1 + n_ports), dtype=np.float32)

        for i, text in enumerate(texts):
            lower = text.lower()

            for j, cat in enumerate(self._categories):
                for kw in TECHNIQUE_KEYWORDS[cat]:
                    if kw in lower:
                        matrix[i, j] = 1.0
                        break

            cve_count = len(re.findall(r"cve-\d{4}-\d{4,7}", lower))
            matrix[i, n_cats] = float(min(cve_count, 5))  # cap at 5

            for k, port in enumerate(self._ports):
                if re.search(rf"\b{port}\b", lower):
                    matrix[i, n_cats + 1 + k] = 1.0

        return matrix

    # ------------------------------------------------------------------
    # Convenience: extract structured entities from a single text
    # ------------------------------------------------------------------

    @staticmethod
    def extract_entities(text: str) -> Dict[str, List[str]]:
        """
        Extract structured entities from a text description.

        Returns
        -------
        dict with keys: cve_ids, ports, services, techniques
        """
        lower = text.lower()

        cve_ids = re.findall(r"cve-\d{4}-\d{4,7}", lower)

        port_matches = [int(m) for m in re.findall(r"\b(\d{2,5})\b", lower) if int(m) in PORT_CATEGORY_MAP]

        service_names = []
        known_services = [
            "ssh", "ftp", "http", "https", "smb", "rdp", "ldap",
            "mysql", "mssql", "postgresql", "redis", "mongodb",
            "apache", "nginx", "iis", "tomcat", "vsftpd", "proftpd",
            "samba", "openssh", "jenkins", "jboss", "weblogic",
        ]
        for svc in known_services:
            if svc in lower:
                service_names.append(svc)

        techniques = []
        for cat, keywords in TECHNIQUE_KEYWORDS.items():
            for kw in keywords:
                if kw in lower:
                    techniques.append(kw)
                    break

        return {
            "cve_ids": list(dict.fromkeys(cve_ids)),
            "ports": list(dict.fromkeys(port_matches)),
            "services": list(dict.fromkeys(service_names)),
            "techniques": list(dict.fromkeys(techniques)),
        }
