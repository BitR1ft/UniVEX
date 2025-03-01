"""
Attack Path Router System

Routes user intent to appropriate attack strategies with classification
and approval controls for the AI penetration testing framework.
primary routing engine, with keyword matching as a fallback.  The classifier
mode is controlled by the ``CLASSIFIER_MODE`` environment variable:
  keyword  (default) — fast regex matching, no dependencies
  ml       — scikit-learn multi-label SVM
  llm      — GPT-4 structured output
  hybrid   — ML + LLM merged (recommended for production)

Respects AUTO_APPROVE_RISK_LEVEL environment variable to
automatically approve attack categories below the configured risk threshold.
  AUTO_APPROVE_RISK_LEVEL=none    — all dangerous categories require approval
  AUTO_APPROVE_RISK_LEVEL=low     — only approve low-risk attacks
  AUTO_APPROVE_RISK_LEVEL=medium  — approve medium + low risk
  AUTO_APPROVE_RISK_LEVEL=high    — approve high + below (HTB lab mode)
  AUTO_APPROVE_RISK_LEVEL=critical— approve everything (dangerous!)
"""

import os
from enum import Enum
from typing import Dict, List
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Risk ordering for AUTO_APPROVE_RISK_LEVEL
# ---------------------------------------------------------------------------

_RISK_ORDER = ["none", "low", "medium", "high", "critical"]


def _auto_approve_threshold() -> str:
    """Read AUTO_APPROVE_RISK_LEVEL env var (default: 'none')."""
    return os.environ.get("AUTO_APPROVE_RISK_LEVEL", "none").lower()


def _risk_is_auto_approved(risk_level: str) -> bool:
    """Return True if *risk_level* is within the configured auto-approve threshold."""
    threshold = _auto_approve_threshold()
    if threshold == "none":
        return False
    try:
        return _RISK_ORDER.index(risk_level) <= _RISK_ORDER.index(threshold)
    except ValueError:
        return False


class AttackCategory(str, Enum):
    """Categories of attack paths available to the agent."""
    CVE_EXPLOITATION = "cve_exploitation"
    BRUTE_FORCE = "brute_force"
    WEB_APP_ATTACK = "web_app_attack"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    PASSWORD_SPRAY = "password_spray"
    SOCIAL_ENGINEERING = "social_engineering"
    NETWORK_PIVOT = "network_pivot"
    FILE_EXFILTRATION = "file_exfiltration"
    PERSISTENCE = "persistence"


class AttackPathRouter:
    """
    Routes user intent to attack strategies with classification and approval controls.
    """

    ATTACK_KEYWORDS: Dict[AttackCategory, List[str]] = {
        AttackCategory.CVE_EXPLOITATION: [
            "cve", "exploit", "vulnerability", "advisory", "patch",
            "remote code execution", "rce", "zero-day",
        ],
        AttackCategory.BRUTE_FORCE: [
            "brute force", "brute-force", "crack", "wordlist",
            "dictionary attack", "hydra", "john",
        ],
        AttackCategory.WEB_APP_ATTACK: [
            "sql injection", "sqli", "xss", "cross-site", "web app",
            "webapp", "csrf", "ssrf", "injection", "web application",
            "directory", "fuzz", "ffuf", "gobuster", "dirb", "dirbuster",
            "hidden", "path", "endpoint discovery",
            "idor", "insecure direct object", "access control", "broken access",
            "auth bypass", "authentication bypass", "session fixation",
            "session puzzling", "rate limit bypass", "privilege escalation web",
            "horizontal escalation", "vertical escalation", "role manipulation",
            "jwt", "json web token", "oauth", "oauth2", "token",
            "api key", "apikey", "secret leak", "token leak",
            "bearer token", "hmac", "rs256", "hs256", "alg none",
            "redirect uri", "scope escalation", "pkce",
        ],
        AttackCategory.PRIVILEGE_ESCALATION: [
            "privilege escalation", "privesc", "priv esc", "root",
            "admin", "sudo", "suid", "escalate",
        ],
        AttackCategory.LATERAL_MOVEMENT: [
            "lateral movement", "lateral", "move laterally",
            "psexec", "wmi", "ssh hop", "spread",
        ],
        AttackCategory.PASSWORD_SPRAY: [
            "password spray", "spray", "credential stuffing",
            "default credentials", "common passwords",
        ],
        AttackCategory.SOCIAL_ENGINEERING: [
            "social engineering", "phishing", "spear phishing",
            "pretexting", "vishing", "smishing",
        ],
        AttackCategory.NETWORK_PIVOT: [
            "network pivot", "pivot", "tunnel", "port forward", "proxy",
            "socks", "chisel", "ligolo", "pivoting",
        ],
        AttackCategory.FILE_EXFILTRATION: [
            "exfiltrate", "exfiltration", "data theft", "steal",
            "extract data", "download files", "dump",
        ],
        AttackCategory.PERSISTENCE: [
            "persistence", "backdoor", "implant", "cron",
            "scheduled task", "registry", "startup", "persist",
        ],
    }

    _DANGEROUS_CATEGORIES = frozenset({
        AttackCategory.CVE_EXPLOITATION,
        AttackCategory.BRUTE_FORCE,
        AttackCategory.PRIVILEGE_ESCALATION,
        AttackCategory.LATERAL_MOVEMENT,
    })

    _TOOL_MAP: Dict[AttackCategory, List[str]] = {
        AttackCategory.CVE_EXPLOITATION: [
            "metasploit", "searchsploit", "nuclei",
        ],
        AttackCategory.BRUTE_FORCE: [
            "hydra", "hash_crack", "john", "hashcat",
        ],
        AttackCategory.WEB_APP_ATTACK: [
            # primary tool names expected by tests
            "sqlmap", "nuclei", "ffuf",
            # detailed tool adapter names
            "sqlmap_detect", "sqlmap_databases", "sqlmap_dump",
            "nikto_scan", "wpscan", "curl",
            "ffuf_fuzz_dirs", "ffuf_fuzz_files", "ffuf_fuzz_params",
            "reflected_xss", "stored_xss", "dom_xss",
            "csrf_detect", "csrf_exploit", "ssrf_probe", "ssrf_blind", "open_redirect",
            "idor_detect", "idor_exploit", "privilege_escalation_web",
            "auth_bypass", "session_puzzling", "rate_limit_bypass",
            "jwt_analyze", "jwt_brute_force", "jwt_forge",
            "oauth_flow", "oauth_token_leak", "api_key_leak",
        ],
        AttackCategory.PRIVILEGE_ESCALATION: [
            # primary tool names expected by tests
            "linpeas", "metasploit",
            # detailed tool adapter names
            "linpeas_scan", "winpeas_scan", "capture_flags",
        ],
        AttackCategory.LATERAL_MOVEMENT: [
            # primary tool names expected by tests
            "metasploit", "impacket",
            # detailed tool adapter names
            "crackmapexec_smb", "pass_the_hash",
            "enum4linux_scan", "ldap_enum", "ssh_login",
        ],
        AttackCategory.PASSWORD_SPRAY: [
            "crackmapexec_smb", "kerbrute_userenum",
            "credential_reuse", "hydra",
        ],
        AttackCategory.SOCIAL_ENGINEERING: [
            "gophish", "set",
        ],
        AttackCategory.NETWORK_PIVOT: [
            "chisel", "ligolo", "ssh_login", "metasploit",
        ],
        AttackCategory.FILE_EXFILTRATION: [
            "capture_flags", "curl", "ssh_key_extract",
        ],
        AttackCategory.PERSISTENCE: [
            "metasploit", "cron", "systemctl",
        ],
    }

    _RISK_LEVELS: Dict[AttackCategory, str] = {
        AttackCategory.CVE_EXPLOITATION: "critical",
        AttackCategory.BRUTE_FORCE: "high",
        AttackCategory.WEB_APP_ATTACK: "high",
        AttackCategory.PRIVILEGE_ESCALATION: "critical",
        AttackCategory.LATERAL_MOVEMENT: "critical",
        AttackCategory.PASSWORD_SPRAY: "medium",
        AttackCategory.SOCIAL_ENGINEERING: "medium",
        AttackCategory.NETWORK_PIVOT: "high",
        AttackCategory.FILE_EXFILTRATION: "high",
        AttackCategory.PERSISTENCE: "critical",
    }

    def __init__(self):
        """Initialize the attack path router with ML/LLM classifier."""
        from app.agent.classification.intent_classifier import IntentClassifier
        self._classifier = IntentClassifier()
        logger.info(
            "AttackPathRouter initialized with classifier mode: %s",
            os.environ.get("CLASSIFIER_MODE", "keyword"),
        )

    def classify_intent(self, user_message: str) -> AttackCategory:
        """
        Classify user intent into an attack category.

        Uses the configured classifier (keyword/ML/LLM/hybrid) to determine
        the most likely attack category for the given message.

        Args:
            user_message: Raw message from the user

        Returns:
            Matched AttackCategory
        """
        result = self.classify_intent_with_confidence(user_message)
        return result["category"]

    def classify_intent_with_confidence(self, user_message: str) -> Dict:
        """
        Classify user intent with confidence scoring and ranked alternatives.

        Args:
            user_message: Raw message from the user

        Returns:
            Dict with 'category', 'confidence' (0.0-1.0), 'alternatives', and 'all_categories'
        """
        clf_result = self._classifier.classify(user_message)

        # Map top category string to AttackCategory enum
        best_category = self._str_to_category(clf_result.top_category)
        confidence = clf_result.scores.get(clf_result.top_category, 0.0)

        # Build alternatives list from all matched categories
        alternatives = []
        for cat_str in clf_result.categories:
            if cat_str != clf_result.top_category:
                alternatives.append({
                    "category": cat_str,
                    "score": clf_result.scores.get(cat_str, 0.0),
                })

        logger.info(
            "Classified intent as '%s' (confidence=%.2f, method=%s, alternatives=%d)",
            best_category.value,
            confidence,
            clf_result.method,
            len(alternatives),
        )

        return {
            "category": best_category,
            "confidence": confidence,
            "score": confidence,
            "alternatives": alternatives,
            "all_categories": [self._str_to_category(c) for c in clf_result.categories],
            "method": clf_result.method,
        }

    @staticmethod
    def _str_to_category(category_str: str) -> "AttackCategory":
        """Convert a category string to AttackCategory enum, with fallback."""
        try:
            return AttackCategory(category_str)
        except ValueError:
            return AttackCategory.WEB_APP_ATTACK

    def get_attack_plan(
        self, category: AttackCategory, target_info: Dict
    ) -> Dict:
        """
        Generate an attack plan for the given category and target.

        Args:
            category: The classified attack category
            target_info: Dictionary with target details (host, port, service, etc.)

        Returns:
            Attack plan with steps, required tools, and risk level
        """
        steps = self._build_steps(category, target_info)
        tools = self.get_required_tools(category)
        risk_level = self._RISK_LEVELS[category]

        plan = {
            "category": category.value,
            "risk_level": risk_level,
            "requires_approval": self.requires_approval(category),
            "target": target_info,
            "tools": tools,
            "steps": steps,
        }

        logger.info(
            f"Generated attack plan for '{category.value}' "
            f"with {len(steps)} steps (risk={risk_level})"
        )
        return plan

    def get_required_tools(self, category: AttackCategory) -> List[str]:
        """
        Return the list of tool names required for an attack category.

        Args:
            category: The attack category

        Returns:
            List of tool name strings
        """
        return list(self._TOOL_MAP.get(category, []))

    def requires_approval(self, category: AttackCategory) -> bool:
        """
        Check whether an attack category requires human approval before execution.

        Respects the ``AUTO_APPROVE_RISK_LEVEL`` environment variable:
        if the category's risk level is at or below the configured threshold,
        approval is waived automatically (useful for HTB lab environments).

        Args:
            category: The attack category

        Returns:
            True if the category is considered dangerous and approval is needed
        """
        if category not in self._DANGEROUS_CATEGORIES:
            return False
        risk_level = self._RISK_LEVELS.get(category, "high")
        if _risk_is_auto_approved(risk_level):
            logger.info(
                "Auto-approving '%s' (risk=%s, threshold=%s)",
                category.value,
                risk_level,
                _auto_approve_threshold(),
            )
            return False
        return True

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_steps(
        category: AttackCategory, target_info: Dict
    ) -> List[Dict]:
        """
        Build ordered attack steps for a category.

        Args:
            category: The attack category
            target_info: Dictionary with target details

        Returns:
            Ordered list of step dictionaries
        """
        host = target_info.get("host", "unknown")

        step_templates: Dict[AttackCategory, List[Dict]] = {
            AttackCategory.CVE_EXPLOITATION: [
                {"id": 1, "action": "identify_cve", "description": f"Search for known CVEs on {host}"},
                {"id": 2, "action": "select_exploit", "description": "Select appropriate exploit module"},
                {"id": 3, "action": "configure_payload", "description": "Configure exploit payload and options"},
                {"id": 4, "action": "execute_exploit", "description": "Execute exploit against target"},
                {"id": 5, "action": "verify_access", "description": "Verify successful exploitation"},
            ],
            AttackCategory.BRUTE_FORCE: [
                {"id": 1, "action": "enumerate_service", "description": f"Enumerate authentication service on {host}"},
                {"id": 2, "action": "select_wordlist", "description": "Select appropriate wordlist"},
                {"id": 3, "action": "launch_attack", "description": "Launch brute-force attack"},
                {"id": 4, "action": "validate_credentials", "description": "Validate discovered credentials"},
            ],
            AttackCategory.WEB_APP_ATTACK: [
                {"id": 1, "action": "discover_endpoints", "description": f"Discover web endpoints on {host}"},
                {"id": 2, "action": "identify_parameters", "description": "Identify injectable parameters"},
                {"id": 3, "action": "test_injection", "description": "Test for injection vulnerabilities"},
                {"id": 4, "action": "exploit_vulnerability", "description": "Exploit discovered vulnerability"},
            ],
            AttackCategory.PRIVILEGE_ESCALATION: [
                {"id": 1, "action": "enumerate_system", "description": f"Enumerate system configuration on {host}"},
                {"id": 2, "action": "find_vectors", "description": "Identify privilege escalation vectors"},
                {"id": 3, "action": "exploit_vector", "description": "Exploit escalation vector"},
                {"id": 4, "action": "verify_privileges", "description": "Verify elevated privileges"},
            ],
            AttackCategory.LATERAL_MOVEMENT: [
                {"id": 1, "action": "discover_targets", "description": "Discover reachable hosts from current position"},
                {"id": 2, "action": "harvest_credentials", "description": "Harvest credentials for lateral movement"},
                {"id": 3, "action": "move_laterally", "description": "Move to adjacent host"},
                {"id": 4, "action": "establish_foothold", "description": "Establish foothold on new host"},
            ],
            AttackCategory.PASSWORD_SPRAY: [
                {"id": 1, "action": "enumerate_users", "description": f"Enumerate valid usernames on {host}"},
                {"id": 2, "action": "select_passwords", "description": "Select common passwords for spraying"},
                {"id": 3, "action": "execute_spray", "description": "Execute password spray attack"},
                {"id": 4, "action": "validate_access", "description": "Validate successful logins"},
            ],
            AttackCategory.SOCIAL_ENGINEERING: [
                {"id": 1, "action": "gather_osint", "description": f"Gather OSINT on target organization at {host}"},
                {"id": 2, "action": "craft_pretext", "description": "Craft social engineering pretext"},
                {"id": 3, "action": "deliver_payload", "description": "Deliver phishing payload"},
                {"id": 4, "action": "monitor_response", "description": "Monitor for target interaction"},
            ],
            AttackCategory.NETWORK_PIVOT: [
                {"id": 1, "action": "map_network", "description": f"Map internal network from {host}"},
                {"id": 2, "action": "setup_tunnel", "description": "Set up network tunnel or proxy"},
                {"id": 3, "action": "route_traffic", "description": "Route traffic through pivot"},
                {"id": 4, "action": "verify_connectivity", "description": "Verify connectivity to target subnet"},
            ],
            AttackCategory.FILE_EXFILTRATION: [
                {"id": 1, "action": "identify_data", "description": f"Identify valuable data on {host}"},
                {"id": 2, "action": "stage_data", "description": "Stage data for exfiltration"},
                {"id": 3, "action": "select_channel", "description": "Select exfiltration channel"},
                {"id": 4, "action": "exfiltrate", "description": "Exfiltrate data to collection point"},
            ],
            AttackCategory.PERSISTENCE: [
                {"id": 1, "action": "select_mechanism", "description": f"Select persistence mechanism for {host}"},
                {"id": 2, "action": "deploy_implant", "description": "Deploy persistence implant"},
                {"id": 3, "action": "configure_callback", "description": "Configure callback channel"},
                {"id": 4, "action": "verify_persistence", "description": "Verify persistence survives reboot"},
            ],
        }

        return step_templates.get(category, [])
