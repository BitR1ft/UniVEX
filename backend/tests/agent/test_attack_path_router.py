"""Tests for AttackPathRouter - attack intent classification and planning."""

import pytest
from app.agent.attack_path_router import AttackPathRouter, AttackCategory


class TestClassifyIntent:
    """Test AttackPathRouter.classify_intent() for each attack category."""

    def setup_method(self):
        """Create a router instance for each test."""
        self.router = AttackPathRouter()

    def test_classify_cve_exploitation(self):
        """Test classification of CVE exploitation messages."""
        result = self.router.classify_intent("Exploit CVE-2021-44228 on the target")
        assert result == AttackCategory.CVE_EXPLOITATION

    def test_classify_cve_with_rce_keyword(self):
        """Test classification with remote code execution keyword."""
        result = self.router.classify_intent("Find a remote code execution vulnerability")
        assert result == AttackCategory.CVE_EXPLOITATION

    def test_classify_brute_force(self):
        """Test classification of brute force messages."""
        result = self.router.classify_intent("Run a brute force attack against SSH")
        assert result == AttackCategory.BRUTE_FORCE

    def test_classify_brute_force_with_wordlist(self):
        """Test classification with wordlist keyword."""
        result = self.router.classify_intent("Use a wordlist to crack the password")
        assert result == AttackCategory.BRUTE_FORCE

    def test_classify_web_app_attack_sqli(self):
        """Test classification of SQL injection messages."""
        result = self.router.classify_intent("Test for sql injection on the login form")
        assert result == AttackCategory.WEB_APP_ATTACK

    def test_classify_web_app_attack_xss(self):
        """Test classification of XSS messages."""
        result = self.router.classify_intent("Try a cross-site scripting attack on the search page")
        assert result == AttackCategory.WEB_APP_ATTACK

    def test_classify_privilege_escalation(self):
        """Test classification of privilege escalation messages."""
        result = self.router.classify_intent("Attempt privilege escalation to get root")
        assert result == AttackCategory.PRIVILEGE_ESCALATION

    def test_classify_lateral_movement(self):
        """Test classification of lateral movement messages."""
        result = self.router.classify_intent("Move laterally to other hosts using psexec")
        assert result == AttackCategory.LATERAL_MOVEMENT

    def test_classify_password_spray(self):
        """Test classification of password spray messages."""
        result = self.router.classify_intent("Execute a password spray attack with common passwords")
        assert result == AttackCategory.PASSWORD_SPRAY

    def test_classify_social_engineering(self):
        """Test classification of social engineering messages."""
        result = self.router.classify_intent("Send a phishing email to the target")
        assert result == AttackCategory.SOCIAL_ENGINEERING

    def test_classify_network_pivot(self):
        """Test classification of network pivot messages."""
        result = self.router.classify_intent("Set up a network pivot using chisel tunnel")
        assert result == AttackCategory.NETWORK_PIVOT

    def test_classify_file_exfiltration(self):
        """Test classification of file exfiltration messages."""
        result = self.router.classify_intent("Exfiltrate data from the compromised host")
        assert result == AttackCategory.FILE_EXFILTRATION

    def test_classify_persistence(self):
        """Test classification of persistence messages."""
        result = self.router.classify_intent("Install a backdoor for persistence on the server")
        assert result == AttackCategory.PERSISTENCE

    def test_classify_defaults_to_web_app_attack(self):
        """Test that unrecognised input defaults to WEB_APP_ATTACK."""
        result = self.router.classify_intent("Do something random with no matching keywords")
        assert result == AttackCategory.WEB_APP_ATTACK

    def test_classify_empty_string_defaults(self):
        """Test that an empty string defaults to WEB_APP_ATTACK."""
        result = self.router.classify_intent("")
        assert result == AttackCategory.WEB_APP_ATTACK

    def test_classify_case_insensitive(self):
        """Test that classification is case-insensitive."""
        result = self.router.classify_intent("BRUTE FORCE the SSH server")
        assert result == AttackCategory.BRUTE_FORCE


class TestGetAttackPlan:
    """Test AttackPathRouter.get_attack_plan()."""

    def setup_method(self):
        self.router = AttackPathRouter()
        self.target_info = {"host": "192.168.1.100", "port": 22}

    def test_plan_has_expected_fields(self):
        """Test that the plan contains all expected top-level fields."""
        plan = self.router.get_attack_plan(AttackCategory.CVE_EXPLOITATION, self.target_info)
        assert "category" in plan
        assert "risk_level" in plan
        assert "requires_approval" in plan
        assert "target" in plan
        assert "tools" in plan
        assert "steps" in plan

    def test_plan_category_matches(self):
        """Test that plan category matches the requested category."""
        plan = self.router.get_attack_plan(AttackCategory.BRUTE_FORCE, self.target_info)
        assert plan["category"] == "brute_force"

    def test_plan_includes_target(self):
        """Test that plan includes target information."""
        plan = self.router.get_attack_plan(AttackCategory.WEB_APP_ATTACK, self.target_info)
        assert plan["target"] == self.target_info

    def test_plan_steps_are_non_empty(self):
        """Test that attack plan contains steps."""
        for category in AttackCategory:
            plan = self.router.get_attack_plan(category, self.target_info)
            assert len(plan["steps"]) > 0, f"No steps for {category.value}"

    def test_plan_risk_level_cve_exploitation(self):
        """Test risk level for CVE exploitation is critical."""
        plan = self.router.get_attack_plan(AttackCategory.CVE_EXPLOITATION, self.target_info)
        assert plan["risk_level"] == "critical"

    def test_plan_risk_level_brute_force(self):
        """Test risk level for brute force is high."""
        plan = self.router.get_attack_plan(AttackCategory.BRUTE_FORCE, self.target_info)
        assert plan["risk_level"] == "high"

    def test_plan_risk_level_web_app_attack(self):
        """Test risk level for web app attack is high."""
        plan = self.router.get_attack_plan(AttackCategory.WEB_APP_ATTACK, self.target_info)
        assert plan["risk_level"] == "high"

    def test_plan_risk_level_privilege_escalation(self):
        """Test risk level for privilege escalation is critical."""
        plan = self.router.get_attack_plan(AttackCategory.PRIVILEGE_ESCALATION, self.target_info)
        assert plan["risk_level"] == "critical"

    def test_plan_risk_level_password_spray(self):
        """Test risk level for password spray is medium."""
        plan = self.router.get_attack_plan(AttackCategory.PASSWORD_SPRAY, self.target_info)
        assert plan["risk_level"] == "medium"

    def test_plan_risk_level_persistence(self):
        """Test risk level for persistence is critical."""
        plan = self.router.get_attack_plan(AttackCategory.PERSISTENCE, self.target_info)
        assert plan["risk_level"] == "critical"


class TestGetRequiredTools:
    """Test AttackPathRouter.get_required_tools()."""

    def setup_method(self):
        self.router = AttackPathRouter()

    def test_cve_exploitation_tools(self):
        """Test tools for CVE exploitation."""
        tools = self.router.get_required_tools(AttackCategory.CVE_EXPLOITATION)
        assert "metasploit" in tools
        assert "searchsploit" in tools

    def test_brute_force_tools(self):
        """Test tools for brute force."""
        tools = self.router.get_required_tools(AttackCategory.BRUTE_FORCE)
        assert "hydra" in tools

    def test_web_app_attack_tools(self):
        """Test tools for web app attack."""
        tools = self.router.get_required_tools(AttackCategory.WEB_APP_ATTACK)
        assert "sqlmap" in tools
        assert "nuclei" in tools

    def test_privilege_escalation_tools(self):
        """Test tools for privilege escalation."""
        tools = self.router.get_required_tools(AttackCategory.PRIVILEGE_ESCALATION)
        assert "linpeas" in tools
        assert "metasploit" in tools

    def test_lateral_movement_tools(self):
        """Test tools for lateral movement."""
        tools = self.router.get_required_tools(AttackCategory.LATERAL_MOVEMENT)
        assert "metasploit" in tools
        assert "impacket" in tools

    def test_returns_list(self):
        """Test that result is always a list."""
        for category in AttackCategory:
            tools = self.router.get_required_tools(category)
            assert isinstance(tools, list)
            assert len(tools) > 0


class TestRequiresApproval:
    """Test AttackPathRouter.requires_approval()."""

    def setup_method(self):
        self.router = AttackPathRouter()

    def test_cve_exploitation_requires_approval(self):
        """Test that CVE exploitation requires approval."""
        assert self.router.requires_approval(AttackCategory.CVE_EXPLOITATION) is True

    def test_brute_force_requires_approval(self):
        """Test that brute force requires approval."""
        assert self.router.requires_approval(AttackCategory.BRUTE_FORCE) is True

    def test_privilege_escalation_requires_approval(self):
        """Test that privilege escalation requires approval."""
        assert self.router.requires_approval(AttackCategory.PRIVILEGE_ESCALATION) is True

    def test_lateral_movement_requires_approval(self):
        """Test that lateral movement requires approval."""
        assert self.router.requires_approval(AttackCategory.LATERAL_MOVEMENT) is True

    def test_web_app_attack_no_approval(self):
        """Test that web app attack does not require approval."""
        assert self.router.requires_approval(AttackCategory.WEB_APP_ATTACK) is False

    def test_password_spray_no_approval(self):
        """Test that password spray does not require approval."""
        assert self.router.requires_approval(AttackCategory.PASSWORD_SPRAY) is False

    def test_social_engineering_no_approval(self):
        """Test that social engineering does not require approval."""
        assert self.router.requires_approval(AttackCategory.SOCIAL_ENGINEERING) is False

    def test_network_pivot_no_approval(self):
        """Test that network pivot does not require approval."""
        assert self.router.requires_approval(AttackCategory.NETWORK_PIVOT) is False

    def test_file_exfiltration_no_approval(self):
        """Test that file exfiltration does not require approval."""
        assert self.router.requires_approval(AttackCategory.FILE_EXFILTRATION) is False

    def test_persistence_no_approval(self):
        """Test that persistence does not require approval."""
        assert self.router.requires_approval(AttackCategory.PERSISTENCE) is False
