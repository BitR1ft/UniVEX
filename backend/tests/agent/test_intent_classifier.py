"""
Tests for the ML-based intent classifier (Week 9-10, Betterment Plan).

Tests:
- KeywordClassifier accuracy
- IntentClassifier in keyword mode (default)
- MLClassifier training and prediction
- LLMClassifier fallback without API key
- HybridClassifier fallback path
- Edge cases: empty input, unrecognised input
"""

from __future__ import annotations

import pytest
from typing import Dict

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def import_classifiers():
    """Import without triggering the full app package (no langchain required)."""
    from app.agent.classification.intent_classifier import (
        KeywordClassifier,
        MLClassifier,
        LLMClassifier,
        HybridClassifier,
        IntentClassifier,
        ClassificationResult,
        CATEGORIES,
    )
    return (
        KeywordClassifier,
        MLClassifier,
        LLMClassifier,
        HybridClassifier,
        IntentClassifier,
        ClassificationResult,
        CATEGORIES,
    )


# ===========================================================================
# ClassificationResult
# ===========================================================================


class TestClassificationResult:
    """Test ClassificationResult data class."""

    def test_has_expected_attributes(self):
        (_, _, _, _, _, ClassificationResult, CATEGORIES) = import_classifiers()
        result = ClassificationResult(
            categories=["cve_exploitation"],
            scores={"cve_exploitation": 0.8},
            method="keyword",
            top_category="cve_exploitation",
        )
        assert result.top_category == "cve_exploitation"
        assert result.categories == ["cve_exploitation"]
        assert result.method == "keyword"
        assert result.scores == {"cve_exploitation": 0.8}


# ===========================================================================
# KeywordClassifier
# ===========================================================================


class TestKeywordClassifier:
    """Test keyword-based classifier against known scenarios."""

    @pytest.fixture(autouse=True)
    def setup(self):
        (KeywordClassifier, *_) = import_classifiers()
        self.clf = KeywordClassifier()

    def _predict(self, text):
        return self.clf.predict(text)

    def test_cve_exploitation_basic(self):
        result = self._predict("exploit CVE-2021-44228 log4j vulnerability")
        assert result.top_category == "cve_exploitation"

    def test_brute_force_basic(self):
        result = self._predict("Run a brute force attack against SSH")
        assert result.top_category == "brute_force"

    def test_brute_force_wordlist(self):
        result = self._predict("Use a wordlist to crack the password")
        assert result.top_category == "brute_force"

    def test_web_app_attack_sqli(self):
        result = self._predict("Test for sql injection on the login form")
        assert result.top_category == "web_app_attack"

    def test_web_app_attack_xss(self):
        result = self._predict("Try a cross-site scripting attack on the search page")
        assert result.top_category == "web_app_attack"

    def test_privilege_escalation(self):
        result = self._predict("Attempt privilege escalation to get root")
        assert result.top_category == "privilege_escalation"

    def test_lateral_movement(self):
        result = self._predict("Move laterally to other hosts using psexec")
        assert result.top_category == "lateral_movement"

    def test_kerberoast_is_lateral_movement(self):
        result = self._predict("kerberoast service account hashes")
        assert result.top_category == "lateral_movement"

    def test_password_spray(self):
        result = self._predict("Execute a password spray attack with common passwords")
        assert result.top_category == "password_spray"

    def test_social_engineering(self):
        result = self._predict("Send a phishing email to the target")
        assert result.top_category == "social_engineering"

    def test_network_pivot(self):
        result = self._predict("Set up a network pivot using chisel tunnel")
        assert result.top_category == "network_pivot"

    def test_file_exfiltration(self):
        result = self._predict("Exfiltrate data from the compromised host")
        assert result.top_category == "file_exfiltration"

    def test_mimikatz_is_file_exfiltration(self):
        result = self._predict("dump lsass credentials mimikatz")
        assert result.top_category == "file_exfiltration"

    def test_persistence(self):
        result = self._predict("Install a backdoor for persistence on the server")
        assert result.top_category == "persistence"

    def test_cron_persistence(self):
        result = self._predict("maintain persistence via cron job backdoor")
        assert result.top_category == "persistence"

    def test_empty_string_defaults_to_web_app_attack(self):
        result = self._predict("")
        assert result.top_category == "web_app_attack"

    def test_unknown_input_defaults_to_web_app_attack(self):
        result = self._predict("Do something random with no matching keywords")
        assert result.top_category == "web_app_attack"

    def test_scores_keys_match_categories(self):
        (_, _, _, _, _, _, CATEGORIES) = import_classifiers()
        result = self._predict("exploit CVE-2021-44228")
        assert set(result.scores.keys()) == set(CATEGORIES)

    def test_scores_are_between_0_and_1(self):
        result = self._predict("exploit CVE-2021-44228 log4j vulnerability")
        for score in result.scores.values():
            assert 0.0 <= score <= 1.0

    def test_categories_list_is_ranked(self):
        """Categories should be in descending score order."""
        result = self._predict("brute force attack hydra hashcat crack hash")
        if len(result.categories) >= 2:
            scores = result.scores
            first_score = scores[result.categories[0]]
            second_score = scores[result.categories[1]]
            assert first_score >= second_score

    def test_case_insensitive(self):
        result_lower = self._predict("brute force attack against ssh")
        result_upper = self._predict("BRUTE FORCE ATTACK AGAINST SSH")
        assert result_lower.top_category == result_upper.top_category

    def test_method_is_keyword(self):
        result = self._predict("exploit CVE-2021-44228")
        assert result.method == "keyword"

    def test_vsftpd_exploit_is_cve_exploitation(self):
        result = self._predict("exploit vsftpd 2.3.4 backdoor")
        assert result.top_category == "cve_exploitation"


# ===========================================================================
# IntentClassifier (public API)
# ===========================================================================


class TestIntentClassifier:
    """Test IntentClassifier in keyword mode (default, no heavy dependencies)."""

    @pytest.fixture(autouse=True)
    def setup(self, monkeypatch):
        # Force keyword mode regardless of environment
        monkeypatch.setenv("CLASSIFIER_MODE", "keyword")
        (_, _, _, _, IntentClassifier, *_) = import_classifiers()
        self.clf = IntentClassifier()

    def test_classify_returns_result(self):
        (_, _, _, _, _, ClassificationResult, _) = import_classifiers()
        result = self.clf.classify("exploit CVE-2021-44228")
        assert isinstance(result, ClassificationResult)

    def test_classify_cve_exploitation(self):
        result = self.clf.classify("Exploit CVE-2021-44228 on the target")
        assert result.top_category == "cve_exploitation"

    def test_classify_brute_force(self):
        result = self.clf.classify("Run a brute force attack against SSH")
        assert result.top_category == "brute_force"

    def test_classify_web_app_attack(self):
        result = self.clf.classify("Test for sql injection on the login form")
        assert result.top_category == "web_app_attack"

    def test_classify_empty_defaults_to_web_app_attack(self):
        result = self.clf.classify("")
        assert result.top_category == "web_app_attack"

    def test_top_category_convenience(self):
        result = self.clf.top_category("phishing campaign send emails")
        assert result == "social_engineering"

    def test_top_n_categories(self):
        cats = self.clf.top_n_categories("brute force attack with hydra hashcat", n=3)
        assert isinstance(cats, list)
        assert len(cats) <= 3

    def test_mode_is_keyword(self):
        assert self.clf._mode == "keyword"


# ===========================================================================
# LLMClassifier (fallback without API key)
# ===========================================================================


class TestLLMClassifierFallback:
    """Test LLMClassifier falls back to keyword classifier when no API key."""

    def test_no_api_key_falls_back(self, monkeypatch):
        (_, _, LLMClassifier, *_) = import_classifiers()
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        clf = LLMClassifier(api_key="")
        result = clf.predict("exploit CVE-2021-44228")
        # Should still return a valid result via keyword fallback
        assert result.top_category in [
            "cve_exploitation", "web_app_attack", "brute_force",
            "privilege_escalation", "lateral_movement", "password_spray",
            "social_engineering", "network_pivot", "file_exfiltration", "persistence",
        ]


# ===========================================================================
# HybridClassifier (fallback path)
# ===========================================================================


class TestHybridClassifier:
    """Test HybridClassifier uses keyword fallback when ML model not trained."""

    def test_falls_back_to_keyword_without_ml(self, monkeypatch):
        (_, _, LLMClassifier, HybridClassifier, *_) = import_classifiers()
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        clf = HybridClassifier(
            ml_classifier=None,
            llm_classifier=LLMClassifier(api_key=""),
        )
        result = clf.predict("brute force attack against SSH")
        assert result.top_category == "brute_force"


# ===========================================================================
# CATEGORIES constant
# ===========================================================================


class TestCategories:
    """Test CATEGORIES list completeness."""

    def test_all_expected_categories_present(self):
        (_, _, _, _, _, _, CATEGORIES) = import_classifiers()
        expected = {
            "cve_exploitation", "brute_force", "web_app_attack",
            "privilege_escalation", "lateral_movement", "password_spray",
            "social_engineering", "network_pivot", "file_exfiltration", "persistence",
        }
        assert expected == set(CATEGORIES)

    def test_categories_is_sorted(self):
        (_, _, _, _, _, _, CATEGORIES) = import_classifiers()
        assert CATEGORIES == sorted(CATEGORIES)
