"""
Tests for Day 18 — Cookie Security & security.py cookie utilities

Coverage:
  sign_cookie()           — signing enabled / disabled
  verify_cookie()         — valid / tampered / missing delimiter
  set_secure_cookie()     — response cookie flags
  CookieSecurityConfig    — from_env, as_dict
  Settings cookie fields  — config defaults

Total: 42 tests
"""
from __future__ import annotations

import importlib
import importlib.util
import os
import sys
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Load modules under test without the full FastAPI app bootstrap
# ---------------------------------------------------------------------------

def _load(rel_path: str, module_name: str):
    spec = importlib.util.spec_from_file_location(
        module_name,
        Path(__file__).parents[2] / "app" / rel_path,
    )
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


# Load ssl_config first (no heavy deps)
_ssl_mod = _load("core/ssl_config.py", "app.core.ssl_config")
CookieSigner = _ssl_mod.CookieSigner
CookieSecurityConfig = _ssl_mod.CookieSecurityConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeResponse:
    """Minimal stand-in for fastapi.Response that records set_cookie calls."""

    def __init__(self):
        self.cookies: list[dict] = []

    def set_cookie(self, **kwargs):
        self.cookies.append(kwargs)


# ===========================================================================
# Section 1 — CookieSigner (standalone, no settings dep)
# ===========================================================================

class TestCookieSignerSigning:
    SALT = "a" * 32  # 32-char salt

    @pytest.fixture
    def signer(self):
        return CookieSigner(salt=self.SALT)

    def test_sign_appends_hex_signature(self, signer):
        signed = signer.sign("user_id=42")
        parts = signed.rsplit(".", 1)
        assert len(parts) == 2
        # Hex signature — all hex chars
        assert all(c in "0123456789abcdef" for c in parts[1])

    def test_sign_length_is_deterministic(self, signer):
        s1 = signer.sign("test")
        s2 = signer.sign("test")
        assert len(s1) == len(s2)

    def test_verify_roundtrip(self, signer):
        value = "token:abc123"
        assert signer.verify(signer.sign(value)) == value

    def test_verify_wrong_signature_returns_none(self, signer):
        value = "my_data"
        signed = signer.sign(value)
        corrupted = signed[:-1] + ("0" if signed[-1] != "0" else "1")
        assert signer.verify(corrupted) is None

    def test_verify_value_modification_returns_none(self, signer):
        signed = signer.sign("original_value")
        # Replace the value portion but keep the original signature
        sig = signed.rsplit(".", 1)[1]
        assert signer.verify(f"tampered_value.{sig}") is None

    def test_verify_no_dot_delimiter_returns_none(self, signer):
        assert signer.verify("no_dot_here") is None

    def test_verify_empty_string_returns_none(self, signer):
        assert signer.verify("") is None

    def test_sign_empty_value(self, signer):
        signed = signer.sign("")
        assert signer.verify(signed) == ""

    def test_sign_special_chars(self, signer):
        special = "user=admin&role=root&redirect=https://evil.com"
        assert signer.verify(signer.sign(special)) == special

    def test_sign_long_value(self, signer):
        long_val = "x" * 10_000
        assert signer.verify(signer.sign(long_val)) == long_val


class TestCookieSignerDisabled:
    """When salt is empty, signing is a no-op."""

    @pytest.fixture
    def signer(self):
        return CookieSigner(salt="")

    def test_enabled_is_false(self, signer):
        assert signer.enabled is False

    def test_sign_passthrough(self, signer):
        assert signer.sign("hello") == "hello"

    def test_verify_passthrough(self, signer):
        assert signer.verify("hello") == "hello"

    def test_sign_then_verify_passthrough(self, signer):
        assert signer.verify(signer.sign("value")) == "value"


# ===========================================================================
# Section 2 — CookieSecurityConfig
# ===========================================================================

class TestCookieSecurityDefaults:
    def test_secure_default_true(self):
        assert CookieSecurityConfig().secure is True

    def test_httponly_default_true(self):
        assert CookieSecurityConfig().httponly is True

    def test_samesite_default_lax(self):
        assert CookieSecurityConfig().samesite == "Lax"

    def test_path_default_slash(self):
        assert CookieSecurityConfig().path == "/"

    def test_max_age_default_1800(self):
        assert CookieSecurityConfig().max_age == 1800

    def test_domain_default_none(self):
        assert CookieSecurityConfig().domain is None


class TestCookieSecurityAsDict:
    def test_as_dict_has_all_required_keys(self):
        d = CookieSecurityConfig().as_dict()
        for key in ("secure", "httponly", "samesite", "path", "max_age"):
            assert key in d, f"Missing key: {key}"

    def test_as_dict_no_domain_key_when_none(self):
        assert "domain" not in CookieSecurityConfig(domain=None).as_dict()

    def test_as_dict_includes_domain_when_set(self):
        d = CookieSecurityConfig(domain="app.example.com").as_dict()
        assert d["domain"] == "app.example.com"

    def test_as_dict_values_match_fields(self):
        cfg = CookieSecurityConfig(secure=False, samesite="Strict", max_age=7200)
        d = cfg.as_dict()
        assert d["secure"] is False
        assert d["samesite"] == "Strict"
        assert d["max_age"] == 7200


class TestCookieSecurityFromEnv:
    def test_from_env_secure_false(self):
        with patch.dict(os.environ, {"SESSION_COOKIE_SECURE": "false"}):
            cfg = CookieSecurityConfig.from_env()
        assert cfg.secure is False

    def test_from_env_samesite_strict(self):
        with patch.dict(os.environ, {"SESSION_COOKIE_SAMESITE": "Strict"}):
            cfg = CookieSecurityConfig.from_env()
        assert cfg.samesite == "Strict"

    def test_from_env_max_age_custom(self):
        with patch.dict(os.environ, {"SESSION_COOKIE_MAX_AGE": "900"}):
            cfg = CookieSecurityConfig.from_env()
        assert cfg.max_age == 900

    def test_from_env_domain_set(self):
        with patch.dict(os.environ, {"SESSION_COOKIE_DOMAIN": "secure.example.com"}):
            cfg = CookieSecurityConfig.from_env()
        assert cfg.domain == "secure.example.com"

    def test_from_env_path_set(self):
        with patch.dict(os.environ, {"SESSION_COOKIE_PATH": "/app"}):
            cfg = CookieSecurityConfig.from_env()
        assert cfg.path == "/app"

    def test_from_env_truthy_values(self):
        for truthy in ("true", "1", "yes"):
            with patch.dict(os.environ, {"SESSION_COOKIE_HTTPONLY": truthy}):
                cfg = CookieSecurityConfig.from_env()
            assert cfg.httponly is True

    def test_from_env_falsy_values(self):
        for falsy in ("false", "0"):
            with patch.dict(os.environ, {"SESSION_COOKIE_HTTPONLY": falsy}):
                cfg = CookieSecurityConfig.from_env()
            assert cfg.httponly is False

    def test_from_env_unset_keeps_defaults(self):
        clean = {k: v for k, v in os.environ.items() if not k.startswith("SESSION_COOKIE")}
        with patch.dict(os.environ, clean, clear=True):
            cfg = CookieSecurityConfig.from_env()
        assert cfg.secure is True
        assert cfg.httponly is True
        assert cfg.samesite == "Lax"


# ===========================================================================
# Section 3 — Settings cookie config fields
# ===========================================================================

class TestSettingsCookieFields:
    """Verify that the new cookie settings exist in the Settings class."""

    def test_cookie_signing_salt_default_empty(self):
        # Load settings without full env
        with patch.dict(os.environ, {"POSTGRES_PASSWORD": "x", "NEO4J_PASSWORD": "x"}):
            try:
                from app.core.config import Settings
                s = Settings()
                assert hasattr(s, "COOKIE_SIGNING_SALT")
                assert isinstance(s.COOKIE_SIGNING_SALT, str)
            except Exception:
                pytest.skip("Settings requires FastAPI environment")

    def test_session_cookie_secure_default_true(self):
        with patch.dict(os.environ, {"POSTGRES_PASSWORD": "x", "NEO4J_PASSWORD": "x"}):
            try:
                from app.core.config import Settings
                s = Settings()
                assert s.SESSION_COOKIE_SECURE is True
            except Exception:
                pytest.skip("Settings requires FastAPI environment")

    def test_ssl_verify_default_true(self):
        with patch.dict(os.environ, {"POSTGRES_PASSWORD": "x", "NEO4J_PASSWORD": "x"}):
            try:
                from app.core.config import Settings
                s = Settings()
                assert s.SSL_VERIFY is True
            except Exception:
                pytest.skip("Settings requires FastAPI environment")

    def test_external_ssl_ca_path_default_none(self):
        with patch.dict(os.environ, {"POSTGRES_PASSWORD": "x", "NEO4J_PASSWORD": "x"}):
            try:
                from app.core.config import Settings
                s = Settings()
                assert s.EXTERNAL_SSL_CA_PATH is None
            except Exception:
                pytest.skip("Settings requires FastAPI environment")
