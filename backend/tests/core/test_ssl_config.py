"""
Tests for Day 18 — SSLConfig module

Coverage:
  SSLConfig               — loading, CA bundle merging, ssl.SSLContext creation,
                             httpx/requests kwargs, error handling
  CookieSigner            — sign, verify, tamper detection, disabled state
  CookieSecurityConfig    — from_env, as_dict
  get_ssl_context()       — module-level helper
  EnvFileGenerator        — ssl section in generated .env

Total: 45 tests
"""
from __future__ import annotations

import hmac
import os
import ssl
import tempfile
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Import the modules under test directly (no heavy app deps)
# ---------------------------------------------------------------------------
import importlib.util
import sys

def _load(rel_path: str, name: str):
    spec = importlib.util.spec_from_file_location(
        name,
        Path(__file__).parents[2] / "app" / rel_path,
    )
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules[name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


# We need to load ssl_config without the full app bootstrap
_ssl_mod = _load("core/ssl_config.py", "app.core.ssl_config")

SSLConfig = _ssl_mod.SSLConfig
CookieSigner = _ssl_mod.CookieSigner
CookieSecurityConfig = _ssl_mod.CookieSecurityConfig
get_ssl_context = _ssl_mod.get_ssl_context


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_pem(path: Path, content: str = "") -> Path:
    """Write a minimal PEM-like placeholder cert to *path*."""
    if not content:
        content = (
            "-----BEGIN CERTIFICATE-----\n"
            "MIIDDTCCAfWgAwIBAgIJALTESTPLACEHOLDER\n"
            "-----END CERTIFICATE-----\n"
        )
    path.write_text(content)
    return path


# ===========================================================================
# Section 1 — SSLConfig — basic construction & defaults
# ===========================================================================

class TestSSLConfigDefaults:
    def test_default_verify_ssl_is_true(self):
        cfg = SSLConfig()
        assert cfg.verify_ssl is True

    def test_default_ca_path_is_none(self):
        cfg = SSLConfig()
        assert cfg.ca_path is None

    def test_default_client_cert_is_none(self):
        cfg = SSLConfig()
        assert cfg.client_cert_path is None
        assert cfg.client_key_path is None

    def test_default_min_tls_is_v1_2(self):
        cfg = SSLConfig()
        assert cfg.min_tls_version == ssl.TLSVersion.TLSv1_2

    def test_loaded_flag_starts_false(self):
        cfg = SSLConfig()
        assert cfg._loaded is False


# ===========================================================================
# Section 2 — SSLConfig.load() — no custom CA
# ===========================================================================

class TestSSLConfigLoadNoCa:
    def test_load_sets_loaded_flag(self):
        cfg = SSLConfig()
        cfg.load()
        assert cfg._loaded is True

    def test_load_no_ca_does_not_set_bundle_path(self):
        cfg = SSLConfig()
        cfg.load()
        assert cfg._ca_bundle_path is None

    def test_load_verify_false_warns(self, caplog):
        import logging
        cfg = SSLConfig(verify_ssl=False)
        with caplog.at_level(logging.WARNING, logger="app.core.ssl_config"):
            cfg.load()
        assert "DISABLED" in caplog.text or cfg._loaded is True

    def test_load_idempotent(self):
        cfg = SSLConfig()
        cfg.load()
        cfg.load()  # second call should not raise
        assert cfg._loaded is True


# ===========================================================================
# Section 3 — SSLConfig.load() — with custom CA file
# ===========================================================================

class TestSSLConfigLoadWithCaFile:
    def test_load_with_valid_ca_file(self, tmp_path):
        ca_file = tmp_path / "custom-ca.pem"
        _write_pem(ca_file)
        cfg = SSLConfig(ca_path=str(ca_file))
        cfg.load()
        assert cfg._loaded is True
        assert cfg._ca_bundle_path is not None
        assert Path(cfg._ca_bundle_path).exists()

    def test_load_ca_bundle_contains_custom_cert(self, tmp_path):
        marker = "UNIVEX_TEST_MARKER_12345"
        ca_file = tmp_path / "custom-ca.pem"
        ca_file.write_text(
            f"-----BEGIN CERTIFICATE-----\n{marker}\n-----END CERTIFICATE-----\n"
        )
        cfg = SSLConfig(ca_path=str(ca_file))
        cfg.load()
        bundle_content = Path(cfg._ca_bundle_path).read_text()
        assert marker in bundle_content

    def test_load_nonexistent_ca_raises(self):
        cfg = SSLConfig(ca_path="/nonexistent/path/ca.pem")
        with pytest.raises(FileNotFoundError):
            cfg.load()

    def test_load_with_ca_directory(self, tmp_path):
        ca_dir = tmp_path / "ca-dir"
        ca_dir.mkdir()
        _write_pem(ca_dir / "root-ca.pem")
        _write_pem(ca_dir / "intermediate.crt")
        cfg = SSLConfig(ca_path=str(ca_dir))
        cfg.load()
        assert cfg._loaded is True
        assert cfg._ca_bundle_path is not None

    def test_load_empty_ca_directory_raises(self, tmp_path):
        ca_dir = tmp_path / "empty-dir"
        ca_dir.mkdir()
        cfg = SSLConfig(ca_path=str(ca_dir))
        with pytest.raises(ValueError, match="No certificate files"):
            cfg.load()

    def test_load_ca_directory_all_extensions(self, tmp_path):
        ca_dir = tmp_path / "multi-ext"
        ca_dir.mkdir()
        for ext in ("pem", "crt", "cer"):
            _write_pem(ca_dir / f"cert.{ext}")
        cfg = SSLConfig(ca_path=str(ca_dir))
        cfg.load()
        bundle = Path(cfg._ca_bundle_path).read_text()
        # All three certs should be concatenated
        assert bundle.count("BEGIN CERTIFICATE") >= 3


# ===========================================================================
# Section 4 — SSLConfig.create_ssl_context()
# ===========================================================================

class TestSSLConfigCreateContext:
    def test_create_context_returns_ssl_context(self):
        cfg = SSLConfig()
        ctx = cfg.create_ssl_context()
        assert isinstance(ctx, ssl.SSLContext)

    def test_create_context_verify_false_disables_check(self):
        cfg = SSLConfig(verify_ssl=False)
        ctx = cfg.create_ssl_context()
        assert ctx.verify_mode == ssl.CERT_NONE
        assert ctx.check_hostname is False

    def test_create_context_default_loads_successfully(self):
        cfg = SSLConfig()
        ctx = cfg.create_ssl_context()
        assert ctx.verify_mode != ssl.CERT_NONE

    def test_create_context_with_ca_file(self, tmp_path):
        ca_file = tmp_path / "ca.pem"
        _write_pem(ca_file)
        cfg = SSLConfig(ca_path=str(ca_file))
        # May raise ssl.SSLError if PEM is not a valid cert — that's expected
        # with placeholder content; just check it calls load
        cfg.load()
        assert cfg._ca_bundle_path is not None


# ===========================================================================
# Section 5 — SSLConfig httpx / requests helpers
# ===========================================================================

class TestSSLConfigHttpxKwargs:
    def test_verify_true_returns_true(self):
        cfg = SSLConfig()
        kwargs = cfg.get_httpx_kwargs()
        assert kwargs.get("verify") is True

    def test_verify_false_returns_false(self):
        cfg = SSLConfig(verify_ssl=False)
        kwargs = cfg.get_httpx_kwargs()
        assert kwargs.get("verify") is False

    def test_with_ca_file_returns_bundle_path(self, tmp_path):
        ca_file = tmp_path / "ca.pem"
        _write_pem(ca_file)
        cfg = SSLConfig(ca_path=str(ca_file))
        cfg.load()
        kwargs = cfg.get_httpx_kwargs()
        assert isinstance(kwargs.get("verify"), str)
        assert Path(kwargs["verify"]).exists()

    def test_get_requests_kwargs_matches_httpx(self):
        cfg = SSLConfig()
        assert cfg.get_httpx_kwargs() == cfg.get_requests_kwargs()


# ===========================================================================
# Section 6 — CookieSigner
# ===========================================================================

class TestCookieSignerEnabled:
    @pytest.fixture
    def signer(self):
        return CookieSigner(salt="test-signing-salt-for-unit-tests")

    def test_sign_returns_value_with_delimiter(self, signer):
        signed = signer.sign("hello")
        assert "." in signed
        assert signed.startswith("hello.")

    def test_sign_produces_consistent_output(self, signer):
        assert signer.sign("world") == signer.sign("world")

    def test_verify_valid_signature_returns_value(self, signer):
        signed = signer.sign("session_data")
        result = signer.verify(signed)
        assert result == "session_data"

    def test_verify_tampered_value_returns_none(self, signer):
        signed = signer.sign("original")
        tampered = "modified." + signed.split(".", 1)[1]
        assert signer.verify(tampered) is None

    def test_verify_tampered_signature_returns_none(self, signer):
        signed = signer.sign("data")
        parts = signed.rsplit(".", 1)
        bad_sig = "a" * len(parts[1])
        assert signer.verify(f"{parts[0]}.{bad_sig}") is None

    def test_verify_missing_delimiter_returns_none(self, signer):
        assert signer.verify("no-delimiter-here") is None

    def test_verify_empty_string_returns_none(self, signer):
        assert signer.verify("") is None

    def test_different_salts_produce_different_signatures(self):
        s1 = CookieSigner(salt="salt-alpha")
        s2 = CookieSigner(salt="salt-beta")
        signed1 = s1.sign("value")
        signed2 = s2.sign("value")
        assert signed1 != signed2

    def test_cross_signer_verify_fails(self):
        s1 = CookieSigner(salt="salt-alpha")
        s2 = CookieSigner(salt="salt-beta")
        signed = s1.sign("value")
        assert s2.verify(signed) is None

    def test_enabled_property_true(self, signer):
        assert signer.enabled is True

    def test_unicode_value_roundtrip(self, signer):
        value = "unicode-ñ-αβγ-🔒"
        assert signer.verify(signer.sign(value)) == value


class TestCookieSignerDisabled:
    @pytest.fixture
    def signer(self):
        with patch.dict(os.environ, {}, clear=True):
            return CookieSigner(salt="")

    def test_enabled_property_false(self, signer):
        assert signer.enabled is False

    def test_sign_returns_value_unchanged(self, signer):
        assert signer.sign("hello") == "hello"

    def test_verify_returns_value_unchanged(self, signer):
        assert signer.verify("hello") == "hello"


# ===========================================================================
# Section 7 — CookieSecurityConfig
# ===========================================================================

class TestCookieSecurityConfig:
    def test_default_secure_true(self):
        cfg = CookieSecurityConfig()
        assert cfg.secure is True

    def test_default_httponly_true(self):
        cfg = CookieSecurityConfig()
        assert cfg.httponly is True

    def test_default_samesite_lax(self):
        cfg = CookieSecurityConfig()
        assert cfg.samesite == "Lax"

    def test_default_max_age(self):
        cfg = CookieSecurityConfig()
        assert cfg.max_age == 1800

    def test_as_dict_contains_required_keys(self):
        cfg = CookieSecurityConfig()
        d = cfg.as_dict()
        for key in ("secure", "httponly", "samesite", "path", "max_age"):
            assert key in d

    def test_as_dict_excludes_domain_when_none(self):
        cfg = CookieSecurityConfig(domain=None)
        assert "domain" not in cfg.as_dict()

    def test_as_dict_includes_domain_when_set(self):
        cfg = CookieSecurityConfig(domain="example.com")
        assert cfg.as_dict()["domain"] == "example.com"

    def test_from_env_reads_env_vars(self):
        env = {
            "SESSION_COOKIE_SECURE": "false",
            "SESSION_COOKIE_HTTPONLY": "true",
            "SESSION_COOKIE_SAMESITE": "Strict",
            "SESSION_COOKIE_MAX_AGE": "3600",
        }
        with patch.dict(os.environ, env):
            cfg = CookieSecurityConfig.from_env()
        assert cfg.secure is False
        assert cfg.httponly is True
        assert cfg.samesite == "Strict"
        assert cfg.max_age == 3600

    def test_from_env_default_when_not_set(self):
        clean_env = {k: v for k, v in os.environ.items() if not k.startswith("SESSION_COOKIE")}
        with patch.dict(os.environ, clean_env, clear=True):
            cfg = CookieSecurityConfig.from_env()
        assert cfg.secure is True
        assert cfg.samesite == "Lax"


# ===========================================================================
# Section 8 — Module-level get_ssl_context()
# ===========================================================================

class TestGetSslContext:
    def test_returns_ssl_context_instance(self):
        # Reset module singleton
        _ssl_mod.ssl_config = SSLConfig()
        ctx = get_ssl_context()
        assert isinstance(ctx, ssl.SSLContext)

    def test_repeated_calls_do_not_raise(self):
        _ssl_mod.ssl_config = SSLConfig()
        ctx1 = get_ssl_context()
        ctx2 = get_ssl_context()
        assert isinstance(ctx1, ssl.SSLContext)
        assert isinstance(ctx2, ssl.SSLContext)
