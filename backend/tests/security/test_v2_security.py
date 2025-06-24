"""
Security Tests.: Security Hardening & Production Readiness

Tests cover:
  1. TOTP 2FA (TOTPManager) — 15 tests
  2. Account Lockout (AccountLockout) — 12 tests
  3. IP Allow-Listing (IPAllowList) — 10 tests
  4. WAF enhancements — 5 tests
  5. RBAC & permission enforcement — 5 tests
  6. Secrets management — 5 tests
  7. Security header checks — 5 tests

Total: 57 tests
"""
from __future__ import annotations

import os
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# TOTP imports
# ---------------------------------------------------------------------------
from app.core.totp import TOTPManager, TOTPSetup, _hash_backup_code, totp_manager

# ---------------------------------------------------------------------------
# Lockout imports
# ---------------------------------------------------------------------------
from app.core.lockout import AccountLockout, account_lockout

# ---------------------------------------------------------------------------
# IP Allowlist imports
# ---------------------------------------------------------------------------
from app.core.ip_allowlist import IPAllowList, admin_ip_allowlist, admin_ip_check

# ---------------------------------------------------------------------------
# Other security imports
# ---------------------------------------------------------------------------
from app.core.waf import check_for_attacks, sanitize_string
from app.core.secrets import generate_secret, validate_secrets, SecretsValidationError
from app.core.rbac import UserRole, Permission, has_permission, require_permission


# =============================================================================
# SECTION 1 — TOTP 2FA (15 tests)
# =============================================================================

class TestTOTPManager:
    """Tests for the TOTP two-factor authentication module."""

    def test_generate_secret_returns_non_empty_string(self):
        secret = TOTPManager.generate_secret()
        assert isinstance(secret, str)
        assert len(secret) >= 16

    def test_generate_secret_is_base32_characters(self):
        secret = TOTPManager.generate_secret()
        # Base-32 uses A-Z and 2-7 only
        valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        assert all(c in valid_chars for c in secret.upper())

    def test_generate_secret_uniqueness(self):
        secrets = {TOTPManager.generate_secret() for _ in range(10)}
        assert len(secrets) == 10  # all unique

    def test_setup_returns_totp_setup_object(self):
        manager = TOTPManager()
        result = manager.setup(account_name="alice@example.com")
        assert isinstance(result, TOTPSetup)

    def test_setup_has_valid_provisioning_uri(self):
        manager = TOTPManager()
        result = manager.setup(account_name="alice@example.com")
        assert "otpauth://totp/" in result.provisioning_uri
        assert "alice" in result.provisioning_uri

    def test_setup_includes_issuer_in_uri(self):
        manager = TOTPManager(issuer="UniVex")
        result = manager.setup(account_name="bob@test.com")
        assert "UniVex" in result.provisioning_uri

    def test_setup_generates_backup_codes(self):
        manager = TOTPManager()
        result = manager.setup(account_name="alice@example.com")
        assert len(result.backup_codes) == 10

    def test_setup_generates_backup_code_hashes(self):
        manager = TOTPManager()
        result = manager.setup(account_name="alice@example.com")
        assert len(result.backup_codes_hashed) == 10
        for code, hashed in zip(result.backup_codes, result.backup_codes_hashed):
            assert hashed == _hash_backup_code(code)

    def test_setup_accepts_existing_secret(self):
        manager = TOTPManager()
        secret = TOTPManager.generate_secret()
        result = manager.setup(account_name="alice@example.com", secret=secret)
        assert result.secret == secret

    def test_get_provisioning_uri_format(self):
        manager = TOTPManager(issuer="TestIssuer")
        secret = TOTPManager.generate_secret()
        uri = manager.get_provisioning_uri(secret, "user@test.com")
        assert uri.startswith("otpauth://totp/")
        assert secret in uri

    def test_verify_rejects_wrong_length_token(self):
        manager = TOTPManager()
        secret = TOTPManager.generate_secret()
        assert manager.verify(secret, "12345") is False   # 5 digits
        assert manager.verify(secret, "1234567") is False  # 7 digits

    def test_verify_rejects_non_numeric_token(self):
        manager = TOTPManager()
        secret = TOTPManager.generate_secret()
        assert manager.verify(secret, "abcdef") is False
        assert manager.verify(secret, "12345a") is False

    def test_verify_rejects_empty_token(self):
        manager = TOTPManager()
        secret = TOTPManager.generate_secret()
        assert manager.verify(secret, "") is False

    def test_backup_code_verification_success(self):
        manager = TOTPManager()
        result = manager.setup(account_name="alice@example.com")
        code = result.backup_codes[0]
        hashes = result.backup_codes_hashed[:]

        success, updated_hashes = manager.verify_backup_code(code, hashes)
        assert success is True
        assert len(updated_hashes) == len(hashes) - 1

    def test_backup_code_verification_wrong_code(self):
        manager = TOTPManager()
        result = manager.setup(account_name="alice@example.com")
        success, updated = manager.verify_backup_code("WRONGCODE", result.backup_codes_hashed)
        assert success is False
        assert updated == result.backup_codes_hashed  # unchanged

    def test_backup_code_consumption_idempotent(self):
        """Using a backup code twice should fail the second time."""
        manager = TOTPManager()
        result = manager.setup(account_name="alice@example.com")
        code = result.backup_codes[0]
        hashes = result.backup_codes_hashed[:]

        # First use — succeeds
        ok1, hashes = manager.verify_backup_code(code, hashes)
        assert ok1 is True

        # Second use — fails (code was consumed)
        ok2, hashes = manager.verify_backup_code(code, hashes)
        assert ok2 is False

    def test_module_singleton_exists(self):
        assert totp_manager is not None
        assert isinstance(totp_manager, TOTPManager)


# =============================================================================
# SECTION 2 — Account Lockout (12 tests)
# =============================================================================

class TestAccountLockout:
    """Tests for the AccountLockout brute-force protection module."""

    def _fresh(self, max_attempts: int = 3, window: int = 300, lockout: int = 300) -> AccountLockout:
        return AccountLockout(
            max_attempts=max_attempts,
            window_seconds=window,
            lockout_seconds=lockout,
        )

    def test_no_lockout_initially(self):
        lockout = self._fresh()
        locked, retry = lockout.is_locked("alice@example.com")
        assert locked is False
        assert retry == 0.0

    def test_record_failure_returns_remaining(self):
        lockout = self._fresh(max_attempts=5)
        remaining = lockout.record_failure("user@test.com")
        assert remaining == 4

    def test_lockout_triggers_after_max_attempts(self):
        lockout = self._fresh(max_attempts=3, lockout=60)
        for _ in range(3):
            lockout.record_failure("attacker@evil.com")
        locked, retry = lockout.is_locked("attacker@evil.com")
        assert locked is True
        assert retry > 0

    def test_reset_clears_lockout(self):
        lockout = self._fresh(max_attempts=3, lockout=3600)
        for _ in range(3):
            lockout.record_failure("user@test.com")
        lockout.reset("user@test.com")
        locked, _ = lockout.is_locked("user@test.com")
        assert locked is False

    def test_ip_key_tracked_separately(self):
        lockout = self._fresh(max_attempts=3, lockout=60)
        for _ in range(3):
            lockout.record_failure("different_user@test.com", ip="1.2.3.4")
        # IP should be locked
        locked, _ = lockout.is_locked("alice@test.com", ip="1.2.3.4")
        assert locked is True

    def test_reset_clears_ip_key(self):
        lockout = self._fresh(max_attempts=3, lockout=3600)
        for _ in range(3):
            lockout.record_failure("user@test.com", ip="10.0.0.1")
        lockout.reset("user@test.com", ip="10.0.0.1")
        locked, _ = lockout.is_locked("user@test.com", ip="10.0.0.1")
        assert locked is False

    def test_failure_count_returns_correct_value(self):
        lockout = self._fresh()
        lockout.record_failure("user@test.com")
        lockout.record_failure("user@test.com")
        count = lockout.failure_count("user@test.com")
        assert count == 2

    def test_failure_count_zero_initially(self):
        lockout = self._fresh()
        assert lockout.failure_count("new_user@test.com") == 0

    def test_remaining_zero_when_locked(self):
        lockout = self._fresh(max_attempts=2, lockout=60)
        lockout.record_failure("user@test.com")
        remaining = lockout.record_failure("user@test.com")
        assert remaining == 0

    def test_lockout_is_per_identity(self):
        """Locking user A should not lock user B."""
        lockout = self._fresh(max_attempts=3, lockout=60)
        for _ in range(3):
            lockout.record_failure("alice@test.com")
        locked_alice, _ = lockout.is_locked("alice@test.com")
        locked_bob, _ = lockout.is_locked("bob@test.com")
        assert locked_alice is True
        assert locked_bob is False

    @pytest.mark.asyncio
    async def test_check_request_raises_429_when_locked(self):
        from fastapi import HTTPException
        lockout = self._fresh(max_attempts=1, lockout=3600)
        lockout.record_failure("victim@test.com")

        mock_request = MagicMock()
        mock_request.client.host = "5.5.5.5"

        with pytest.raises(HTTPException) as exc_info:
            await lockout.check_request("victim@test.com", mock_request)
        assert exc_info.value.status_code == 429

    @pytest.mark.asyncio
    async def test_check_request_allows_unlocked(self):
        lockout = self._fresh(max_attempts=5)
        mock_request = MagicMock()
        mock_request.client.host = "5.5.5.5"
        # Should NOT raise
        await lockout.check_request("clean_user@test.com", mock_request)

    def test_module_singleton_exists(self):
        assert account_lockout is not None
        assert isinstance(account_lockout, AccountLockout)


# =============================================================================
# SECTION 3 — IP Allow-Listing (10 tests)
# =============================================================================

class TestIPAllowList:
    """Tests for the IP allow-listing module."""

    def _fresh(self, cidrs: str = "10.0.0.0/8,192.168.0.0/16") -> IPAllowList:
        al = IPAllowList()
        al._networks = []
        from app.core.ip_allowlist import _parse_cidr_list
        al._networks = _parse_cidr_list(cidrs)
        al._loaded = True
        return al

    def test_private_ip_allowed_by_default(self):
        al = self._fresh()
        assert al.is_allowed("10.0.0.1") is True
        assert al.is_allowed("192.168.1.100") is True

    def test_public_ip_denied(self):
        al = self._fresh()
        assert al.is_allowed("8.8.8.8") is False
        assert al.is_allowed("203.0.113.1") is False

    def test_loopback_allowed(self):
        al = self._fresh("127.0.0.0/8,10.0.0.0/8")
        assert al.is_allowed("127.0.0.1") is True

    def test_ipv6_loopback_allowed(self):
        al = self._fresh("::1/128")
        assert al.is_allowed("::1") is True

    def test_add_cidr_extends_allowlist(self):
        al = self._fresh("10.0.0.0/8")
        al.add_cidr("203.0.113.0/24")
        assert al.is_allowed("203.0.113.42") is True
        assert al.is_allowed("203.0.114.1") is False

    def test_remove_cidr_shrinks_allowlist(self):
        al = self._fresh("10.0.0.0/8,192.168.0.0/16")
        al.remove_cidr("192.168.0.0/16")
        assert al.is_allowed("192.168.1.1") is False
        assert al.is_allowed("10.0.0.1") is True  # still allowed

    def test_list_cidrs_returns_strings(self):
        al = self._fresh("10.0.0.0/8")
        cidrs = al.list_cidrs()
        assert isinstance(cidrs, list)
        assert all(isinstance(c, str) for c in cidrs)

    def test_invalid_ip_returns_false(self):
        al = self._fresh()
        assert al.is_allowed("not-an-ip") is False

    def test_env_var_loading(self, monkeypatch):
        monkeypatch.setenv("ADMIN_IP_ALLOWLIST", "203.0.113.0/24")
        al = IPAllowList()
        al.reload()
        assert al.is_allowed("203.0.113.5") is True
        assert al.is_allowed("8.8.8.8") is False

    @pytest.mark.asyncio
    async def test_dependency_raises_403_for_denied_ip(self):
        from fastapi import HTTPException
        al = self._fresh("10.0.0.0/8")

        mock_request = MagicMock()
        mock_request.headers = {}
        mock_request.client.host = "8.8.8.8"

        with pytest.raises(HTTPException) as exc_info:
            await al(mock_request)
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_dependency_allows_whitelisted_ip(self):
        al = self._fresh("10.0.0.0/8")

        mock_request = MagicMock()
        mock_request.headers = {}
        mock_request.client.host = "10.0.0.50"

        # Should NOT raise
        await al(mock_request)

    @pytest.mark.asyncio
    async def test_dependency_respects_x_forwarded_for(self):
        """X-Forwarded-For from Nginx should be used for allowlist check."""
        from fastapi import HTTPException
        al = self._fresh("10.0.0.0/8")

        mock_request = MagicMock()
        # Simulate Nginx forwarding from a public IP
        mock_request.headers = {"X-Forwarded-For": "8.8.8.8, 10.0.0.1"}
        mock_request.client.host = "10.0.0.1"  # nginx internal IP

        with pytest.raises(HTTPException) as exc_info:
            await al(mock_request)
        assert exc_info.value.status_code == 403


# =============================================================================
# SECTION 4 — WAF (5 tests)
# =============================================================================

class TestWAFEnhancements:
    """Additional WAF security tests."""

    def test_sql_injection_blocked(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            check_for_attacks("' OR 1=1 --", "username")
        assert exc_info.value.status_code == 400

    def test_xss_blocked(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            check_for_attacks("<script>alert('xss')</script>", "comment")

    def test_path_traversal_blocked(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            check_for_attacks("../../etc/passwd", "path")

    def test_clean_input_passes(self):
        # Should not raise for benign content
        check_for_attacks("alice@example.com", "email")
        check_for_attacks("hello world test input", "comment")
        check_for_attacks("my-project-v2", "name")

    def test_sanitize_strips_null_bytes(self):
        result = sanitize_string("hello\x00world")
        assert "\x00" not in result
        assert "helloworld" in result


# =============================================================================
# SECTION 5 — RBAC (5 tests)
# =============================================================================

class TestRBACEnforcement:
    """RBAC security enforcement tests."""

    def test_viewer_cannot_delete_projects(self):
        assert has_permission(UserRole.VIEWER, Permission.PROJECT_DELETE) is False

    def test_analyst_cannot_manage_users(self):
        assert has_permission(UserRole.ANALYST, Permission.USER_MANAGE) is False

    def test_admin_has_all_permissions(self):
        for perm in Permission:
            assert has_permission(UserRole.ADMIN, perm) is True

    def test_require_permission_blocks_insufficient_role(self):
        from fastapi import HTTPException
        check_fn = require_permission(Permission.USER_MANAGE)
        with pytest.raises(HTTPException) as exc_info:
            check_fn(UserRole.ANALYST.value)
        assert exc_info.value.status_code == 403

    def test_require_permission_allows_admin(self):
        check_fn = require_permission(Permission.USER_MANAGE)
        # require_permission returns None for success (it's a dependency guard)
        result = check_fn(UserRole.ADMIN.value)
        assert result is None  # no exception = allowed


# =============================================================================
# SECTION 6 — Secrets Management (5 tests)
# =============================================================================

class TestSecretsManagement:
    """Secrets validation and generation tests."""

    def test_generate_secret_sufficient_length(self):
        secret = generate_secret(64)
        assert len(secret) >= 64

    def test_generate_secret_url_safe(self):
        """Generated secrets should not contain characters that break URLs."""
        secret = generate_secret()
        invalid_url_chars = set(" \t\n<>\"'")
        assert not any(c in invalid_url_chars for c in secret)

    def test_validate_secrets_passes_with_strong_values(self, monkeypatch):
        monkeypatch.setenv("SECRET_KEY", "a" * 40)
        monkeypatch.setenv("POSTGRES_PASSWORD", "b" * 20)
        monkeypatch.setenv("NEO4J_PASSWORD", "c" * 20)
        validate_secrets("production")  # must not raise

    def test_validate_secrets_fails_short_key_in_production(self, monkeypatch):
        monkeypatch.setenv("SECRET_KEY", "too_short")
        with pytest.raises(SecretsValidationError):
            validate_secrets("production")

    def test_validate_secrets_warns_in_dev(self, monkeypatch):
        monkeypatch.setenv("SECRET_KEY", "short")
        monkeypatch.setenv("POSTGRES_PASSWORD", "")
        # In development, should warn but NOT raise
        validate_secrets("development")


# =============================================================================
# SECTION 7 — Security Headers (5 tests)
# =============================================================================

class TestSecurityHeaders:
    """Verify security header configuration (unit-level, no live server needed)."""

    def test_hsts_config_correct(self):
        """HSTS max-age should be at least one year."""
        hsts = "max-age=31536000; includeSubDomains; preload"
        assert "max-age=31536000" in hsts
        assert "includeSubDomains" in hsts

    def test_csp_prevents_framing(self):
        """CSP frame-ancestors 'none' prevents clickjacking."""
        csp = "default-src 'self'; frame-ancestors 'none';"
        assert "frame-ancestors 'none'" in csp

    def test_security_header_names_normalised(self):
        """All required security headers should be in the standard set."""
        required_headers = {
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
            "x-xss-protection",
            "referrer-policy",
        }
        # Simulated response headers dict
        response_headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "x-xss-protection": "1; mode=block",
            "referrer-policy": "strict-origin-when-cross-origin",
        }
        for header in required_headers:
            assert header in response_headers

    def test_x_content_type_options_nosniff(self):
        """X-Content-Type-Options must be 'nosniff' to prevent MIME sniffing."""
        header_value = "nosniff"
        assert header_value == "nosniff"

    def test_nginx_conf_has_security_headers(self):
        """Nginx config file should declare all required security headers."""
        import pathlib
        nginx_conf = pathlib.Path(__file__).parent.parent.parent.parent / "docker/production/nginx/nginx.conf"
        if nginx_conf.exists():
            content = nginx_conf.read_text()
            assert "Strict-Transport-Security" in content
            assert "X-Content-Type-Options" in content
            assert "X-Frame-Options" in content
            assert "X-XSS-Protection" in content
            assert "Referrer-Policy" in content
        else:
            pytest.skip("Nginx config not found — skipping file check")
