"""Tests for Week 25 security hardening features."""
import pytest
from unittest.mock import patch, MagicMock
import json
import time

from app.core.secrets import validate_secrets, generate_secret, SecretsValidationError

from app.core.rbac import UserRole, Permission, has_permission, get_role_permissions, require_permission, require_role

from app.core.audit import log_audit, AuditAction

from app.core.rate_limit import SlidingWindowRateLimiter

from app.core.waf import check_for_attacks, sanitize_string
def test_generate_secret_returns_string():
    s = generate_secret()
    assert isinstance(s, str) and len(s) > 32

def test_validate_secrets_warns_in_dev(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "short")
    monkeypatch.setenv("POSTGRES_PASSWORD", "")
    # In dev, should warn but not raise
    validate_secrets("development")  # no exception

def test_validate_secrets_raises_in_prod(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "tooshort")
    with pytest.raises(SecretsValidationError):
        validate_secrets("production")

def test_validate_secrets_passes_with_good_values(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "a" * 40)
    monkeypatch.setenv("POSTGRES_PASSWORD", "b" * 20)
    monkeypatch.setenv("NEO4J_PASSWORD", "c" * 20)
    validate_secrets("production")  # no exception
def test_admin_has_all_permissions():
    for perm in Permission:
        assert has_permission(UserRole.ADMIN, perm)

def test_viewer_read_only():
    assert has_permission(UserRole.VIEWER, Permission.PROJECT_READ)
    assert not has_permission(UserRole.VIEWER, Permission.PROJECT_CREATE)
    assert not has_permission(UserRole.VIEWER, Permission.PROJECT_DELETE)

def test_analyst_can_create_projects():
    assert has_permission(UserRole.ANALYST, Permission.PROJECT_CREATE)
    assert not has_permission(UserRole.ANALYST, Permission.USER_MANAGE)

def test_get_role_permissions_returns_set():
    perms = get_role_permissions(UserRole.ANALYST)
    assert isinstance(perms, set)
    assert len(perms) > 0

def test_require_permission_viewer_default_blocks_create():
    """Default role (viewer) must NOT have project:create — fail-secure behavior."""
    from fastapi import HTTPException
    check_fn = require_permission(Permission.PROJECT_CREATE)
    # Call with viewer (the new secure default) — should raise 403
    with pytest.raises(HTTPException) as exc_info:
        check_fn(UserRole.VIEWER.value)
    assert exc_info.value.status_code == 403

def test_require_role_viewer_default_blocks_admin_endpoint():
    """Default role (viewer) must NOT satisfy require_role(ADMIN)."""
    from fastapi import HTTPException
    check_fn = require_role(UserRole.ADMIN)
    with pytest.raises(HTTPException) as exc_info:
        check_fn(UserRole.VIEWER.value)
    assert exc_info.value.status_code == 403

def test_require_permission_unknown_role_returns_403():
    from fastapi import HTTPException
    check_fn = require_permission(Permission.PROJECT_READ)
    with pytest.raises(HTTPException) as exc_info:
        check_fn("superadmin")
    assert exc_info.value.status_code == 403
def test_log_audit_emits_json():
    with patch("app.core.audit.audit_logger") as mock_logger:
        log_audit(
            AuditAction.USER_LOGIN,
            actor_id="user-123",
            ip_address="127.0.0.1",
            correlation_id="req-abc",
            success=True,
        )
        mock_logger.info.assert_called_once()
        raw = mock_logger.info.call_args[0][0]
        entry = json.loads(raw)
        assert entry["action"] == AuditAction.USER_LOGIN
        assert entry["actor_id"] == "user-123"
        assert entry["success"] is True

def test_log_audit_failed_action():
    with patch("app.core.audit.audit_logger") as mock_logger:
        log_audit(AuditAction.USER_LOGIN_FAILED, success=False, ip_address="1.2.3.4")
        raw = mock_logger.info.call_args[0][0]
        entry = json.loads(raw)
        assert entry["success"] is False
def test_rate_limiter_allows_within_limit():
    limiter = SlidingWindowRateLimiter(max_calls=5, window_seconds=60, name="test")
    for _ in range(5):
        allowed = limiter.is_allowed("user1")
        assert allowed

def test_rate_limiter_blocks_over_limit():
    limiter = SlidingWindowRateLimiter(max_calls=3, window_seconds=60, name="test")
    for _ in range(3):
        limiter.is_allowed("user2")
    allowed, remaining = limiter._check_with_remaining("user2")
    assert not allowed
    assert remaining == 0

def test_rate_limiter_independent_keys():
    limiter = SlidingWindowRateLimiter(max_calls=1, window_seconds=60, name="test")
    allowed_a = limiter.is_allowed("keyA")
    allowed_b = limiter.is_allowed("keyB")
    assert allowed_a and allowed_b

def test_rate_limiter_window_expiry():
    limiter = SlidingWindowRateLimiter(max_calls=1, window_seconds=1, name="test")
    limiter.is_allowed("expiry_key")
    time.sleep(1.1)
    allowed = limiter.is_allowed("expiry_key")
    assert allowed

def test_rate_limiter_check_raises_http429_when_exceeded():
    """The check() method must raise HTTP 429 when the limit is exceeded."""
    from fastapi import HTTPException
    limiter = SlidingWindowRateLimiter(max_calls=2, window_seconds=60, name="test_check")
    limiter.check("check_key")
    limiter.check("check_key")
    with pytest.raises(HTTPException) as exc_info:
        limiter.check("check_key", correlation_id="req-xyz")
    assert exc_info.value.status_code == 429
    assert "Retry-After" in exc_info.value.headers

def test_rate_limiter_check_allows_within_limit():
    """check() should not raise when within the limit."""
    limiter = SlidingWindowRateLimiter(max_calls=10, window_seconds=60, name="test_check_ok")
    # Should not raise
    for _ in range(5):
        limiter.check("ok_key")
def test_waf_blocks_sql_injection():
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        check_for_attacks("SELECT * FROM users", "query")
    assert exc_info.value.status_code == 400

def test_waf_blocks_xss():
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        check_for_attacks("<script>alert(1)</script>", "body")

def test_waf_blocks_path_traversal():
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        check_for_attacks("../../etc/passwd", "path")

def test_waf_allows_clean_input():
    check_for_attacks("example.com", "target")  # no exception
    check_for_attacks("My Pentest Project", "name")

def test_sanitize_string_strips_whitespace():
    assert sanitize_string("  hello  ") == "hello"

def test_sanitize_string_removes_null_bytes():
    assert "\x00" not in sanitize_string("hello\x00world")
