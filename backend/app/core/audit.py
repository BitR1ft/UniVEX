"""
Audit logging for sensitive operations.

All writes go to the standard Python logging system under the
``univex.audit`` logger so they can be routed to a separate
sink (file, SIEM, etc.) via logging configuration.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

audit_logger = logging.getLogger("univex.audit")


class AuditAction(str, Enum):
    # Auth
    USER_REGISTER = "user.register"
    USER_LOGIN = "user.login"
    LOGIN_SUCCESS = "user.login"  # alias for USER_LOGIN
    USER_LOGIN_FAILED = "user.login_failed"
    LOGIN_FAILED = "user.login_failed"  # alias for USER_LOGIN_FAILED
    USER_LOGOUT = "user.logout"
    TOKEN_REFRESH = "token.refresh"
    PASSWORD_CHANGE = "user.password_change"
    # Projects
    PROJECT_CREATE = "project.create"
    PROJECT_UPDATE = "project.update"
    PROJECT_DELETE = "project.delete"
    PROJECT_START = "project.start"
    # Admin
    USER_ROLE_CHANGE = "user.role_change"
    USER_DELETE = "user.delete"
    # Security
    PERMISSION_DENIED = "security.permission_denied"
    RATE_LIMIT_HIT = "security.rate_limit_hit"


def log_audit(
    action: AuditAction,
    *,
    actor_id: Optional[str] = None,
    target_id: Optional[str] = None,
    target_type: Optional[str] = None,
    ip_address: Optional[str] = None,
    correlation_id: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
    success: bool = True,
) -> None:
    """
    Emit a structured audit log entry.

    Args:
        action: The audited action (from AuditAction enum).
        actor_id: ID of the user performing the action.
        target_id: ID of the resource being acted upon.
        target_type: Type name of the target resource.
        ip_address: Remote IP of the request.
        correlation_id: X-Request-ID for tracing.
        details: Additional context dict (will be JSON-serialised).
        success: Whether the action succeeded.
    """
    entry: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "success": success,
    }
    if actor_id:
        entry["actor_id"] = actor_id
    if target_id:
        entry["target_id"] = target_id
    if target_type:
        entry["target_type"] = target_type
    if ip_address:
        entry["ip_address"] = ip_address
    if correlation_id:
        entry["correlation_id"] = correlation_id
    if details:
        entry["details"] = details

    audit_logger.info(json.dumps(entry))
