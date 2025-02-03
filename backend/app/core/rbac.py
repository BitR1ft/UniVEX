"""
Role-Based Access Control (RBAC).

Defines roles, permissions, and FastAPI dependency helpers for enforcing
access control on endpoints.

Usage:
    from app.core.rbac import require_permission, Permission

    @router.delete("/projects/{id}")
    async def delete_project(
        project_id: str,
        _: None = Depends(require_permission(Permission.PROJECT_DELETE)),
        current_user_id: str = Depends(get_current_user_id),
    ):
        ...

The ``require_permission`` and ``require_role`` dependencies resolve the
authenticated user's role from the database via ``get_current_user_with_role``,
which is exported from this module and can also be used directly.
"""
from __future__ import annotations

import logging
from enum import Enum
from typing import Annotated, Optional, Set, Tuple

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.security import decode_token

logger = logging.getLogger(__name__)

_security = HTTPBearer()


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


# Permission constants
class Permission(str, Enum):
    # Project permissions
    PROJECT_CREATE = "project:create"
    PROJECT_READ = "project:read"
    PROJECT_UPDATE = "project:update"
    PROJECT_DELETE = "project:delete"
    PROJECT_START = "project:start"
    # Scan permissions
    SCAN_READ = "scan:read"
    SCAN_WRITE = "scan:write"
    # Graph permissions
    GRAPH_READ = "graph:read"
    # Admin permissions
    USER_MANAGE = "user:manage"
    METRICS_READ = "metrics:read"


# Role → permission mapping
ROLE_PERMISSIONS: dict[UserRole, Set[Permission]] = {
    UserRole.ADMIN: set(Permission),  # All permissions
    UserRole.ANALYST: {
        Permission.PROJECT_CREATE,
        Permission.PROJECT_READ,
        Permission.PROJECT_UPDATE,
        Permission.PROJECT_START,
        Permission.SCAN_READ,
        Permission.SCAN_WRITE,
        Permission.GRAPH_READ,
        Permission.METRICS_READ,
    },
    UserRole.VIEWER: {
        Permission.PROJECT_READ,
        Permission.SCAN_READ,
        Permission.GRAPH_READ,
    },
}


def get_role_permissions(role: UserRole) -> Set[Permission]:
    """Return the set of permissions for a given role."""
    return ROLE_PERMISSIONS.get(role, set())


def has_permission(role: UserRole, permission: Permission) -> bool:
    """Check if a role has a specific permission."""
    return permission in get_role_permissions(role)


# ---------------------------------------------------------------------------
# JWT-aware dependency: resolves user_id AND role from the bearer token
# ---------------------------------------------------------------------------

async def get_current_user_with_role(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(_security)],
) -> Tuple[str, UserRole]:
    """
    FastAPI dependency that validates the JWT bearer token and returns
    (user_id, role) for the authenticated user.

    The role is read from the ``role`` claim in the JWT payload.  If the
    claim is absent or invalid the authenticated user is treated as VIEWER
    (least-privileged fallback).

    Returns:
        Tuple of (user_id: str, role: UserRole)

    Raises:
        HTTP 401 if the token is missing, expired, or invalid.
    """
    payload = decode_token(credentials.credentials)
    user_id: Optional[str] = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

    # Read role from JWT claim; fall back to VIEWER if absent / unrecognised
    role_str: str = payload.get("role", UserRole.VIEWER.value)
    try:
        role = UserRole(role_str)
    except ValueError:
        logger.warning(
            "Unknown role claim '%s' for user %s — defaulting to viewer",
            role_str,
            user_id,
        )
        role = UserRole.VIEWER

    return user_id, role


# ---------------------------------------------------------------------------
# Dependency factories
# ---------------------------------------------------------------------------


def require_permission(permission: Permission):
    """
    FastAPI dependency factory that requires the authenticated user to hold
    a specific permission (derived from their role).

    Usage::

        @router.post("/projects")
        async def create(
            _: None = Depends(require_permission(Permission.PROJECT_CREATE)),
            ...
        ):
    """
    async def _check(
        user_role: Tuple[str, UserRole] = Depends(get_current_user_with_role),
    ) -> None:
        _, role = user_role
        if not has_permission(role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role.value}' does not have permission '{permission.value}'",
            )

    return _check


def require_role(*roles: UserRole):
    """
    FastAPI dependency factory that restricts access to specific roles.

    Usage::

        @router.delete("/users/{id}")
        async def delete_user(
            _: None = Depends(require_role(UserRole.ADMIN)),
            ...
        ):
    """
    allowed = set(roles)

    async def _check(
        user_role: Tuple[str, UserRole] = Depends(get_current_user_with_role),
    ) -> None:
        _, role = user_role
        if role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role.value}' is not authorized for this action. "
                f"Required: {[r.value for r in allowed]}",
            )

    return _check
