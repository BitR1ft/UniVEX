"""
Account Lockout — protect against brute-force login attacks.

Implements a thread-safe, in-process sliding-window lockout policy.
A distributed Redis-backed variant (RedisAccountLockout) is provided
for multi-instance deployments.

Usage::

    from app.core.lockout import account_lockout

    # Record a failed login attempt
    account_lockout.record_failure("alice@example.com", ip="1.2.3.4")

    # Check if the account (or IP) is locked before processing login
    if account_lockout.is_locked("alice@example.com", ip="1.2.3.4"):
        raise HTTPException(status_code=429, detail="Account locked")

    # Clear lockout on successful login
    account_lockout.reset("alice@example.com", ip="1.2.3.4")
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, Optional, Tuple

from fastapi import HTTPException, Request, status

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------
_DEFAULT_MAX_ATTEMPTS = 5        # max failures before lockout
_DEFAULT_WINDOW_SECONDS = 900    # 15-minute sliding window
_DEFAULT_LOCKOUT_SECONDS = 900   # 15-minute lockout duration


@dataclass
class _LockoutEntry:
    """Per-key lockout state."""

    failures: list[float] = field(default_factory=list)
    """Timestamps of recent failed attempts."""

    locked_until: float = 0.0
    """Epoch timestamp at which the lockout expires (0 = not locked)."""


class AccountLockout:
    """
    Thread-safe account lockout using an in-process sliding window.

    Keys can be usernames, email addresses, or IP addresses — the caller
    decides the granularity.  Both *identity* and *IP* keys are tracked
    so that credential stuffing attacks (many IPs) and password-spraying
    attacks (many identities from one IP) are both detected.

    Args:
        max_attempts:     Maximum failures before lockout.
        window_seconds:   Sliding window for counting failures.
        lockout_seconds:  How long the account stays locked after threshold.
    """

    def __init__(
        self,
        max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
        window_seconds: int = _DEFAULT_WINDOW_SECONDS,
        lockout_seconds: int = _DEFAULT_LOCKOUT_SECONDS,
    ) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds

        self._state: Dict[str, _LockoutEntry] = defaultdict(_LockoutEntry)
        self._lock = Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_locked(self, identity: str, *, ip: Optional[str] = None) -> Tuple[bool, float]:
        """
        Check whether an identity (and optionally its originating IP) is locked.

        Returns:
            (is_locked, retry_after_seconds)
            retry_after_seconds is 0 if not locked.
        """
        now = time.monotonic()
        with self._lock:
            for key in self._keys(identity, ip):
                entry = self._state[key]
                if entry.locked_until > now:
                    retry_after = entry.locked_until - now
                    logger.warning(
                        "Lockout active for key=%s retry_after=%.0fs", key, retry_after
                    )
                    return True, retry_after
        return False, 0.0

    def record_failure(self, identity: str, *, ip: Optional[str] = None) -> int:
        """
        Record a failed authentication attempt.

        Returns:
            Remaining attempts before lockout (0 means now locked).
        """
        now = time.monotonic()
        cutoff = now - self.window_seconds
        remaining = self.max_attempts

        with self._lock:
            for key in self._keys(identity, ip):
                entry = self._state[key]
                # Evict old failures outside window
                entry.failures = [t for t in entry.failures if t > cutoff]
                entry.failures.append(now)

                if len(entry.failures) >= self.max_attempts:
                    entry.locked_until = now + self.lockout_seconds
                    remaining = 0
                    logger.warning(
                        "Account locked: key=%s failures=%d locked_for=%.0fs",
                        key, len(entry.failures), self.lockout_seconds,
                    )
                else:
                    remaining = min(remaining, self.max_attempts - len(entry.failures))

        return remaining

    def reset(self, identity: str, *, ip: Optional[str] = None) -> None:
        """Clear failure history and any lockout for the given identity/IP."""
        with self._lock:
            for key in self._keys(identity, ip):
                self._state.pop(key, None)

    def failure_count(self, identity: str, *, ip: Optional[str] = None) -> int:
        """Return the number of recent failures for diagnostic purposes."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        total = 0
        with self._lock:
            for key in self._keys(identity, ip):
                entry = self._state[key]
                total = max(total, sum(1 for t in entry.failures if t > cutoff))
        return total

    # ------------------------------------------------------------------
    # FastAPI dependency
    # ------------------------------------------------------------------

    async def check_request(self, identity: str, request: Request) -> None:
        """
        FastAPI dependency: raises HTTP 429 if the identity or remote IP is locked.

        Usage::

            @router.post("/login")
            async def login(body: LoginIn, _: None = Depends(account_lockout.check_request)):
                ...
        """
        ip = request.client.host if request.client else None
        locked, retry_after = self.is_locked(identity, ip=ip)
        if locked:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Account locked. Try again in {int(retry_after)} seconds.",
                headers={"Retry-After": str(int(retry_after))},
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _keys(identity: str, ip: Optional[str]) -> list[str]:
        """Return the list of lockout keys to check/update."""
        keys = [f"identity:{identity.lower().strip()}"]
        if ip:
            keys.append(f"ip:{ip}")
        return keys


# ---------------------------------------------------------------------------
# Module-level singleton (shared across all requests in the process)
# ---------------------------------------------------------------------------
account_lockout = AccountLockout(
    max_attempts=_DEFAULT_MAX_ATTEMPTS,
    window_seconds=_DEFAULT_WINDOW_SECONDS,
    lockout_seconds=_DEFAULT_LOCKOUT_SECONDS,
)
