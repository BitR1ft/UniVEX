"""
TOTP-based Two-Factor Authentication (2FA) for UniVex.

Implements RFC 6238 TOTP using pyotp.  Provides:
  - Secret generation (per-user)
  - QR code URI generation (for authenticator apps)
  - TOTP verification with drift tolerance (±1 window)
  - Backup code generation and verification

Usage::

    from app.core.totp import TOTPManager

    manager = TOTPManager()
    secret  = manager.generate_secret()
    uri     = manager.get_provisioning_uri(secret, account_name="alice@example.com")
    ok      = manager.verify(secret, token="123456")
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

try:
    import pyotp  # type: ignore
    _PYOTP_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PYOTP_AVAILABLE = False
    logger.warning(
        "pyotp not installed — TOTP 2FA will be disabled. "
        "Install it with: pip install pyotp"
    )

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_ISSUER_NAME = "UniVex"
_TOKEN_DIGITS = 6
_TOKEN_INTERVAL = 30          # seconds
_VALID_WINDOW = 1             # ±1 interval = 90 seconds of tolerance
_BACKUP_CODE_LENGTH = 10      # characters per backup code
_BACKUP_CODE_COUNT = 10       # codes generated per setup


@dataclass
class TOTPSetup:
    """Result of setting up 2FA for a user."""

    secret: str
    """Base-32 encoded TOTP secret — store encrypted in database."""

    provisioning_uri: str
    """otpauth:// URI for QR-code generation in authenticator apps."""

    backup_codes: List[str]
    """One-time backup codes for account recovery.
    Store only the **hashed** versions in the database.
    """

    backup_codes_hashed: List[str] = field(default_factory=list)
    """SHA-256 hashes of backup_codes (safe to store in DB)."""

    def __post_init__(self) -> None:
        self.backup_codes_hashed = [_hash_backup_code(c) for c in self.backup_codes]


def _hash_backup_code(code: str) -> str:
    """Return SHA-256 hex-digest of a backup code (salted with TOTP prefix)."""
    return hashlib.sha256(f"univex-2fa-backup:{code}".encode()).hexdigest()


class TOTPManager:
    """
    Manages TOTP 2FA lifecycle: setup, verification, and backup codes.

    All methods are stateless — secrets and backup-code hashes are stored
    by the caller (typically in the ``users`` database table).
    """

    def __init__(
        self,
        issuer: str = _ISSUER_NAME,
        digits: int = _TOKEN_DIGITS,
        interval: int = _TOKEN_INTERVAL,
        valid_window: int = _VALID_WINDOW,
    ) -> None:
        self.issuer = issuer
        self.digits = digits
        self.interval = interval
        self.valid_window = valid_window

    # ------------------------------------------------------------------
    # Secret management
    # ------------------------------------------------------------------

    @staticmethod
    def generate_secret() -> str:
        """Generate a cryptographically secure Base-32 TOTP secret."""
        if _PYOTP_AVAILABLE:
            return pyotp.random_base32()
        # Fallback: generate raw bytes and base-32 encode manually
        import base64
        raw = secrets.token_bytes(20)
        return base64.b32encode(raw).decode().rstrip("=")

    def setup(self, account_name: str, secret: Optional[str] = None) -> TOTPSetup:
        """
        Generate everything needed to enrol a user in 2FA.

        Args:
            account_name: Typically the user's email address.
            secret: Optional existing secret (re-enrolment). Generates new if omitted.

        Returns:
            TOTPSetup with secret, QR URI, and backup codes.
        """
        if secret is None:
            secret = self.generate_secret()

        uri = self.get_provisioning_uri(secret, account_name)
        backup_codes = self._generate_backup_codes()

        return TOTPSetup(
            secret=secret,
            provisioning_uri=uri,
            backup_codes=backup_codes,
        )

    def get_provisioning_uri(self, secret: str, account_name: str) -> str:
        """
        Return the ``otpauth://`` URI for QR code generation.

        Args:
            secret: Base-32 TOTP secret.
            account_name: User identifier shown in the authenticator app.

        Returns:
            otpauth URI string.
        """
        if _PYOTP_AVAILABLE:
            totp = pyotp.TOTP(
                secret,
                digits=self.digits,
                interval=self.interval,
                issuer=self.issuer,
            )
            return totp.provisioning_uri(name=account_name, issuer_name=self.issuer)

        # Fallback — manually construct URI (RFC 6238 format)
        from urllib.parse import quote
        label = quote(f"{self.issuer}:{account_name}")
        return (
            f"otpauth://totp/{label}"
            f"?secret={secret}"
            f"&issuer={quote(self.issuer)}"
            f"&digits={self.digits}"
            f"&period={self.interval}"
            f"&algorithm=SHA1"
        )

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self, secret: str, token: str) -> bool:
        """
        Verify a user-supplied TOTP token.

        Args:
            secret: The stored Base-32 secret for this user.
            token: The 6-digit token from the authenticator app.

        Returns:
            True if the token is valid (with ±1 window tolerance), False otherwise.
        """
        token = token.strip().replace(" ", "")
        if len(token) != self.digits or not token.isdigit():
            return False

        if _PYOTP_AVAILABLE:
            totp = pyotp.TOTP(secret, digits=self.digits, interval=self.interval)
            return totp.verify(token, valid_window=self.valid_window)

        # Fallback TOTP implementation (HMAC-SHA1 per RFC 6238)
        return self._verify_fallback(secret, token)

    def _verify_fallback(self, secret: str, token: str) -> bool:
        """Pure-Python TOTP verification (no pyotp dependency)."""
        import base64
        import hmac
        import struct

        try:
            padding = (8 - len(secret) % 8) % 8
            key = base64.b32decode(secret.upper() + "=" * padding)
        except Exception:
            return False

        counter = int(time.time()) // self.interval

        for delta in range(-self.valid_window, self.valid_window + 1):
            c = counter + delta
            msg = struct.pack(">Q", c)
            mac = hmac.new(key, msg, hashlib.sha1).digest()  # type: ignore[attr-defined]
            offset = mac[-1] & 0x0F
            code = (
                (mac[offset] & 0x7F) << 24
                | mac[offset + 1] << 16
                | mac[offset + 2] << 8
                | mac[offset + 3]
            ) % (10 ** self.digits)
            if str(code).zfill(self.digits) == token:
                return True

        return False

    # ------------------------------------------------------------------
    # Backup codes
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_backup_codes(count: int = _BACKUP_CODE_COUNT) -> List[str]:
        """Generate one-time backup codes."""
        codes: List[str] = []
        for _ in range(count):
            code = secrets.token_hex(5)  # 10 hex chars = 40 bits
            codes.append(code.upper())
        return codes

    @staticmethod
    def verify_backup_code(candidate: str, stored_hashes: List[str]) -> tuple[bool, List[str]]:
        """
        Verify a backup code and consume it (remove from the stored hashes).

        Args:
            candidate: The backup code supplied by the user.
            stored_hashes: List of SHA-256 hashes currently stored in the DB.

        Returns:
            (success, updated_hashes) — updated_hashes has the used code removed.
        """
        candidate_hash = _hash_backup_code(candidate.strip().upper())
        if candidate_hash in stored_hashes:
            updated = [h for h in stored_hashes if h != candidate_hash]
            logger.info("Backup code consumed — %d remaining", len(updated))
            return True, updated
        return False, stored_hashes


# ---------------------------------------------------------------------------
# Module-level singleton (convenience)
# ---------------------------------------------------------------------------
totp_manager = TOTPManager()
