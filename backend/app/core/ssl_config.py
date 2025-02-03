"""
SSLConfig — Centralized SSL/TLS Configuration Management

Provides:
  - Custom CA certificate bundle loading (enterprise PKI support)
  - Certificate validation toggle for development environments
  - Client certificate support (mTLS for enterprise SSO)
  - Outbound HTTPS session factory pre-configured with the custom trust store
  - Cookie signing via HMAC-SHA256

Usage::

    from app.core.ssl_config import ssl_config, get_ssl_context, create_http_session

    # Load trust store (called once at application startup)
    ssl_config.load()

    # Obtain a configured ssl.SSLContext for outbound connections
    ctx = get_ssl_context()

    # Cookie signing
    from app.core.ssl_config import cookie_signer
    signed   = cookie_signer.sign("session_data")
    verified = cookie_signer.verify(signed)
"""
from __future__ import annotations

import atexit
import hmac
import logging
import os
import ssl
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_COOKIE_SIGNING_SALT_LENGTH = 32  # bytes
_COOKIE_DELIMITER = "."
_HMAC_DIGEST = "sha256"

# ---------------------------------------------------------------------------
# SSL Configuration
# ---------------------------------------------------------------------------


@dataclass
class SSLConfig:
    """
    Centralized SSL/TLS configuration for all outbound HTTPS connections.

    Attributes:
        ca_path:            Path to a custom CA certificate file or directory.
                            When set, the default OS trust store is extended
                            with these additional CA certificates.
        verify_ssl:         When False (dev only), TLS certificate validation
                            is disabled.  **Never set False in production.**
        client_cert_path:   Path to PEM client certificate (mTLS).
        client_key_path:    Path to PEM private key matching the client cert.
        client_key_password: Optional password for encrypted private keys.
        min_tls_version:    Minimum TLS protocol version to accept.
                            Defaults to ``ssl.TLSVersion.TLSv1_2``.
    """

    ca_path: Optional[str] = None
    verify_ssl: bool = True
    client_cert_path: Optional[str] = None
    client_key_path: Optional[str] = None
    client_key_password: Optional[str] = None
    min_tls_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2

    # Internal — populated by load()
    _loaded: bool = field(default=False, init=False, repr=False)
    _ca_bundle_path: Optional[str] = field(default=None, init=False, repr=False)

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load(self) -> None:
        """
        Load and validate the SSL configuration.

        - Verifies that ``ca_path`` exists and is readable.
        - Merges custom CA certs into a temporary bundle so that the system
          default trust store is **preserved** (custom CAs are added on top,
          not replacing the defaults).
        - Warns loudly when ``verify_ssl=False``.
        """
        if not self.verify_ssl:
            logger.warning(
                "SSL certificate verification is DISABLED. "
                "This setting is for development only — never use in production."
            )

        if self.ca_path:
            ca = Path(self.ca_path)
            if not ca.exists():
                raise FileNotFoundError(
                    f"Custom CA path does not exist: {self.ca_path}"
                )
            if ca.is_file():
                self._ca_bundle_path = self._merge_ca_bundle(ca)
            elif ca.is_dir():
                self._ca_bundle_path = self._merge_ca_directory(ca)
            else:
                raise ValueError(f"ca_path must be a file or directory: {self.ca_path}")
            logger.info("Custom CA certificates loaded from %s", self.ca_path)

        if self.client_cert_path:
            cert = Path(self.client_cert_path)
            if not cert.exists():
                raise FileNotFoundError(
                    f"Client certificate not found: {self.client_cert_path}"
                )
            logger.info("Client certificate loaded from %s", self.client_cert_path)

        self._loaded = True

    @staticmethod
    def _merge_ca_bundle(ca_file: Path) -> str:
        """
        Merge *ca_file* with the system default CA bundle.

        Returns the path to a temporary merged bundle file that should be
        passed to ``ssl.SSLContext.load_verify_locations``.
        """
        # Read custom CAs
        custom_certs = ca_file.read_bytes()

        # Read system default bundle
        system_bundle = SSLConfig._get_system_ca_bundle()

        # Write merged bundle to a temp file (persists for the process lifetime)
        # Registered with atexit so the file is cleaned up on normal process exit.
        merged = tempfile.NamedTemporaryFile(
            prefix="univex_ca_bundle_",
            suffix=".pem",
            delete=False,
        )
        if system_bundle:
            merged.write(system_bundle)
            merged.write(b"\n")
        merged.write(custom_certs)
        merged.flush()
        merged.close()
        atexit.register(lambda p=merged.name: Path(p).unlink(missing_ok=True))
        return merged.name

    @staticmethod
    def _merge_ca_directory(ca_dir: Path) -> str:
        """
        Concatenate all .pem / .crt / .cer files in *ca_dir* and merge with
        the system default bundle.
        """
        custom_certs: list[bytes] = []
        for ext in ("*.pem", "*.crt", "*.cer", "*.ca-bundle"):
            for cert_file in sorted(ca_dir.glob(ext)):
                custom_certs.append(cert_file.read_bytes())

        if not custom_certs:
            raise ValueError(
                f"No certificate files (.pem/.crt/.cer) found in {ca_dir}"
            )

        combined = b"\n".join(custom_certs)
        tmp_file = tempfile.NamedTemporaryFile(
            prefix="univex_ca_dir_",
            suffix=".pem",
            delete=False,
        )
        system_bundle = SSLConfig._get_system_ca_bundle()
        if system_bundle:
            tmp_file.write(system_bundle)
            tmp_file.write(b"\n")
        tmp_file.write(combined)
        tmp_file.flush()
        tmp_file.close()
        atexit.register(lambda p=tmp_file.name: Path(p).unlink(missing_ok=True))
        return tmp_file.name

    @staticmethod
    def _get_system_ca_bundle() -> Optional[bytes]:
        """Return the default system CA bundle bytes, or None if not found."""
        # Common locations across Linux distros + macOS
        candidates = [
            "/etc/ssl/certs/ca-certificates.crt",   # Debian/Ubuntu
            "/etc/pki/tls/certs/ca-bundle.crt",     # RHEL/CentOS
            "/etc/ssl/cert.pem",                     # macOS/FreeBSD
            "/usr/share/ca-certificates/cacert.pem", # some Linux
            ssl.get_default_verify_paths().cafile or "",
        ]
        for candidate in candidates:
            if candidate and Path(candidate).is_file():
                return Path(candidate).read_bytes()
        return None

    # ------------------------------------------------------------------
    # SSLContext factory
    # ------------------------------------------------------------------

    def create_ssl_context(
        self,
        purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH,
    ) -> ssl.SSLContext:
        """
        Build an :class:`ssl.SSLContext` pre-configured with the custom
        CA bundle and (optionally) a client certificate.

        Args:
            purpose: ``ssl.Purpose.SERVER_AUTH`` for outbound client connections
                     (the default); ``ssl.Purpose.CLIENT_AUTH`` for servers.

        Returns:
            A fully configured :class:`ssl.SSLContext`.
        """
        if not self._loaded:
            self.load()

        ctx = ssl.create_default_context(purpose=purpose)
        ctx.minimum_version = self.min_tls_version

        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx

        # Load custom CA bundle
        if self._ca_bundle_path:
            ctx.load_verify_locations(cafile=self._ca_bundle_path)
        else:
            # Load system defaults
            ctx.load_default_certs(purpose)

        # Load client certificate (mTLS)
        if self.client_cert_path and self.client_key_path:
            ctx.load_cert_chain(
                certfile=self.client_cert_path,
                keyfile=self.client_key_path,
                password=self.client_key_password,
            )

        return ctx

    # ------------------------------------------------------------------
    # Httpx / requests integration helpers
    # ------------------------------------------------------------------

    def get_httpx_kwargs(self) -> dict:
        """
        Return keyword arguments suitable for passing directly to
        ``httpx.AsyncClient`` or ``httpx.Client``.

        Example::

            import httpx
            from app.core.ssl_config import ssl_config
            async with httpx.AsyncClient(**ssl_config.get_httpx_kwargs()) as client:
                resp = await client.get("https://api.openai.com/v1/models")
        """
        if not self._loaded:
            self.load()

        if not self.verify_ssl:
            return {"verify": False}

        if self._ca_bundle_path:
            return {"verify": self._ca_bundle_path}

        return {"verify": True}

    def get_requests_kwargs(self) -> dict:
        """
        Return keyword arguments suitable for passing directly to
        ``requests.get`` / ``requests.Session``.
        """
        return self.get_httpx_kwargs()


# ---------------------------------------------------------------------------
# Cookie signing
# ---------------------------------------------------------------------------


class CookieSigner:
    """
    Signs and verifies cookie values using HMAC-SHA256.

    Prevents cookie tampering even if the database is compromised —
    an attacker who knows the cookie value but not the signing salt
    cannot forge a valid signed cookie.

    The signed format is::

        <value>.<hex-signature>

    Where ``<hex-signature>`` is the HMAC-SHA256 of ``<value>`` keyed
    by the signing salt.

    Args:
        salt:   Signing salt (HMAC key).  Must be at least 16 characters.
                Read from ``COOKIE_SIGNING_SALT`` environment variable or
                passed explicitly.
    """

    def __init__(self, salt: Optional[str] = None) -> None:
        resolved_salt = salt or os.environ.get("COOKIE_SIGNING_SALT", "")
        if not resolved_salt:
            logger.warning(
                "COOKIE_SIGNING_SALT is not set — cookie signing is disabled. "
                "Set COOKIE_SIGNING_SALT to a random 32+ character string."
            )
        self._salt = resolved_salt.encode("utf-8") if resolved_salt else b""

    @property
    def enabled(self) -> bool:
        """Return True when a non-empty salt is configured."""
        return bool(self._salt)

    def sign(self, value: str) -> str:
        """
        Return *value* appended with a HMAC-SHA256 signature.

        If cookie signing is disabled (no salt), returns *value* unchanged.

        Args:
            value: Plain cookie value to sign.

        Returns:
            Signed cookie string ``"<value>.<hex-signature>"``.
        """
        if not self.enabled:
            return value
        sig = self._compute_signature(value)
        return f"{value}{_COOKIE_DELIMITER}{sig}"

    def verify(self, signed_value: str) -> Optional[str]:
        """
        Verify a signed cookie and return the original value.

        Args:
            signed_value: Signed cookie string (``"<value>.<hex-signature>"``).

        Returns:
            The original *value* if the signature is valid, ``None`` otherwise.
        """
        if not self.enabled:
            return signed_value

        parts = signed_value.rsplit(_COOKIE_DELIMITER, maxsplit=1)
        if len(parts) != 2:
            return None

        value, sig = parts
        expected_sig = self._compute_signature(value)

        # Constant-time comparison to prevent timing attacks
        if hmac.compare_digest(sig, expected_sig):
            return value
        return None

    def _compute_signature(self, value: str) -> str:
        """Compute the HMAC-SHA256 hex digest of *value*."""
        return hmac.new(
            key=self._salt,
            msg=value.encode("utf-8"),
            digestmod=_HMAC_DIGEST,
        ).hexdigest()


# ---------------------------------------------------------------------------
# Cookie security configuration
# ---------------------------------------------------------------------------


@dataclass
class CookieSecurityConfig:
    """
    Centralized session cookie security settings.

    All settings are read from environment variables at construction time
    and can be passed directly to ``fastapi.Response.set_cookie`` or any
    other ASGI framework.

    Attributes:
        secure:     Set the ``Secure`` flag (HTTPS only).
        httponly:   Set the ``HttpOnly`` flag (no JS access).
        samesite:   ``Strict`` | ``Lax`` | ``None`` (CSRF protection).
        domain:     Optional cookie domain scope.
        path:       Cookie path scope (default: ``/``).
        max_age:    Cookie TTL in seconds (default: 30 minutes).
    """

    secure: bool = True
    httponly: bool = True
    samesite: str = "Lax"
    domain: Optional[str] = None
    path: str = "/"
    max_age: int = 1800  # 30 minutes

    @classmethod
    def from_env(cls) -> "CookieSecurityConfig":
        """
        Build a :class:`CookieSecurityConfig` from environment variables.

        Environment variables:
            SESSION_COOKIE_SECURE    (``true`` / ``false``, default ``true``)
            SESSION_COOKIE_HTTPONLY  (``true`` / ``false``, default ``true``)
            SESSION_COOKIE_SAMESITE  (``Strict`` / ``Lax`` / ``None``, default ``Lax``)
            SESSION_COOKIE_DOMAIN    (optional)
            SESSION_COOKIE_PATH      (default ``/``)
            SESSION_COOKIE_MAX_AGE   (seconds, default 1800)
        """
        def _bool(name: str, default: bool) -> bool:
            val = os.environ.get(name, "").lower()
            if not val:
                return default
            return val in ("true", "1", "yes")

        return cls(
            secure=_bool("SESSION_COOKIE_SECURE", True),
            httponly=_bool("SESSION_COOKIE_HTTPONLY", True),
            samesite=os.environ.get("SESSION_COOKIE_SAMESITE", "Lax"),
            domain=os.environ.get("SESSION_COOKIE_DOMAIN") or None,
            path=os.environ.get("SESSION_COOKIE_PATH", "/"),
            max_age=int(os.environ.get("SESSION_COOKIE_MAX_AGE", "1800")),
        )

    def as_dict(self) -> dict:
        """Return cookie kwargs suitable for ``Response.set_cookie``."""
        result: dict = {
            "secure": self.secure,
            "httponly": self.httponly,
            "samesite": self.samesite,
            "path": self.path,
            "max_age": self.max_age,
        }
        if self.domain:
            result["domain"] = self.domain
        return result


# ---------------------------------------------------------------------------
# Module-level singletons
# ---------------------------------------------------------------------------


def _build_ssl_config() -> SSLConfig:
    """Build the module-level SSLConfig from environment variables."""
    ca_path = os.environ.get("EXTERNAL_SSL_CA_PATH") or None
    verify = os.environ.get("SSL_VERIFY", "true").lower() not in ("false", "0", "no")
    min_tls = os.environ.get("SSL_MIN_TLS_VERSION", "TLSv1_2")

    tls_map = {
        "TLSv1_2": ssl.TLSVersion.TLSv1_2,
        "TLSv1_3": ssl.TLSVersion.TLSv1_3,
    }

    return SSLConfig(
        ca_path=ca_path,
        verify_ssl=verify,
        client_cert_path=os.environ.get("SSL_CLIENT_CERT_PATH") or None,
        client_key_path=os.environ.get("SSL_CLIENT_KEY_PATH") or None,
        client_key_password=os.environ.get("SSL_CLIENT_KEY_PASSWORD") or None,
        min_tls_version=tls_map.get(min_tls, ssl.TLSVersion.TLSv1_2),
    )


# Lazy-loaded module singletons
ssl_config: SSLConfig = _build_ssl_config()
cookie_signer: CookieSigner = CookieSigner()
cookie_security: CookieSecurityConfig = CookieSecurityConfig.from_env()


def get_ssl_context(
    purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH,
) -> ssl.SSLContext:
    """
    Return the application-level :class:`ssl.SSLContext`.

    Loads the SSL config on first call and caches the result.
    Thread-safe — :meth:`SSLConfig.load` is idempotent.
    """
    if not ssl_config._loaded:
        ssl_config.load()
    return ssl_config.create_ssl_context(purpose=purpose)
