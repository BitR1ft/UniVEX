"""
Proxy SSL Context Manager

Provides dynamic SSL certificate generation for HTTPS interception:
  - Generates a self-signed Certificate Authority (CA) on first use
  - Issues per-domain leaf certificates signed by the CA on demand
  - Caches issued certificates in memory (LRU) so repeated connections
    to the same host do not incur re-generation cost

Dependencies: cryptography (already in requirements.txt)
"""

from __future__ import annotations

import datetime
import ipaddress
import logging
import os
import threading
from collections import OrderedDict
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional import — graceful degradation when cryptography is unavailable
# ---------------------------------------------------------------------------

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    _CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover
    _CRYPTO_AVAILABLE = False
    logger.warning(
        "cryptography package not found — SSLContextManager will raise RuntimeError"
    )

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CA_KEY_SIZE = 4096
_LEAF_KEY_SIZE = 2048
_CERT_VALIDITY_DAYS_CA = 3650  # 10 years
_CERT_VALIDITY_DAYS_LEAF = 365
_CACHE_MAX_SIZE = 256  # maximum number of per-domain certificates to cache


class SSLContextManager:
    """
    Dynamic SSL certificate factory for HTTPS man-in-the-middle interception.

    Usage::

        mgr = SSLContextManager()
        mgr.initialize()                          # generates CA key + cert
        leaf_cert, leaf_key = mgr.get_cert("example.com")

    The CA certificate (PEM) is available via ``mgr.ca_cert_pem`` and should
    be distributed to clients so that browser/tooling trust the intercepted
    connections.

    Thread-safe: all mutating operations are protected by a single lock.
    """

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(
        self,
        ca_cert_path: Optional[str] = None,
        ca_key_path: Optional[str] = None,
        cache_size: int = _CACHE_MAX_SIZE,
    ) -> None:
        """
        Args:
            ca_cert_path: Optional file path to persist the CA certificate.
            ca_key_path:  Optional file path to persist the CA private key.
            cache_size:   Maximum number of per-domain certs to hold in memory.
        """
        if not _CRYPTO_AVAILABLE:
            raise RuntimeError(
                "The 'cryptography' package is required for SSLContextManager. "
                "Run: pip install cryptography"
            )

        self._ca_cert_path = ca_cert_path
        self._ca_key_path = ca_key_path
        self._cache_size = cache_size
        self._lock = threading.RLock()

        # State — populated by initialize()
        self._ca_key: Optional[rsa.RSAPrivateKey] = None
        self._ca_cert: Optional[x509.Certificate] = None
        self._cert_cache: OrderedDict[str, Tuple[bytes, bytes]] = OrderedDict()
        self._initialized = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """
        Generate (or load from disk) the CA key + certificate.

        Idempotent — safe to call multiple times.
        """
        with self._lock:
            if self._initialized:
                return

            # Try to load from disk first
            if self._ca_cert_path and self._ca_key_path:
                if os.path.exists(self._ca_cert_path) and os.path.exists(
                    self._ca_key_path
                ):
                    self._load_ca_from_disk()
                    self._initialized = True
                    logger.info("Loaded CA certificate and key from disk.")
                    return

            # Generate new CA
            self._generate_ca()

            # Persist if paths are configured
            if self._ca_cert_path and self._ca_key_path:
                self._save_ca_to_disk()

            self._initialized = True
            logger.info("Generated new CA certificate.")

    @property
    def initialized(self) -> bool:
        return self._initialized

    @property
    def ca_cert_pem(self) -> bytes:
        """Return the CA certificate as PEM bytes."""
        self._ensure_initialized()
        return self._ca_cert.public_bytes(serialization.Encoding.PEM)

    @property
    def ca_key_pem(self) -> bytes:
        """Return the CA private key as PEM bytes (unencrypted)."""
        self._ensure_initialized()
        return self._ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def get_cert(self, hostname: str) -> Tuple[bytes, bytes]:
        """
        Return a (cert_pem, key_pem) tuple for the given hostname.

        Certificates are cached — repeated calls for the same hostname return
        the cached pair without re-generating.

        Args:
            hostname: Domain name or IP address to issue a certificate for.

        Returns:
            Tuple of (certificate PEM bytes, private key PEM bytes).
        """
        self._ensure_initialized()

        with self._lock:
            if hostname in self._cert_cache:
                self._cert_cache.move_to_end(hostname)
                return self._cert_cache[hostname]

            cert_pem, key_pem = self._issue_leaf_cert(hostname)

            # Evict LRU entry if cache is full
            if len(self._cert_cache) >= self._cache_size:
                self._cert_cache.popitem(last=False)

            self._cert_cache[hostname] = (cert_pem, key_pem)
            return cert_pem, key_pem

    def clear_cache(self) -> None:
        """Clear the per-domain certificate cache."""
        with self._lock:
            self._cert_cache.clear()

    @property
    def cache_size(self) -> int:
        with self._lock:
            return len(self._cert_cache)

    def export_ca_cert(self, path: str) -> None:
        """Write CA certificate PEM to *path* for distribution to clients."""
        self._ensure_initialized()
        with open(path, "wb") as fh:
            fh.write(self.ca_cert_pem)
        logger.info(f"CA certificate exported to {path}")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _ensure_initialized(self) -> None:
        if not self._initialized:
            raise RuntimeError(
                "SSLContextManager is not initialized. Call initialize() first."
            )

    def _generate_ca(self) -> None:
        """Generate a new RSA private key and self-signed CA certificate."""
        self._ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=_CA_KEY_SIZE,
            backend=default_backend(),
        )

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "UniVex Intercept CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UniVex"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            ]
        )

        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        self._ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=_CERT_VALIDITY_DAYS_CA))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self._ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self._ca_key, hashes.SHA256(), default_backend())
        )

    def _issue_leaf_cert(self, hostname: str) -> Tuple[bytes, bytes]:
        """Generate a leaf certificate signed by our CA for *hostname*."""
        leaf_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=_LEAF_KEY_SIZE,
            backend=default_backend(),
        )

        # Build Subject Alternative Names
        try:
            san: x509.GeneralName = x509.IPAddress(
                ipaddress.ip_address(hostname)
            )
        except ValueError:
            san = x509.DNSName(hostname)

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UniVex Intercept"),
            ]
        )

        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=_CERT_VALIDITY_DAYS_LEAF))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName([san]),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256(), default_backend())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return cert_pem, key_pem

    def _save_ca_to_disk(self) -> None:
        os.makedirs(os.path.dirname(self._ca_cert_path) or ".", exist_ok=True)
        # Access the raw objects directly — _initialized may not be set yet
        cert_pem = self._ca_cert.public_bytes(serialization.Encoding.PEM)
        key_pem = self._ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(self._ca_cert_path, "wb") as fh:
            fh.write(cert_pem)
        with open(self._ca_key_path, "wb") as fh:
            fh.write(key_pem)

    def _load_ca_from_disk(self) -> None:
        with open(self._ca_cert_path, "rb") as fh:
            self._ca_cert = x509.load_pem_x509_certificate(
                fh.read(), default_backend()
            )
        with open(self._ca_key_path, "rb") as fh:
            self._ca_key = serialization.load_pem_private_key(
                fh.read(), password=None, backend=default_backend()
            )
