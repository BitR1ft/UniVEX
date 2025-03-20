"""
Certificate Manager — CA, server, and client cert lifecycle management.

"""
from __future__ import annotations

import datetime
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from prometheus_client import Counter, Gauge

logger = logging.getLogger(__name__)

# Prometheus metrics
_cert_expiry_gauge = Gauge(
    "univex_cert_expiry_days",
    "Days until certificate expires",
    ["server_name"],
)
_cert_rotations_counter = Counter(
    "univex_cert_rotations_total",
    "Total certificate rotations",
    ["server_name"],
)


@dataclass
class CertConfig:
    """Configuration for certificate generation."""
    common_name: str
    organization: str = "UniVex"
    country: str = "US"
    validity_days: int = 365
    key_size: int = 2048


class CertManager:
    """
    Manages certificate lifecycle: generation, storage, rotation, and revocation.

    Uses the Python `cryptography` library to generate RSA keys and X.509 certs.
    """

    def __init__(self) -> None:
        # Map from cert serial (int) to reason string
        self._revoked: Dict[int, str] = {}

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    def _generate_private_key(self, key_size: int) -> RSAPrivateKey:
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

    def _build_name(self, config: CertConfig) -> x509.Name:
        return x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, config.country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.organization),
            x509.NameAttribute(NameOID.COMMON_NAME, config.common_name),
        ])

    # ------------------------------------------------------------------
    # Certificate generation
    # ------------------------------------------------------------------

    def generate_ca(self, config: CertConfig) -> Tuple[RSAPrivateKey, Certificate]:
        """Generate a CA key and self-signed certificate."""
        key = self._generate_private_key(config.key_size)
        name = self._build_name(config)
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=config.validity_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        logger.info("Generated CA certificate: CN=%s", config.common_name)
        return key, cert

    def generate_server_cert(
        self,
        server_name: str,
        ca_key: RSAPrivateKey,
        ca_cert: Certificate,
        config: Optional[CertConfig] = None,
    ) -> Tuple[RSAPrivateKey, Certificate]:
        """Generate a server certificate signed by *ca_key*/*ca_cert*."""
        if config is None:
            config = CertConfig(common_name=server_name)
        key = self._generate_private_key(config.key_size)
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(self._build_name(config))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=config.validity_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(server_name)]),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        days_left = self.check_expiry(cert)
        _cert_expiry_gauge.labels(server_name=server_name).set(days_left)
        logger.info("Generated server certificate: CN=%s", config.common_name)
        return key, cert

    def generate_client_cert(
        self,
        client_name: str,
        ca_key: RSAPrivateKey,
        ca_cert: Certificate,
        config: Optional[CertConfig] = None,
    ) -> Tuple[RSAPrivateKey, Certificate]:
        """Generate a client certificate signed by *ca_key*/*ca_cert*."""
        if config is None:
            config = CertConfig(common_name=client_name)
        key = self._generate_private_key(config.key_size)
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(self._build_name(config))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=config.validity_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        logger.info("Generated client certificate: CN=%s", config.common_name)
        return key, cert

    # ------------------------------------------------------------------
    # Save / load
    # ------------------------------------------------------------------

    def save_cert(self, cert: Certificate, path: str) -> None:
        """Write a PEM-encoded certificate to *path*."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def save_key(self, key: RSAPrivateKey, path: str, password: Optional[bytes] = None) -> None:
        """Write a PEM-encoded private key to *path* (mode 600)."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption,
        )
        with open(path, "wb") as f:
            f.write(pem)
        os.chmod(path, 0o600)

    def load_cert(self, path: str) -> Certificate:
        """Load a PEM certificate from *path*."""
        with open(path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())

    def load_key(self, path: str, password: Optional[bytes] = None) -> RSAPrivateKey:
        """Load a PEM private key from *path*."""
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=password)  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Expiry & revocation
    # ------------------------------------------------------------------

    def check_expiry(self, cert: Certificate) -> int:
        """Return the number of days until *cert* expires (negative if expired)."""
        now = datetime.datetime.now(datetime.timezone.utc)
        # not_valid_after_utc is available in cryptography >= 42; fall back for older installs.
        try:
            expiry = cert.not_valid_after_utc
        except AttributeError:
            expiry = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)  # type: ignore[union-attr]
        delta = expiry - now
        return delta.days

    def is_expired(self, cert: Certificate) -> bool:
        """Return True if *cert* has passed its expiry date."""
        return self.check_expiry(cert) < 0

    def revoke_cert(self, cert_serial: int, reason: str = "unspecified") -> None:
        """Add *cert_serial* to the revocation list."""
        self._revoked[cert_serial] = reason
        logger.info("Revoked certificate serial=%d reason=%s", cert_serial, reason)

    def get_revocation_list(self) -> List[Dict]:
        """Return list of revoked cert info dicts."""
        return [{"serial": s, "reason": r} for s, r in self._revoked.items()]

    # ------------------------------------------------------------------
    # Rotation
    # ------------------------------------------------------------------

    def rotate_cert(
        self,
        server_name: str,
        ca_key: RSAPrivateKey,
        ca_cert: Certificate,
        config: Optional[CertConfig] = None,
    ) -> Tuple[RSAPrivateKey, Certificate]:
        """Atomically generate a replacement server cert for *server_name*."""
        key, cert = self.generate_server_cert(server_name, ca_key, ca_cert, config)
        _cert_rotations_counter.labels(server_name=server_name).inc()
        logger.info("Rotated certificate for server=%s", server_name)
        return key, cert

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_cert(self, cert: Certificate, ca_cert: Certificate) -> bool:
        """Verify that *cert* was signed by *ca_cert*."""
        try:
            from cryptography.hazmat.primitives.asymmetric import padding
            ca_cert.public_key().verify(  # type: ignore[union-attr]
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            return True
        except Exception:
            return False
