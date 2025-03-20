"""
TLS Inspector Module - Month 5

TLS/SSL certificate inspection and analysis.
Extracts certificate details, analyzes cipher suites, and performs JARM fingerprinting.
"""

import ssl
import socket
import asyncio
import hashlib
from typing import Optional
from datetime import datetime, timezone
import logging

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .schemas import TLSCertInfo, TLSInfo

logger = logging.getLogger(__name__)


# Weak cipher suites to detect
WEAK_CIPHERS = {
    'RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon',
    'ADH', 'AECDH', '3DES'
}


class TLSInspector:
    """
    TLS/SSL certificate inspection and analysis.
    
    Features:
    - Certificate extraction and parsing
    - Subject and SAN extraction
    - Expiration date analysis
    - Cipher suite analysis
    - Weak cipher detection
    - JARM fingerprinting
    """
    
    def __init__(self, timeout: int = 10):
        """
        Initialize TLS inspector.
        
        Args:
            timeout: Connection timeout in seconds
        """
        self.timeout = timeout
    
    async def inspect_tls(self, host: str, port: int = 443) -> Optional[TLSInfo]:
        """
        Inspect TLS/SSL for a host.
        
        Args:
            host: Target hostname
            port: Target port (default 443)
            
        Returns:
            TLSInfo object with certificate and cipher information
        """
        try:
            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None,
                self._inspect_tls_sync,
                host,
                port
            )
        except Exception as e:
            logger.error(f"TLS inspection failed for {host}:{port}: {e}")
            return None
    
    def _inspect_tls_sync(self, host: str, port: int) -> Optional[TLSInfo]:
        """Synchronous TLS inspection"""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get certificate in DER format
                    cert_der = ssock.getpeercert(binary_form=True)
                    
                    # Get cipher info
                    cipher_info = ssock.cipher()
                    tls_version = ssock.version()
                    
                    # Parse certificate
                    cert_info = self._parse_certificate(cert_der)
                    
                    # Analyze cipher
                    cipher_name = cipher_info[0] if cipher_info else None
                    cipher_strength = self._analyze_cipher_strength(cipher_name)
                    has_weak_cipher = cipher_strength == "weak"
                    
                    # Generate JARM fingerprint
                    jarm = self._generate_jarm_fingerprint(host, port)
                    
                    return TLSInfo(
                        version=tls_version,
                        cipher_suite=cipher_name,
                        cipher_strength=cipher_strength,
                        certificate=cert_info,
                        jarm_fingerprint=jarm,
                        has_weak_cipher=has_weak_cipher
                    )
                    
        except Exception as e:
            logger.debug(f"TLS inspection error for {host}:{port}: {e}")
            return None
    
    def _parse_certificate(self, cert_der: bytes) -> TLSCertInfo:
        """Parse X.509 certificate"""
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            
            # Extract subject
            subject = cert.subject.rfc4514_string()
            
            # Extract issuer
            issuer = cert.issuer.rfc4514_string()
            
            # Extract serial number
            serial_number = format(cert.serial_number, 'x')
            
            # Extract validity dates
            not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
            not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
            
            # Make timezone-aware if needed
            if not_before.tzinfo is None:
                not_before = not_before.replace(tzinfo=timezone.utc)
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=timezone.utc)
            
            # Calculate days until expiry
            now = datetime.now(timezone.utc)
            days_until_expiry = (not_after - now).days
            is_expired = days_until_expiry < 0
            
            # Extract SANs
            sans = []
            try:
                san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                sans = [name.value for name in san_ext.value]
            except x509.ExtensionNotFound:
                pass
            
            # Extract signature algorithm
            sig_algo = cert.signature_algorithm_oid._name
            
            # Extract public key info
            public_key = cert.public_key()
            public_key_type = type(public_key).__name__
            public_key_bits = public_key.key_size if hasattr(public_key, 'key_size') else None
            
            # Check if self-signed
            is_self_signed = subject == issuer
            
            return TLSCertInfo(
                subject=subject,
                issuer=issuer,
                serial_number=serial_number,
                not_before=not_before,
                not_after=not_after,
                days_until_expiry=days_until_expiry,
                subject_alt_names=sans,
                signature_algorithm=sig_algo,
                public_key_type=public_key_type,
                public_key_bits=public_key_bits,
                is_expired=is_expired,
                is_self_signed=is_self_signed
            )
            
        except Exception as e:
            logger.error(f"Certificate parsing error: {e}")
            return TLSCertInfo()
    
    def _analyze_cipher_strength(self, cipher_name: Optional[str]) -> str:
        """
        Analyze cipher suite strength.
        
        Returns:
            "strong", "medium", or "weak"
        """
        if not cipher_name:
            return "unknown"
        
        cipher_upper = cipher_name.upper()
        
        # Check for weak ciphers
        for weak in WEAK_CIPHERS:
            if weak in cipher_upper:
                return "weak"
        
        # Check for strong ciphers (GCM, ChaCha20)
        if 'GCM' in cipher_upper or 'CHACHA20' in cipher_upper:
            return "strong"
        
        # Default to medium
        return "medium"
    
    def _generate_jarm_fingerprint(self, host: str, port: int) -> Optional[str]:
        """
        Generate JARM fingerprint for the host.
        
        JARM is an active TLS server fingerprinting tool.
        This is a simplified implementation.
        
        Args:
            host: Target hostname
            port: Target port
            
        Returns:
            JARM fingerprint hash or None
        """
        try:
            # Simplified JARM: collect TLS handshake details
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            fingerprint_data = []
            
            # Try different TLS versions and cipher suites
            for protocol in [ssl.PROTOCOL_TLS, ssl.PROTOCOL_TLSv1_2]:
                try:
                    ctx = ssl.SSLContext(protocol)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((host, port), timeout=5) as sock:
                        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                            cipher = ssock.cipher()
                            version = ssock.version()
                            fingerprint_data.append(f"{version}:{cipher[0] if cipher else 'none'}")
                except Exception:
                    fingerprint_data.append("failed")
            
            # Create hash of collected data
            fingerprint_str = "|".join(fingerprint_data)
            jarm_hash = hashlib.sha256(fingerprint_str.encode()).hexdigest()[:62]
            
            return jarm_hash
            
        except Exception as e:
            logger.debug(f"JARM fingerprinting failed for {host}:{port}: {e}")
            return None
