"""

Sends structured syslog messages over UDP, TCP, or TLS.

Usage::

    fwd = SyslogForwarder(host="siem.corp.internal", port=514,
                          protocol=SyslogProtocol.UDP)
    fwd.send(SyslogMessage(severity=SyslogSeverity.ERR,
                           facility=SyslogFacility.SECURITY,
                           app_name="univex",
                           msg_id="FINDING",
                           message="SQL Injection found on /login"))
"""
from __future__ import annotations

import logging
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# RFC 5424 enumerations
# ---------------------------------------------------------------------------

class SyslogFacility(IntEnum):
    """RFC 5424 / RFC 3164 facility codes."""
    KERN = 0
    USER = 1
    MAIL = 2
    DAEMON = 3
    AUTH = 4
    SYSLOG = 5
    LPR = 6
    NEWS = 7
    UUCP = 8
    CRON = 9
    SECURITY = 10   # commonly used for security tools
    FTP = 11
    NTP = 12
    LOG_AUDIT = 13
    LOG_ALERT = 14
    CLOCK = 15
    LOCAL0 = 16
    LOCAL1 = 17
    LOCAL2 = 18
    LOCAL3 = 19
    LOCAL4 = 20
    LOCAL5 = 21
    LOCAL6 = 22
    LOCAL7 = 23


class SyslogSeverity(IntEnum):
    """RFC 5424 severity levels (lower = more severe)."""
    EMERG = 0
    ALERT = 1
    CRIT = 2
    ERR = 3
    WARNING = 4
    NOTICE = 5
    INFO = 6
    DEBUG = 7


class SyslogProtocol(str):
    """Transport protocol for syslog delivery."""
    UDP = "udp"
    TCP = "tcp"
    TLS = "tls"

    @classmethod
    def values(cls):
        return {cls.UDP, cls.TCP, cls.TLS}


# ---------------------------------------------------------------------------
# RFC 5424 message model
# ---------------------------------------------------------------------------

NILVALUE = "-"


@dataclass
class SyslogMessage:
    """Represents a single RFC 5424 syslog message."""

    message: str
    severity: SyslogSeverity = SyslogSeverity.INFO
    facility: SyslogFacility = SyslogFacility.SECURITY
    app_name: str = "univex"
    proc_id: str = NILVALUE
    msg_id: str = NILVALUE
    structured_data: Optional[str] = None  # SD-ELEMENT string, e.g. '[mySD@1234 key="val"]'
    hostname: Optional[str] = None
    timestamp: Optional[datetime] = None

    def __post_init__(self) -> None:
        if self.timestamp is None:
            self.timestamp = datetime.now(tz=timezone.utc)
        if self.hostname is None:
            self.hostname = socket.gethostname()

    @property
    def priority(self) -> int:
        return self.facility * 8 + self.severity

    def to_rfc5424(self) -> str:
        """
        Serialise the message to a full RFC 5424 SYSLOG-MSG string.

        Format:
          <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID
          STRUCTURED-DATA MSG
        """
        pri = f"<{self.priority}>"
        version = "1"
        ts = self.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        hostname = (self.hostname or NILVALUE)[:255]
        app_name = (self.app_name or NILVALUE)[:48]
        proc_id = (self.proc_id or NILVALUE)[:128]
        msg_id = (self.msg_id or NILVALUE)[:32]
        structured_data = self.structured_data or NILVALUE

        header = f"{pri}{version} {ts} {hostname} {app_name} {proc_id} {msg_id}"
        return f"{header} {structured_data} \ufeff{self.message}"


# ---------------------------------------------------------------------------
# SyslogForwarder
# ---------------------------------------------------------------------------

class SyslogForwarder:
    """
    Forwards RFC 5424 syslog messages over UDP, TCP, or TLS.

    Parameters
    ----------
    host        : SIEM / syslog server hostname or IP.
    port        : Destination port (default 514 for UDP/TCP, 6514 for TLS).
    protocol    : "udp" | "tcp" | "tls" (default: "udp").
    tls_ca_cert : Path to CA certificate file for TLS verification.
    tls_verify  : Whether to verify the server's TLS certificate.
    timeout     : Socket timeout in seconds.
    """

    def __init__(
        self,
        host: str,
        port: Optional[int] = None,
        protocol: str = SyslogProtocol.UDP,
        *,
        tls_ca_cert: Optional[str] = None,
        tls_verify: bool = True,
        timeout: float = 5.0,
    ) -> None:
        if protocol not in SyslogProtocol.values():
            raise ValueError(f"protocol must be one of {SyslogProtocol.values()}")

        self.host = host
        self.protocol = protocol
        self.tls_ca_cert = tls_ca_cert
        self.tls_verify = tls_verify
        self.timeout = timeout

        if port is None:
            self.port = 6514 if protocol == SyslogProtocol.TLS else 514
        else:
            self.port = port

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send(self, message: SyslogMessage) -> bool:
        """
        Send a single syslog message.

        Returns ``True`` on success, ``False`` on failure (error is logged).
        """
        raw = message.to_rfc5424().encode("utf-8")
        try:
            if self.protocol == SyslogProtocol.UDP:
                return self._send_udp(raw)
            if self.protocol == SyslogProtocol.TCP:
                return self._send_tcp(raw)
            if self.protocol == SyslogProtocol.TLS:
                return self._send_tls(raw)
            raise ValueError(f"Unknown protocol: {self.protocol}")
        except Exception as exc:
            logger.error("SyslogForwarder.send failed: %s", exc)
            return False

    def send_batch(self, messages: list) -> dict:
        """
        Send a list of :class:`SyslogMessage` objects.

        Returns dict with ``sent`` and ``failed`` counts.
        """
        sent = failed = 0
        for msg in messages:
            if self.send(msg):
                sent += 1
            else:
                failed += 1
        return {"sent": sent, "failed": failed}

    # ------------------------------------------------------------------
    # Transport implementations
    # ------------------------------------------------------------------

    def _send_udp(self, raw: bytes) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            sock.sendto(raw, (self.host, self.port))
        return True

    def _send_tcp(self, raw: bytes) -> bool:
        """TCP octet-count framing (RFC 6587 §3.4.1)."""
        framed = f"{len(raw)} ".encode("ascii") + raw
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            sock.sendall(framed)
        return True

    def _send_tls(self, raw: bytes) -> bool:
        """TLS-encrypted TCP with octet-count framing (RFC 5425)."""
        context = ssl.create_default_context()
        # Enforce TLS 1.2 as the minimum — TLS 1.0/1.1 are insecure and deprecated
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if self.tls_ca_cert:
            context.load_verify_locations(self.tls_ca_cert)
        if not self.tls_verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        framed = f"{len(raw)} ".encode("ascii") + raw
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=self.host) as tls_sock:
                tls_sock.sendall(framed)
        return True

    # ------------------------------------------------------------------
    # Convenience factory for findings
    # ------------------------------------------------------------------

    @staticmethod
    def finding_to_message(
        finding_id: str,
        title: str,
        severity: str,
        description: str,
        target: str = "",
        *,
        app_name: str = "univex",
    ) -> SyslogMessage:
        """
        Convert a pentest finding into a :class:`SyslogMessage`.

        Maps finding severity → syslog severity level.
        """
        _sev_map = {
            "critical": SyslogSeverity.CRIT,
            "high": SyslogSeverity.ERR,
            "medium": SyslogSeverity.WARNING,
            "low": SyslogSeverity.NOTICE,
            "info": SyslogSeverity.INFO,
            "informational": SyslogSeverity.INFO,
        }
        syslog_sev = _sev_map.get(severity.lower(), SyslogSeverity.WARNING)

        # Build structured data element per RFC 5424
        sd = (
            f'[univex@12345 findingId="{finding_id}" severity="{severity}" '
            f'target="{target}"]'
        )

        return SyslogMessage(
            message=f"{title}: {description}",
            severity=syslog_sev,
            facility=SyslogFacility.SECURITY,
            app_name=app_name,
            msg_id="FINDING",
            structured_data=sd,
        )
