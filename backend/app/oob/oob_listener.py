"""
OOB Listener — Out-of-Band Callback Infrastructure

out-of-band callbacks. Supports three channels:

  HTTP listener  (port 8080) — catches blind SSRF, IDOR, and SSTI callbacks
  DNS listener   (configurable) — detects blind XXE and RCE via DNS exfiltration
  SMTP listener  (port 2525)  — detects blind command injection via email

Architecture
------------
  OOBListener          — central coordinator; spawns all sub-listeners
  OOBHTTPListener      — asyncio HTTP server that logs inbound GET/POST
  OOBDNSListener       — asyncio UDP DNS server that logs A/AAAA queries
  OOBSMTPListener      — asyncio SMTP server that logs inbound mail
  OOBCallback          — Pydantic model for a single received callback
  OOBCallbackStore     — in-memory store with correlation (token → callbacks)

Usage
-----
Each test is assigned a unique *token* via `OOBListener.generate_token(test_id)`.
The agent embeds this token in payloads (e.g., http://oob.univex.local:8080/<token>).
When the target application fetches the callback URL the OOBListener logs it and
`OOBListener.get_callbacks(token)` returns the correlated events.

Environment variables
---------------------
  OOB_EXTERNAL_IP     — public/routable IP for callback URL generation (default 127.0.0.1)
  OOB_HTTP_PORT       — HTTP listener port (default 8080)
  OOB_DNS_PORT        — DNS listener port (default 5353)
  OOB_SMTP_PORT       — SMTP listener port (default 2525)
  OOB_TOKEN_TTL       — seconds before callbacks are pruned (default 3600)
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

OOB_EXTERNAL_IP: str = os.getenv("OOB_EXTERNAL_IP", "127.0.0.1")
OOB_HTTP_PORT: int = int(os.getenv("OOB_HTTP_PORT", "8080"))
OOB_DNS_PORT: int = int(os.getenv("OOB_DNS_PORT", "5353"))
OOB_SMTP_PORT: int = int(os.getenv("OOB_SMTP_PORT", "2525"))
OOB_TOKEN_TTL: int = int(os.getenv("OOB_TOKEN_TTL", "3600"))

# Signing key for token HMAC — prevents forged callback registrations
_SIGNING_KEY: bytes = os.getenv("OOB_SIGNING_KEY", secrets.token_hex(32)).encode()


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class OOBCallback:
    """A single out-of-band callback event received by a listener."""

    token: str
    channel: str  # "http" | "dns" | "smtp"
    source_ip: str
    source_port: int
    timestamp: float = field(default_factory=time.time)
    payload: str = ""
    method: str = ""  # HTTP method / DNS query type / SMTP verb
    path: str = ""  # HTTP request path / DNS query name / SMTP recipient

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token": self.token,
            "channel": self.channel,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "timestamp": self.timestamp,
            "datetime": datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat(),
            "payload": self.payload,
            "method": self.method,
            "path": self.path,
        }


class OOBCallbackStore:
    """
    Thread-safe in-memory store for OOB callbacks.

    Keys are *tokens* (short hex strings).  Old entries are evicted on access
    if they are older than ``OOB_TOKEN_TTL`` seconds.
    """

    def __init__(self, ttl: int = OOB_TOKEN_TTL) -> None:
        self._ttl = ttl
        self._store: Dict[str, List[OOBCallback]] = {}
        self._registered_at: Dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def register_token(self, token: str) -> None:
        """Reserve a slot for *token* before any callbacks arrive."""
        async with self._lock:
            if token not in self._store:
                self._store[token] = []
                self._registered_at[token] = time.time()

    async def record(self, callback: OOBCallback) -> None:
        """Store a received *callback*."""
        async with self._lock:
            if callback.token not in self._store:
                self._store[callback.token] = []
                self._registered_at[callback.token] = time.time()
            self._store[callback.token].append(callback)

    async def get(self, token: str) -> List[OOBCallback]:
        """Return all callbacks for *token* (may be empty list)."""
        await self._evict()
        async with self._lock:
            return list(self._store.get(token, []))

    async def _evict(self) -> None:
        now = time.time()
        async with self._lock:
            stale = [t for t, ts in self._registered_at.items() if now - ts > self._ttl]
            for t in stale:
                self._store.pop(t, None)
                self._registered_at.pop(t, None)

    async def all_tokens(self) -> List[str]:
        await self._evict()
        async with self._lock:
            return list(self._store.keys())


# ---------------------------------------------------------------------------
# HTTP listener
# ---------------------------------------------------------------------------


class OOBHTTPListener:
    """
    Minimal asyncio HTTP server that listens for inbound callback requests.

    Any request to ``/<token>[/...]`` records an OOBCallback for that token.
    Returns HTTP 200 with a 1×1 GIF to avoid retries from misconfigured
    HTTP clients in the target application.
    """

    _GIF = (
        b"GIF89a\x01\x00\x01\x00\x00\xff\x00,"
        b"\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x00;"
    )

    def __init__(self, store: OOBCallbackStore, port: int = OOB_HTTP_PORT) -> None:
        self._store = store
        self._port = port
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, "0.0.0.0", self._port
        )
        logger.info("OOBHTTPListener started on port %d", self._port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("OOBHTTPListener stopped")

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            raw = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            request_line = raw.decode("latin-1", errors="replace").split("\r\n")[0]
            parts = request_line.split(" ")
            method = parts[0] if parts else "GET"
            path = parts[1] if len(parts) > 1 else "/"

            # Extract token from first path segment: /TOKEN[/...]
            segments = [s for s in path.split("/") if s]
            token = segments[0] if segments else ""

            peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
            source_ip, source_port = str(peer[0]), int(peer[1])

            cb = OOBCallback(
                token=token,
                channel="http",
                source_ip=source_ip,
                source_port=source_port,
                method=method,
                path=path,
                payload=raw.decode("latin-1", errors="replace"),
            )
            await self._store.record(cb)
            logger.info(
                "OOB HTTP callback: token=%s method=%s path=%s from %s:%d",
                token, method, path, source_ip, source_port,
            )

            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: image/gif\r\n"
                b"Content-Length: 26\r\n"
                b"Connection: close\r\n\r\n"
            ) + self._GIF
            writer.write(response)
            await writer.drain()
        except Exception as exc:
            logger.debug("OOBHTTPListener._handle error: %s", exc)
        finally:
            writer.close()


# ---------------------------------------------------------------------------
# DNS listener
# ---------------------------------------------------------------------------


class OOBDNSListener:
    """
    Minimal asyncio UDP DNS listener for detecting blind DNS exfiltration.

    Parses incoming A/AAAA query packets and extracts the queried domain name.
    The first label of the domain is treated as the token:
      e.g.  <token>.oob.univex.local → token is extracted and recorded.
    """

    def __init__(self, store: OOBCallbackStore, port: int = OOB_DNS_PORT) -> None:
        self._store = store
        self._port = port
        self._transport: Optional[asyncio.DatagramTransport] = None

    async def start(self) -> None:
        loop = asyncio.get_event_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _DNSProtocol(self._store),
            local_addr=("0.0.0.0", self._port),
        )
        logger.info("OOBDNSListener started on UDP port %d", self._port)

    async def stop(self) -> None:
        if self._transport:
            self._transport.close()
            logger.info("OOBDNSListener stopped")


class _DNSProtocol(asyncio.DatagramProtocol):
    """asyncio DatagramProtocol that parses DNS query packets."""

    def __init__(self, store: OOBCallbackStore) -> None:
        self._store = store

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        try:
            domain = self._parse_query(data)
            if not domain:
                return
            labels = domain.lower().rstrip(".").split(".")
            token = labels[0] if labels else ""
            source_ip, source_port = str(addr[0]), int(addr[1])
            cb = OOBCallback(
                token=token,
                channel="dns",
                source_ip=source_ip,
                source_port=source_port,
                method="A",
                path=domain,
            )
            asyncio.ensure_future(self._store.record(cb))
            logger.info(
                "OOB DNS callback: token=%s domain=%s from %s:%d",
                token, domain, source_ip, source_port,
            )
        except Exception as exc:
            logger.debug("_DNSProtocol.datagram_received error: %s", exc)

    @staticmethod
    def _parse_query(data: bytes) -> Optional[str]:
        """Extract the queried domain name from a raw DNS packet."""
        try:
            # DNS header is 12 bytes; question section starts at offset 12
            offset = 12
            labels: List[str] = []
            while offset < len(data):
                length = data[offset]
                if length == 0:
                    break
                offset += 1
                # Bounds check: prevent buffer overread on malformed packets
                if offset + length > len(data):
                    return None
                labels.append(data[offset: offset + length].decode("ascii", errors="replace"))
                offset += length
            return ".".join(labels) if labels else None
        except Exception:
            return None


# ---------------------------------------------------------------------------
# SMTP listener
# ---------------------------------------------------------------------------


class OOBSMTPListener:
    """
    Minimal asyncio SMTP listener for detecting blind command injection via email.

    Any email sent to this server is recorded.  The RCPT TO address local part
    is treated as the token: e.g.  <token>@oob.univex.local
    """

    def __init__(self, store: OOBCallbackStore, port: int = OOB_SMTP_PORT) -> None:
        self._store = store
        self._port = port
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, "0.0.0.0", self._port
        )
        logger.info("OOBSMTPListener started on port %d", self._port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("OOBSMTPListener stopped")

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        source_ip, source_port = str(peer[0]), int(peer[1])
        token = ""
        try:
            writer.write(b"220 oob.univex.local SMTP Ready\r\n")
            await writer.drain()

            lines: List[bytes] = []
            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=10.0)
                except asyncio.TimeoutError:
                    break
                if not line:
                    break
                lines.append(line)
                cmd = line.strip().upper()

                if cmd.startswith(b"EHLO") or cmd.startswith(b"HELO"):
                    writer.write(b"250-oob.univex.local Hello\r\n250 OK\r\n")
                elif cmd.startswith(b"RCPT TO:"):
                    rcpt = line.strip()[8:].decode("latin-1", errors="replace").strip("<> ")
                    token = rcpt.split("@")[0]
                    writer.write(b"250 OK\r\n")
                elif cmd.startswith(b"MAIL FROM:"):
                    writer.write(b"250 OK\r\n")
                elif cmd == b"DATA":
                    writer.write(b"354 Start input; end with <CRLF>.<CRLF>\r\n")
                elif cmd == b".":
                    writer.write(b"250 Message accepted\r\n")
                    break
                elif cmd == b"QUIT":
                    writer.write(b"221 Bye\r\n")
                    break
                else:
                    writer.write(b"500 Unrecognised command\r\n")

                await writer.drain()

            payload = b"\r\n".join(lines).decode("latin-1", errors="replace")
            cb = OOBCallback(
                token=token,
                channel="smtp",
                source_ip=source_ip,
                source_port=source_port,
                method="SMTP",
                path=f"RCPT TO:{token}@oob.univex.local",
                payload=payload,
            )
            await self._store.record(cb)
            logger.info(
                "OOB SMTP callback: token=%s from %s:%d", token, source_ip, source_port
            )
        except Exception as exc:
            logger.debug("OOBSMTPListener._handle error: %s", exc)
        finally:
            writer.close()


# ---------------------------------------------------------------------------
# Main coordinator
# ---------------------------------------------------------------------------


class OOBListener:
    """
    Central coordinator for all out-of-band callback listeners.

    Lifecycle::

        listener = OOBListener()
        await listener.start()

        # generate a token for a specific test
        token = listener.generate_token("test-42")
        payload_url = listener.callback_url(token)  # embed in exploit payload

        # … wait for target to execute …

        callbacks = await listener.get_callbacks(token)
        print(callbacks)

        await listener.stop()
    """

    def __init__(
        self,
        http_port: int = OOB_HTTP_PORT,
        dns_port: int = OOB_DNS_PORT,
        smtp_port: int = OOB_SMTP_PORT,
        external_ip: str = OOB_EXTERNAL_IP,
    ) -> None:
        self._external_ip = external_ip
        self._http_port = http_port
        self._dns_port = dns_port
        self._smtp_port = smtp_port

        self._store = OOBCallbackStore()
        self._http = OOBHTTPListener(self._store, http_port)
        self._dns = OOBDNSListener(self._store, dns_port)
        self._smtp = OOBSMTPListener(self._store, smtp_port)

        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start all listeners concurrently."""
        await asyncio.gather(
            self._http.start(),
            self._dns.start(),
            self._smtp.start(),
        )
        self._running = True
        logger.info(
            "OOBListener running — HTTP:%d  DNS:%d  SMTP:%d  external=%s",
            self._http_port,
            self._dns_port,
            self._smtp_port,
            self._external_ip,
        )

    async def stop(self) -> None:
        """Stop all listeners."""
        await asyncio.gather(
            self._http.stop(),
            self._dns.stop(),
            self._smtp.stop(),
        )
        self._running = False
        logger.info("OOBListener stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    # ------------------------------------------------------------------
    # Token management
    # ------------------------------------------------------------------

    def generate_token(self, test_id: str) -> str:
        """
        Generate a unique, HMAC-signed token for *test_id*.

        The token is short enough to use as a DNS label (≤ 32 hex chars).
        """
        nonce = secrets.token_hex(8)
        raw = f"{test_id}:{nonce}"
        mac = hmac.new(_SIGNING_KEY, raw.encode(), hashlib.sha256).hexdigest()[:24]
        return mac

    def callback_url(self, token: str, channel: str = "http") -> str:
        """Return the public callback URL for *token*."""
        if channel == "http":
            return f"http://{self._external_ip}:{self._http_port}/{token}"
        if channel == "dns":
            return f"{token}.oob.univex.local"
        if channel == "smtp":
            return f"{token}@oob.univex.local"
        raise ValueError(f"Unknown channel: {channel!r}")

    async def register_token(self, token: str) -> None:
        """Pre-register *token* so the store is ready before the payload fires."""
        await self._store.register_token(token)

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    async def get_callbacks(self, token: str) -> List[OOBCallback]:
        """Return all callbacks received for *token*."""
        return await self._store.get(token)

    async def wait_for_callback(
        self,
        token: str,
        timeout: float = 30.0,
        poll_interval: float = 0.5,
    ) -> Optional[OOBCallback]:
        """
        Poll until at least one callback arrives for *token* or *timeout* elapses.

        Returns the first callback or ``None`` if the timeout expired.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            cbs = await self._store.get(token)
            if cbs:
                return cbs[0]
            await asyncio.sleep(poll_interval)
        return None

    async def all_tokens(self) -> List[str]:
        """Return all currently tracked tokens."""
        return await self._store.all_tokens()

    def stats(self) -> Dict[str, Any]:
        """Return runtime statistics."""
        return {
            "running": self._running,
            "external_ip": self._external_ip,
            "http_port": self._http_port,
            "dns_port": self._dns_port,
            "smtp_port": self._smtp_port,
        }


__all__ = [
    "OOBCallback",
    "OOBCallbackStore",
    "OOBHTTPListener",
    "OOBDNSListener",
    "OOBSMTPListener",
    "OOBListener",
]
