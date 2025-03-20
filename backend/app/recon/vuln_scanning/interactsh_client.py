"""
Interactsh Client Wrapper

Provides a Python client for Interactsh (https://github.com/projectdiscovery/interactsh)
for detecting Out-of-Band (OOB) interactions caused by blind vulnerability classes
such as:
  - Blind SSRF
  - Blind XXE
  - Blind SQL injection (DNS-based)
  - Blind Command injection (DNS-based)
  - Log4Shell / JNDI injection

The client talks to an Interactsh server (public or self-hosted) over HTTPS,
registers a unique correlation ID, and polls for interactions.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default public Interactsh server
# ---------------------------------------------------------------------------

_DEFAULT_SERVER = "https://interact.sh"

# ---------------------------------------------------------------------------
# Interaction data model
# ---------------------------------------------------------------------------


@dataclass
class OOBInteraction:
    """Represents a single OOB interaction captured by Interactsh."""

    correlation_id: str
    interaction_type: str          # "dns", "http", "smtp", "ftp", etc.
    raw_request: Optional[str] = None
    raw_response: Optional[str] = None
    remote_address: Optional[str] = None
    timestamp: Optional[datetime] = None
    unique_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "interaction_type": self.interaction_type,
            "raw_request": self.raw_request,
            "raw_response": self.raw_response,
            "remote_address": self.remote_address,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "unique_id": self.unique_id,
        }


# ---------------------------------------------------------------------------
# InteractshClient
# ---------------------------------------------------------------------------


class InteractshClient:
    """
    Async client for the Interactsh OOB interaction platform.

    Usage::

        async with InteractshClient() as client:
            payload_url = client.payload_url   # embed in scan payloads
            # … trigger the target …
            interactions = await client.poll(timeout=30)
            for ix in interactions:
                print(ix.interaction_type, ix.remote_address)

    The client performs a lightweight HTTPS register/poll cycle.  A full
    cryptographic session (RSA key exchange) is used by the official CLI; here
    we use the simpler unauthenticated poll endpoint which is sufficient for
    integration testing and is how many CI-based tools operate.
    """

    def __init__(
        self,
        server_url: str = _DEFAULT_SERVER,
        poll_interval: float = 5.0,
        correlation_id: Optional[str] = None,
    ) -> None:
        self._server = server_url.rstrip("/")
        self._poll_interval = poll_interval
        self._correlation_id: str = correlation_id or self._generate_correlation_id()
        self._interactions: List[OOBInteraction] = []
        self._callbacks: List[Callable[[OOBInteraction], None]] = []
        self._polling = False
        self._session: Optional[Any] = None  # httpx.AsyncClient

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def correlation_id(self) -> str:
        """Unique correlation ID for this session."""
        return self._correlation_id

    @property
    def payload_url(self) -> str:
        """
        Interactsh payload URL to embed in scan payloads.

        e.g. ``<correlation_id>.interact.sh``
        """
        host = self._server.replace("https://", "").replace("http://", "")
        return f"{self._correlation_id}.{host}"

    @property
    def interactions(self) -> List[OOBInteraction]:
        """All captured interactions so far."""
        return list(self._interactions)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "InteractshClient":
        await self._open_session()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self._close_session()

    async def _open_session(self) -> None:
        try:
            import httpx
            self._session = httpx.AsyncClient(timeout=15.0, verify=True)
            logger.debug("Interactsh session opened (server=%s)", self._server)
        except ImportError:
            logger.warning(
                "httpx not installed – Interactsh client will not be able to poll. "
                "Install with: pip install httpx"
            )

    async def _close_session(self) -> None:
        self._polling = False
        if self._session is not None:
            await self._session.aclose()
            self._session = None

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    async def register(self) -> bool:
        """
        Register a new correlation ID with the Interactsh server.

        Returns True on success, False otherwise.
        """
        if self._session is None:
            logger.warning("Session not open; call open_session() first")
            return False
        try:
            url = f"{self._server}/register"
            resp = await self._session.post(
                url,
                json={"correlation-id": self._correlation_id},
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code in (200, 201):
                logger.info("Registered Interactsh correlation-id: %s", self._correlation_id)
                return True
            logger.warning("Interactsh register returned %d", resp.status_code)
            return False
        except Exception as exc:
            logger.error("Failed to register with Interactsh: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Polling
    # ------------------------------------------------------------------

    async def poll_once(self) -> List[OOBInteraction]:
        """
        Poll the Interactsh server once and return new interactions.

        New interactions are also appended to :attr:`interactions` and
        any registered callbacks are invoked.
        """
        if self._session is None:
            return []

        try:
            url = f"{self._server}/poll"
            resp = await self._session.get(
                url,
                params={"id": self._correlation_id, "secret": ""},
            )
            if resp.status_code != 200:
                logger.debug("Interactsh poll returned %d", resp.status_code)
                return []

            data = resp.json()
            new_interactions: List[OOBInteraction] = []

            for item in data.get("data", []) or []:
                try:
                    raw = self._decode_interaction(item)
                    ix = OOBInteraction(
                        correlation_id=self._correlation_id,
                        interaction_type=raw.get("protocol", "unknown"),
                        raw_request=raw.get("raw-request"),
                        raw_response=raw.get("raw-response"),
                        remote_address=raw.get("remote-address"),
                        timestamp=datetime.now(tz=timezone.utc),
                    )
                    self._interactions.append(ix)
                    new_interactions.append(ix)
                    for cb in self._callbacks:
                        try:
                            cb(ix)
                        except Exception:
                            pass
                except Exception as exc:
                    logger.debug("Error parsing interaction: %s", exc)

            return new_interactions

        except Exception as exc:
            logger.debug("Interactsh poll error: %s", exc)
            return []

    async def poll(
        self,
        timeout: float = 30.0,
        stop_on_first: bool = False,
    ) -> List[OOBInteraction]:
        """
        Poll continuously for *timeout* seconds, returning all captured
        interactions.

        Args:
            timeout:        Maximum polling duration in seconds.
            stop_on_first:  Stop as soon as the first interaction arrives.
        """
        deadline = time.monotonic() + timeout
        all_new: List[OOBInteraction] = []

        while time.monotonic() < deadline:
            new = await self.poll_once()
            all_new.extend(new)
            if stop_on_first and new:
                break
            await asyncio.sleep(self._poll_interval)

        return all_new

    # ------------------------------------------------------------------
    # Callback registration
    # ------------------------------------------------------------------

    def on_interaction(self, callback: Callable[[OOBInteraction], None]) -> None:
        """Register a callback invoked for every new interaction."""
        self._callbacks.append(callback)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_correlation_id() -> str:
        """Generate a 33-character alphanumeric correlation ID."""
        raw = uuid.uuid4().bytes + uuid.uuid4().bytes
        return base64.urlsafe_b64encode(raw)[:33].decode().lower().replace("-", "a").replace("_", "b")

    @staticmethod
    def _decode_interaction(item: Any) -> Dict[str, Any]:
        """
        Decode an interaction data item.

        Interactsh encodes interaction data as base64 in some server versions.
        """
        if isinstance(item, dict):
            return item
        if isinstance(item, str):
            try:
                decoded = base64.b64decode(item + "==").decode(errors="replace")
                import json
                return json.loads(decoded)
            except Exception:
                return {"protocol": "unknown", "raw-request": item}
        return {}

    # ------------------------------------------------------------------
    # Payload generation helpers
    # ------------------------------------------------------------------

    def dns_payload(self, suffix: str = "") -> str:
        """Return a DNS interaction payload URL (subdomain of correlation ID)."""
        return f"{suffix}.{self.payload_url}" if suffix else self.payload_url

    def http_payload(self, path: str = "/") -> str:
        """Return an HTTP interaction payload URL."""
        return f"http://{self.payload_url}{path}"

    def log4shell_payload(self) -> str:
        """Return a Log4Shell / JNDI DNS-based payload string."""
        return f"${{jndi:ldap://{self.payload_url}/a}}"

    def ssrf_payload(self, path: str = "/") -> str:
        """Return an SSRF HTTP payload URL."""
        return self.http_payload(path)
