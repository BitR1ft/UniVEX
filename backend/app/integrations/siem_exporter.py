"""

Exports pentest findings to SIEM-compatible formats:
  - CEF  (ArcSight Common Event Format)
  - LEEF (IBM QRadar Log Event Extended Format)
  - JSON (generic structured log)

Also provides push-based connectors:
  - Splunk HTTP Event Collector (HEC)
  - Elasticsearch Bulk API (ELK)
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums & data models
# ---------------------------------------------------------------------------

class SIEMFormat(str, Enum):
    CEF = "cef"
    LEEF = "leef"
    JSON = "json"


SEVERITY_MAP: Dict[str, int] = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 3,
    "info": 1,
    "informational": 1,
}


@dataclass
class SIEMEvent:
    """A normalized finding ready for SIEM export."""

    id: str
    title: str
    description: str
    severity: str  # critical | high | medium | low | info
    category: str = ""
    source_tool: str = "UniVex"
    target_host: str = ""
    target_port: Optional[int] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: str = ""
    timestamp: Optional[datetime] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timestamp is None:
            self.timestamp = datetime.now(tz=timezone.utc)
        self.severity = self.severity.lower()

    @property
    def severity_int(self) -> int:
        return SEVERITY_MAP.get(self.severity, 5)

    @property
    def event_id(self) -> str:
        """Deterministic short event ID."""
        raw = f"{self.id}:{self.title}:{self.target_host}"
        return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()[:16]  # noqa: S324


# ---------------------------------------------------------------------------
# CEF formatting helpers
# ---------------------------------------------------------------------------

_CEF_ESCAPE = re.compile(r"([\\|=])")


def _cef_escape(value: str) -> str:
    """Escape special characters in CEF extension values."""
    return _CEF_ESCAPE.sub(r"\\\1", str(value))


def _cef_extension(key: str, value: Any) -> str:
    return f"{key}={_cef_escape(str(value))}"


# ---------------------------------------------------------------------------
# LEEF formatting helpers
# ---------------------------------------------------------------------------

_LEEF_ESCAPE = re.compile(r"([\t\n\r\\])")


def _leef_escape(value: str) -> str:
    return _LEEF_ESCAPE.sub(lambda m: "\\" + m.group(0), str(value))


# ---------------------------------------------------------------------------
# SIEMExporter
# ---------------------------------------------------------------------------

class SIEMExporter:
    """
    Exports :class:`SIEMEvent` objects to CEF, LEEF, or JSON format and
    provides push connectors for Splunk HEC and Elasticsearch.
    """

    VENDOR = "BitR1FT"
    PRODUCT = "UniVex"
    VERSION = "1.0"
    CEF_DEVICE_EVENT_CLASS_ID = "UNIVEX_FINDING"

    # ------------------------------------------------------------------
    # Format methods
    # ------------------------------------------------------------------

    def to_cef(self, event: SIEMEvent) -> str:
        """
        Produce a single-line CEF 0 record.

        Format:
          CEF:Version|Device Vendor|Device Product|Device Version|
          Device Event Class ID|Name|Severity|[Extension]
        """
        event.timestamp.strftime("%b %d %H:%M:%S") if event.timestamp else ""
        header = "|".join(
            [
                "CEF:0",
                self.VENDOR,
                self.PRODUCT,
                self.VERSION,
                self.CEF_DEVICE_EVENT_CLASS_ID,
                _cef_escape(event.title),
                str(event.severity_int),
            ]
        )

        ext_parts: List[str] = [
            _cef_extension("rt", int(event.timestamp.timestamp() * 1000) if event.timestamp else 0),
            _cef_extension("src", event.target_host or "unknown"),
            _cef_extension("msg", event.description),
            _cef_extension("cat", event.category),
            _cef_extension("sev", event.severity),
            _cef_extension("act", "Reported"),
            _cef_extension("app", event.source_tool),
            _cef_extension("deviceExternalId", event.event_id),
        ]

        if event.target_port:
            ext_parts.append(_cef_extension("dpt", event.target_port))
        if event.cve_id:
            ext_parts.append(_cef_extension("cs1", event.cve_id))
            ext_parts.append(_cef_extension("cs1Label", "CVE_ID"))
        if event.cvss_score is not None:
            ext_parts.append(_cef_extension("cs2", event.cvss_score))
            ext_parts.append(_cef_extension("cs2Label", "CVSS_Score"))
        if event.remediation:
            ext_parts.append(_cef_extension("cs3", event.remediation))
            ext_parts.append(_cef_extension("cs3Label", "Remediation"))

        extension = " ".join(ext_parts)
        return f"{header}|{extension}"

    def to_leef(self, event: SIEMEvent) -> str:
        """
        Produce a LEEF 2.0 syslog-friendly record.

        Format:
          LEEF:2.0|Vendor|Product|Version|EventID|\t-separated attrs
        """
        event_id = f"FINDING_{event.severity.upper()}"
        header = "|".join(
            [
                "LEEF:2.0",
                self.VENDOR,
                self.PRODUCT,
                self.VERSION,
                event_id,
            ]
        )

        attrs: Dict[str, Any] = {
            "devTime": event.timestamp.isoformat() if event.timestamp else "",
            "sev": event.severity_int,
            "src": event.target_host or "unknown",
            "cat": event.category,
            "msg": event.description,
            "usrName": event.source_tool,
            "findingId": event.event_id,
            "title": event.title,
            "action": "Reported",
        }
        if event.target_port:
            attrs["dstPort"] = event.target_port
        if event.cve_id:
            attrs["cveId"] = event.cve_id
        if event.cvss_score is not None:
            attrs["cvssScore"] = event.cvss_score
        if event.remediation:
            attrs["remediation"] = event.remediation

        ext = "\t".join(f"{k}={_leef_escape(str(v))}" for k, v in attrs.items())
        return f"{header}|{ext}"

    def to_json(self, event: SIEMEvent) -> Dict[str, Any]:
        """Return a JSON-serialisable dict for the event."""
        return {
            "id": event.id,
            "event_id": event.event_id,
            "title": event.title,
            "description": event.description,
            "severity": event.severity,
            "severity_score": event.severity_int,
            "category": event.category,
            "source_tool": event.source_tool,
            "target": {
                "host": event.target_host,
                "port": event.target_port,
            },
            "cve_id": event.cve_id,
            "cvss_score": event.cvss_score,
            "remediation": event.remediation,
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "extra": event.extra,
            "format": "univex_finding_v1",
        }

    def to_json_str(self, event: SIEMEvent) -> str:
        return json.dumps(self.to_json(event))

    # ------------------------------------------------------------------
    # Batch helpers
    # ------------------------------------------------------------------

    def export_batch(
        self, events: List[SIEMEvent], fmt: SIEMFormat
    ) -> List[str]:
        """Convert a list of events to strings in the given format."""
        if fmt == SIEMFormat.CEF:
            return [self.to_cef(e) for e in events]
        if fmt == SIEMFormat.LEEF:
            return [self.to_leef(e) for e in events]
        return [self.to_json_str(e) for e in events]

    # ------------------------------------------------------------------
    # Splunk HEC connector
    # ------------------------------------------------------------------

    def push_to_splunk(
        self,
        events: List[SIEMEvent],
        hec_url: str,
        hec_token: str,
        *,
        index: str = "main",
        source: str = "univex",
        sourcetype: str = "univex:finding",
        timeout: float = 10.0,
    ) -> Dict[str, Any]:
        """
        Push events to Splunk via HTTP Event Collector.

        Returns a summary dict with ``sent``, ``failed``, and ``errors``.
        """
        if not hec_url or not hec_token:
            raise ValueError("hec_url and hec_token are required")

        parsed = urlparse(hec_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Invalid HEC URL scheme: {parsed.scheme}")

        payload_lines: List[str] = []
        for ev in events:
            record = {
                "time": ev.timestamp.timestamp() if ev.timestamp else time.time(),
                "host": ev.target_host or socket.gethostname(),
                "source": source,
                "sourcetype": sourcetype,
                "index": index,
                "event": self.to_json(ev),
            }
            payload_lines.append(json.dumps(record))

        body = "\n".join(payload_lines).encode("utf-8")
        headers = {
            "Authorization": f"Splunk {hec_token}",
            "Content-Type": "application/json",
        }

        endpoint = hec_url.rstrip("/") + "/services/collector/event"
        req = Request(endpoint, data=body, headers=headers, method="POST")

        try:
            with urlopen(req, timeout=timeout) as resp:  # noqa: S310
                response_body = resp.read().decode("utf-8")
                result = json.loads(response_body)
                return {
                    "sent": len(events),
                    "failed": 0,
                    "errors": [],
                    "splunk_response": result,
                }
        except HTTPError as exc:
            logger.error("Splunk HEC HTTP error %s: %s", exc.code, exc.reason)
            return {
                "sent": 0,
                "failed": len(events),
                "errors": [f"HTTP {exc.code}: {exc.reason}"],
            }
        except URLError as exc:
            logger.error("Splunk HEC connection error: %s", exc.reason)
            return {
                "sent": 0,
                "failed": len(events),
                "errors": [str(exc.reason)],
            }

    # ------------------------------------------------------------------
    # Elasticsearch / ELK bulk API connector
    # ------------------------------------------------------------------

    def push_to_elk(
        self,
        events: List[SIEMEvent],
        elk_url: str,
        *,
        index: str = "univex-findings",
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: float = 15.0,
    ) -> Dict[str, Any]:
        """
        Push events to Elasticsearch via the Bulk API.

        Authentication supports API key or basic auth.
        Returns a summary dict with ``sent``, ``failed``, and ``errors``.
        """
        if not elk_url:
            raise ValueError("elk_url is required")

        parsed = urlparse(elk_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Invalid ELK URL scheme: {parsed.scheme}")

        # Build ndjson body  (action_meta + source pairs)
        ndjson_lines: List[str] = []
        for ev in events:
            action_meta = json.dumps(
                {"index": {"_index": index, "_id": ev.event_id}}
            )
            source = json.dumps(self.to_json(ev))
            ndjson_lines.append(action_meta)
            ndjson_lines.append(source)

        body = ("\n".join(ndjson_lines) + "\n").encode("utf-8")
        headers: Dict[str, str] = {"Content-Type": "application/x-ndjson"}

        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"
        elif username and password:
            import base64
            creds = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {creds}"

        endpoint = elk_url.rstrip("/") + "/_bulk"
        req = Request(endpoint, data=body, headers=headers, method="POST")

        try:
            with urlopen(req, timeout=timeout) as resp:  # noqa: S310
                response_body = resp.read().decode("utf-8")
                result = json.loads(response_body)
                errors = [
                    item.get("index", {}).get("error")
                    for item in result.get("items", [])
                    if item.get("index", {}).get("error")
                ]
                return {
                    "sent": len(events) - len(errors),
                    "failed": len(errors),
                    "errors": [str(e) for e in errors],
                    "elk_response": {"errors": result.get("errors", False)},
                }
        except HTTPError as exc:
            logger.error("ELK bulk HTTP error %s: %s", exc.code, exc.reason)
            return {
                "sent": 0,
                "failed": len(events),
                "errors": [f"HTTP {exc.code}: {exc.reason}"],
            }
        except URLError as exc:
            logger.error("ELK bulk connection error: %s", exc.reason)
            return {
                "sent": 0,
                "failed": len(events),
                "errors": [str(exc.reason)],
            }
