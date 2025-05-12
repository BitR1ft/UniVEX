"""

Handles target import from CSV/JSON, CIDR expansion, scope validation,
and deduplication.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)

_URL_RE = re.compile(
    r"^(https?://)?"
    r"(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}"
    r"(?::\d+)?(?:/.*)?$"
)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

@dataclass
class ParsedTarget:
    """A validated, normalised target ready to be added to a campaign."""
    host: str
    port: Optional[int] = None
    protocol: str = "https"
    scope_notes: str = ""
    tags: List[str] = field(default_factory=list)
    raw: str = ""


@dataclass
class ImportResult:
    """Result of a bulk target import operation."""
    parsed: List[ParsedTarget] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duplicates_removed: int = 0

    @property
    def success_count(self) -> int:
        return len(self.parsed)

    @property
    def error_count(self) -> int:
        return len(self.errors)


# ---------------------------------------------------------------------------
# TargetManager
# ---------------------------------------------------------------------------

class TargetManager:
    """
    Import, validate, and normalise pentest targets.

    Supports:
      - CSV files (columns: host, port, protocol, scope_notes, tags)
      - JSON arrays ({host, port?, protocol?, scope_notes?, tags?})
      - Plain text (one host/CIDR per line)
      - CIDR expansion (expands CIDR blocks to individual host records)
      - Scope validation (whitelist / blacklist patterns)
      - Duplicate detection
    """

    # Reserved / unroutable CIDRs that should never be targets in production
    _RESERVED_CIDRS = [
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
    ]

    def __init__(
        self,
        scope_whitelist: Optional[List[str]] = None,
        scope_blacklist: Optional[List[str]] = None,
        max_cidr_hosts: int = 256,
    ) -> None:
        """
        Args:
            scope_whitelist: List of glob/regex patterns. If set, only matching
                             hosts are accepted.
            scope_blacklist: List of patterns that must NOT match.
            max_cidr_hosts:  Maximum number of hosts expanded from a single CIDR
                             block (safety guard).
        """
        self._whitelist = [re.compile(p) for p in (scope_whitelist or [])]
        self._blacklist = [re.compile(p) for p in (scope_blacklist or [])]
        self.max_cidr_hosts = max_cidr_hosts
        self._reserved = [ipaddress.ip_network(c, strict=False) for c in self._RESERVED_CIDRS]

    # ------------------------------------------------------------------
    # Public import entry points
    # ------------------------------------------------------------------

    def import_csv(self, content: str) -> ImportResult:
        """Parse targets from CSV text."""
        result = ImportResult()
        reader = csv.DictReader(io.StringIO(content.strip()))
        for i, row in enumerate(reader, start=1):
            host = (row.get("host") or row.get("Host") or "").strip()
            if not host:
                result.errors.append(f"Row {i}: missing 'host' column")
                continue
            target = self._build_parsed_target(
                host=host,
                port=self._parse_port(row.get("port", "")),
                protocol=(row.get("protocol") or "https").strip().lower(),
                scope_notes=(row.get("scope_notes") or "").strip(),
                tags=self._parse_tags(row.get("tags", "")),
                raw=str(row),
            )
            self._collect(target, result)
        self._remove_duplicates(result)
        return result

    def import_json(self, content: str) -> ImportResult:
        """Parse targets from JSON array text."""
        result = ImportResult()
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            result.errors.append(f"Invalid JSON: {exc}")
            return result

        if not isinstance(data, list):
            result.errors.append("JSON root must be an array of target objects")
            return result

        for i, item in enumerate(data, start=1):
            if not isinstance(item, dict):
                result.errors.append(f"Item {i}: must be a JSON object")
                continue
            host = str(item.get("host", "")).strip()
            if not host:
                result.errors.append(f"Item {i}: missing 'host' field")
                continue
            target = self._build_parsed_target(
                host=host,
                port=self._parse_port(str(item.get("port", ""))),
                protocol=str(item.get("protocol", "https")).lower(),
                scope_notes=str(item.get("scope_notes", "")),
                tags=item.get("tags", []) if isinstance(item.get("tags"), list) else [],
                raw=json.dumps(item),
            )
            self._collect(target, result)
        self._remove_duplicates(result)
        return result

    def import_text(self, content: str) -> ImportResult:
        """Parse targets from plain text (one host / CIDR per line)."""
        result = ImportResult()
        for i, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Preserve CIDR notation; only normalise URLs
            if "/" in line and not line.lower().startswith(("http://", "https://")):
                host = line  # keep as CIDR for expansion
            else:
                host = self._normalise_url_to_host(line)
            target = self._build_parsed_target(host=host, raw=line)
            self._collect(target, result)
        self._remove_duplicates(result)
        return result

    def import_auto(self, content: str, fmt: Optional[str] = None) -> ImportResult:
        """
        Auto-detect format and import targets.

        Args:
            content: Raw text content.
            fmt:     Force format: 'csv', 'json', or 'text'.
        """
        if fmt == "csv":
            return self.import_csv(content)
        if fmt == "json":
            return self.import_json(content)
        if fmt == "text":
            return self.import_text(content)
        # Auto-detect
        stripped = content.strip()
        if stripped.startswith("[") or stripped.startswith("{"):
            return self.import_json(content)
        if "," in stripped.splitlines()[0] if stripped else False:
            return self.import_csv(content)
        return self.import_text(content)

    # ------------------------------------------------------------------
    # CIDR expansion
    # ------------------------------------------------------------------

    def expand_cidr(self, cidr: str) -> List[str]:
        """
        Expand a CIDR block into individual IP strings.

        Returns at most ``self.max_cidr_hosts`` hosts.
        Raises ``ValueError`` for invalid CIDR notation.
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR notation: {cidr!r}") from exc

        hosts = [str(h) for h in network.hosts()]
        if len(hosts) > self.max_cidr_hosts:
            logger.warning(
                "CIDR %s has %d hosts, truncating to %d",
                cidr, len(hosts), self.max_cidr_hosts,
            )
            hosts = hosts[: self.max_cidr_hosts]
        return hosts

    # ------------------------------------------------------------------
    # Scope validation
    # ------------------------------------------------------------------

    def validate_scope(self, host: str) -> Tuple[bool, str]:
        """
        Validate a host against whitelist / blacklist.

        Returns:
            (True, "") if in scope.
            (False, reason) if out of scope.
        """
        # Blacklist check first
        for pattern in self._blacklist:
            if pattern.search(host):
                return False, f"Blocked by blacklist pattern {pattern.pattern!r}"

        # Reserved CIDRs
        try:
            addr = ipaddress.ip_address(host)
            for reserved in self._reserved:
                if addr in reserved:
                    return False, f"Reserved/loopback address: {host}"
        except ValueError:
            pass  # Not an IP address; hostname — skip IP checks

        # Whitelist check (only enforced when whitelist is set)
        if self._whitelist:
            for pattern in self._whitelist:
                if pattern.search(host):
                    return True, ""
            return False, "Not in scope whitelist"

        return True, ""

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_parsed_target(
        self,
        host: str,
        port: Optional[int] = None,
        protocol: str = "https",
        scope_notes: str = "",
        tags: Optional[List[str]] = None,
        raw: str = "",
    ) -> ParsedTarget | ImportResult:
        """Build a ParsedTarget or an error record."""
        return ParsedTarget(
            host=host,
            port=port,
            protocol=protocol,
            scope_notes=scope_notes,
            tags=tags or [],
            raw=raw,
        )

    def _collect(self, target: ParsedTarget, result: ImportResult) -> None:
        """Validate and collect a parsed target into ImportResult."""
        host = target.host

        # Try CIDR expansion first
        if "/" in host:
            try:
                expanded = self.expand_cidr(host)
                for ip in expanded:
                    t = ParsedTarget(
                        host=ip,
                        port=target.port,
                        protocol=target.protocol,
                        scope_notes=target.scope_notes,
                        tags=list(target.tags),
                        raw=target.raw,
                    )
                    self._validate_and_add(t, result)
            except ValueError as exc:
                result.errors.append(str(exc))
            return

        self._validate_and_add(target, result)

    def _validate_and_add(self, target: ParsedTarget, result: ImportResult) -> None:
        """Run validation and add to result.parsed or result.errors."""
        if not target.host:
            result.errors.append("Empty host")
            return

        # Basic syntax check
        if not self._is_valid_host(target.host):
            result.errors.append(f"Invalid host: {target.host!r}")
            return

        # Scope check
        ok, reason = self.validate_scope(target.host)
        if not ok:
            result.errors.append(f"Out of scope: {target.host!r} — {reason}")
            return

        result.parsed.append(target)

    def _is_valid_host(self, host: str) -> bool:
        """Return True if host is a valid IP address or hostname."""
        # Try IP
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            pass
        # Try hostname
        return bool(_HOSTNAME_RE.match(host)) and len(host) <= 253

    @staticmethod
    def _normalise_url_to_host(raw: str) -> str:
        """Strip protocol/path from a URL to get just the host."""
        raw = raw.strip()
        for prefix in ("https://", "http://"):
            if raw.startswith(prefix):
                raw = raw[len(prefix):]
        raw = raw.split("/")[0]  # remove path
        raw = raw.split("?")[0]  # remove query string
        # Split off port if present
        if ":" in raw and not raw.startswith("["):
            raw = raw.split(":")[0]
        return raw.strip()

    @staticmethod
    def _parse_port(value: str) -> Optional[int]:
        try:
            port = int(str(value).strip())
            return port if 1 <= port <= 65535 else None
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _parse_tags(value: str) -> List[str]:
        if not value:
            return []
        return [t.strip() for t in value.split(",") if t.strip()]

    @staticmethod
    def _remove_duplicates(result: ImportResult) -> None:
        """Remove duplicate hosts (by host+port) from result."""
        seen: Set[str] = set()
        unique: List[ParsedTarget] = []
        for t in result.parsed:
            key = f"{t.host}:{t.port}"
            if key in seen:
                result.duplicates_removed += 1
            else:
                seen.add(key)
                unique.append(t)
        result.parsed = unique
