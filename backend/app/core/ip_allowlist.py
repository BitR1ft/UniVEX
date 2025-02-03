"""
IP Allow-Listing for admin endpoints.

Provides a FastAPI dependency that rejects requests from IP addresses
not in the configured allow-list.

Configuration:
    Set ADMIN_IP_ALLOWLIST in environment (comma-separated CIDRs or IPs):
        ADMIN_IP_ALLOWLIST="10.0.0.0/8,192.168.1.0/24,203.0.113.42"

    If the variable is empty or unset, private RFC-1918 ranges are
    allowed by default (safe for internal networks).

Usage::

    from app.core.ip_allowlist import admin_ip_check

    @router.get("/api/admin/users")
    async def list_users(_: None = Depends(admin_ip_check)):
        ...
"""
from __future__ import annotations

import logging
import os
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from typing import List, Union

from fastapi import HTTPException, Request, status

logger = logging.getLogger(__name__)

IPNetwork = Union[IPv4Network, IPv6Network]

# ---------------------------------------------------------------------------
# Default private CIDRs (RFC-1918 + loopback + IPv6 link-local)
# ---------------------------------------------------------------------------
_DEFAULT_PRIVATE_CIDRS: List[str] = [
    "127.0.0.0/8",       # IPv4 loopback
    "10.0.0.0/8",        # RFC-1918 private
    "172.16.0.0/12",     # RFC-1918 private
    "192.168.0.0/16",    # RFC-1918 private
    "::1/128",           # IPv6 loopback
    "fc00::/7",          # IPv6 unique local
    "fe80::/10",         # IPv6 link-local
]


def _parse_cidr_list(raw: str) -> List[IPNetwork]:
    """Parse a comma-separated list of CIDR notations or single IPs."""
    networks: List[IPNetwork] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            # Single IP without mask — treat as /32 or /128
            if "/" not in item:
                addr = ip_address(item)
                prefix = 32 if addr.version == 4 else 128
                item = f"{item}/{prefix}"
            networks.append(ip_network(item, strict=False))
        except ValueError as exc:
            logger.error("Invalid CIDR in IP allowlist: %r — %s", item, exc)
    return networks


def _load_allowlist() -> List[IPNetwork]:
    """Load the IP allow-list from environment variable or use defaults."""
    raw = os.getenv("ADMIN_IP_ALLOWLIST", "").strip()
    if raw:
        nets = _parse_cidr_list(raw)
        logger.info("Admin IP allowlist loaded: %d entries from env", len(nets))
        return nets
    # Fall back to private ranges
    nets = _parse_cidr_list(",".join(_DEFAULT_PRIVATE_CIDRS))
    logger.info("Admin IP allowlist: using default private CIDRs (%d entries)", len(nets))
    return nets


class IPAllowList:
    """
    Reloadable IP allow-list with a FastAPI dependency interface.

    The list is built from the ADMIN_IP_ALLOWLIST environment variable on
    first use.  Call :meth:`reload` to pick up changes at runtime.
    """

    def __init__(self) -> None:
        self._networks: List[IPNetwork] = []
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self._networks = _load_allowlist()
            self._loaded = True

    def reload(self) -> None:
        """Force-reload from environment (useful after secret rotation)."""
        self._networks = _load_allowlist()
        self._loaded = True

    def is_allowed(self, remote_ip: str) -> bool:
        """
        Return True if *remote_ip* falls within any allowed network.

        Args:
            remote_ip: The IP address string from the incoming request.
        """
        self._ensure_loaded()
        try:
            addr = ip_address(remote_ip)
        except ValueError:
            logger.warning("Could not parse remote IP: %r", remote_ip)
            return False  # fail-closed for unparseable addresses

        for network in self._networks:
            if addr in network:
                return True

        logger.warning("Admin request denied from IP: %s (not in allowlist)", remote_ip)
        return False

    def add_cidr(self, cidr: str) -> None:
        """Dynamically add a CIDR to the in-memory allow-list."""
        self._ensure_loaded()
        try:
            net = ip_network(cidr, strict=False)
            if net not in self._networks:
                self._networks.append(net)
                logger.info("Added CIDR to admin allowlist: %s", cidr)
        except ValueError as exc:
            logger.error("Invalid CIDR %r: %s", cidr, exc)

    def remove_cidr(self, cidr: str) -> bool:
        """Remove a CIDR from the in-memory allow-list. Returns True if found."""
        self._ensure_loaded()
        try:
            net = ip_network(cidr, strict=False)
            if net in self._networks:
                self._networks.remove(net)
                logger.info("Removed CIDR from admin allowlist: %s", cidr)
                return True
        except ValueError:
            pass
        return False

    def list_cidrs(self) -> List[str]:
        """Return the current allow-list as a list of CIDR strings."""
        self._ensure_loaded()
        return [str(n) for n in self._networks]

    # ------------------------------------------------------------------
    # FastAPI dependency
    # ------------------------------------------------------------------

    async def __call__(self, request: Request) -> None:
        """
        FastAPI dependency — raises HTTP 403 if the remote IP is not allowed.

        Usage::

            @router.get("/admin/users", dependencies=[Depends(admin_ip_allowlist)])
            async def list_users():
                ...
        """
        # Support X-Forwarded-For when behind Nginx
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the leftmost (original client) IP
            remote_ip = forwarded_for.split(",")[0].strip()
        else:
            remote_ip = request.client.host if request.client else "0.0.0.0"

        if not self.is_allowed(remote_ip):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: your IP address is not authorised for this endpoint.",
            )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
admin_ip_allowlist = IPAllowList()


# ---------------------------------------------------------------------------
# Convenience alias for use as a FastAPI dependency
# ---------------------------------------------------------------------------
async def admin_ip_check(request: Request) -> None:
    """FastAPI dependency: enforce admin IP allowlist."""
    await admin_ip_allowlist(request)
