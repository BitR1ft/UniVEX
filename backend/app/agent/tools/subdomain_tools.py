"""
Subdomain Takeover & DNS Attack Tools

Implements four agent tools for detecting subdomain takeover vulnerabilities
and performing DNS-based attack techniques:

  SubdomainTakeoverTool    — Resolve CNAME records and match against 80+
                             known-vulnerable service fingerprints.
  DanglingCNAMEDetectTool — Identify CNAMEs pointing to unregistered or
                             expired domains (dangling DNS records).
  DNSZoneTransferTool     — Attempt AXFR zone transfers against all
                             discovered nameservers for a target domain.
  DNSCacheSnoopTool       — Detect cached internal hostnames via non-recursive
                             DNS queries (cache snooping).

OWASP Mapping: A05:2021-Security Misconfiguration, A06:2021-Vulnerable and
               Outdated Components
MITRE ATT&CK:  T1584.001 (Acquire Infrastructure: Domains),
               T1590.002 (Gather Victim Network Information: DNS)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import subprocess
from typing import Any, Dict, List, Optional

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import (
    truncate_output,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Fingerprint database path
# ---------------------------------------------------------------------------

_FINGERPRINTS_PATH = os.path.normpath(
    os.path.join(
        os.path.dirname(__file__),
        "../../../data/subdomain_takeover_fingerprints.json",
    )
)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_fingerprints() -> List[Dict[str, Any]]:
    """Load subdomain takeover fingerprints from JSON file."""
    try:
        with open(_FINGERPRINTS_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        logger.warning("Fingerprints file not found at %s", _FINGERPRINTS_PATH)
        return []
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse fingerprints JSON: %s", exc)
        return []


def _resolve_cname(hostname: str) -> Optional[str]:
    """
    Resolve the canonical name (CNAME) for a hostname using the system resolver.

    Returns the CNAME target string (without trailing dot) or None when the
    hostname has no CNAME record or resolution fails.
    """
    try:
        result = subprocess.run(
            ["dig", "+short", "+time=3", "+tries=1", "CNAME", hostname],
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = result.stdout.strip()
        if output:
            return output.rstrip(".")
        return None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # Fallback: getaddrinfo gives us an alias chain on some platforms
    try:
        answers = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        if answers:
            return None  # getaddrinfo doesn't expose CNAMEs directly
    except socket.gaierror:
        pass
    return None


def _resolve_a(hostname: str) -> Optional[str]:
    """Resolve the A record IP for a hostname, returning None on failure."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def _resolve_ns(domain: str) -> List[str]:
    """Return a list of nameserver hostnames for the given domain."""
    try:
        result = subprocess.run(
            ["dig", "+short", "+time=3", "+tries=1", "NS", domain],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return [ns.rstrip(".") for ns in result.stdout.strip().splitlines() if ns.strip()]
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []


def _axfr_transfer(domain: str, nameserver: str) -> str:
    """Attempt an AXFR zone transfer and return raw output."""
    try:
        result = subprocess.run(
            ["dig", f"@{nameserver}", "+time=5", "+tries=1", "AXFR", domain],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return f"AXFR attempt failed: {exc}"


def _match_fingerprints(
    cname: str,
    fingerprints: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """
    Return the first fingerprint entry whose CNAME patterns match the resolved
    CNAME target.  Matching is suffix-based (e.g. ``github.io`` matches
    ``mysite.github.io``).
    """
    cname_lower = cname.lower()
    for fp in fingerprints:
        for pattern in fp.get("cname", []):
            if cname_lower == pattern.lower() or cname_lower.endswith("." + pattern.lower()):
                return fp
    return None


async def _async_resolve_cname(hostname: str) -> Optional[str]:
    """Async wrapper around _resolve_cname."""
    return await asyncio.to_thread(_resolve_cname, hostname)


async def _async_resolve_a(hostname: str) -> Optional[str]:
    """Async wrapper around _resolve_a."""
    return await asyncio.to_thread(_resolve_a, hostname)


async def _async_resolve_ns(domain: str) -> List[str]:
    """Async wrapper around _resolve_ns."""
    return await asyncio.to_thread(_resolve_ns, domain)


async def _async_axfr(domain: str, nameserver: str) -> str:
    """Async wrapper around _axfr_transfer."""
    return await asyncio.to_thread(_axfr_transfer, domain, nameserver)


# ---------------------------------------------------------------------------
# SubdomainTakeoverTool
# ---------------------------------------------------------------------------


class SubdomainTakeoverTool(BaseTool):
    """
    Check a list of subdomains for subdomain takeover vulnerabilities.

    Resolves CNAME chains and compares targets against 80+ known-vulnerable
    service fingerprints (GitHub Pages, Heroku, Azure, S3, Shopify, etc.).

    OWASP: A05:2021-Security Misconfiguration
    MITRE: T1584.001
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="subdomain_takeover_check",
            description=(
                "Detect subdomain takeover vulnerabilities by resolving CNAME records "
                "and matching against 80+ known-vulnerable service fingerprints "
                "(GitHub Pages, Heroku, S3, Azure, Shopify, Netlify, Vercel, etc.). "
                "OWASP: A05:2021-Security Misconfiguration | MITRE: T1584.001"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "subdomains": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of subdomain hostnames to check",
                    },
                    "domain": {
                        "type": "string",
                        "description": "Single domain to check (alternative to subdomains list)",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": (
                            "Per-subdomain asyncio.wait_for() timeout in seconds (default: 5). "
                            "Note: the underlying dig subprocess uses a fixed 3-second timeout; "
                            "the effective timeout is min(this value, 3 + subprocess overhead)."
                        ),
                        "default": 5,
                    },
                },
            },
        )

    async def execute(self, **kwargs: Any) -> str:
        subdomains: List[str] = kwargs.get("subdomains", [])
        domain: Optional[str] = kwargs.get("domain")
        timeout: int = int(kwargs.get("timeout", 5))

        if domain and not subdomains:
            subdomains = [domain]

        if not subdomains:
            return "Error: provide 'subdomains' list or a single 'domain' parameter."

        fingerprints = _load_fingerprints()
        if not fingerprints:
            return "Error: Could not load subdomain takeover fingerprints database."

        results: List[str] = [
            f"[SubdomainTakeoverTool] Checking {len(subdomains)} subdomain(s) against "
            f"{len(fingerprints)} fingerprints\n"
            + "=" * 70
        ]
        vulnerable: List[str] = []

        async def _check_one(host: str) -> str:
            try:
                cname = await asyncio.wait_for(_async_resolve_cname(host), timeout=timeout)
            except asyncio.TimeoutError:
                return f"  [TIMEOUT] {host} — DNS resolution timed out"

            if not cname:
                return f"  [NO-CNAME] {host} — no CNAME record found"

            match = _match_fingerprints(cname, fingerprints)
            if match:
                vulnerable.append(host)
                return (
                    f"  [VULNERABLE] {host}\n"
                    f"    CNAME   : {cname}\n"
                    f"    Service : {match['service']}\n"
                    f"    Status  : {match['status']} | Difficulty: {match['difficulty']}\n"
                    f"    OWASP   : {match.get('owasp', 'A05:2021')}\n"
                    f"    Ref     : {match.get('discussion', 'N/A')}"
                )
            return f"  [SAFE] {host} → CNAME: {cname}"

        tasks = [_check_one(h) for h in subdomains]
        outputs = await asyncio.gather(*tasks, return_exceptions=True)

        for item in outputs:
            if isinstance(item, Exception):
                results.append(f"  [ERROR] {item}")
            else:
                results.append(item)

        results.append("\n" + "=" * 70)
        results.append(f"Summary: {len(vulnerable)} vulnerable / {len(subdomains)} checked")
        if vulnerable:
            results.append("Vulnerable subdomains: " + ", ".join(vulnerable))

        return truncate_output("\n".join(results))


# ---------------------------------------------------------------------------
# DanglingCNAMEDetectTool
# ---------------------------------------------------------------------------


class DanglingCNAMEDetectTool(BaseTool):
    """
    Identify CNAME records pointing to unregistered or expired domains.

    A dangling CNAME occurs when a subdomain's CNAME target no longer resolves
    to an IP address — the target domain may have expired and be re-registerable
    by an attacker.

    OWASP: A05:2021-Security Misconfiguration
    MITRE: T1584.001, T1590.002
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="dangling_cname_detect",
            description=(
                "Identify dangling CNAME records — CNAMEs that resolve to a target "
                "hostname that itself has no A/AAAA record, indicating the target domain "
                "may be unregistered and claimable by an attacker. "
                "OWASP: A05:2021-Security Misconfiguration | MITRE: T1584.001, T1590.002"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "subdomains": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of subdomain hostnames to evaluate",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": (
                            "Per-lookup asyncio.wait_for() timeout in seconds (default: 5). "
                            "Note: the underlying dig subprocess uses a fixed 3-second timeout; "
                            "the effective timeout is min(this value, 3 + subprocess overhead)."
                        ),
                        "default": 5,
                    },
                },
                "required": ["subdomains"],
            },
        )

    async def execute(self, **kwargs: Any) -> str:
        subdomains: List[str] = kwargs.get("subdomains", [])
        timeout: int = int(kwargs.get("timeout", 5))

        if not subdomains:
            return "Error: 'subdomains' list is required."

        results: List[str] = [
            f"[DanglingCNAMEDetectTool] Scanning {len(subdomains)} subdomain(s) for dangling CNAMEs\n"
            + "=" * 70
        ]
        dangling: List[str] = []

        async def _check_one(host: str) -> str:
            try:
                cname = await asyncio.wait_for(_async_resolve_cname(host), timeout=timeout)
            except asyncio.TimeoutError:
                return f"  [TIMEOUT] {host}"

            if not cname:
                return f"  [NO-CNAME] {host} — no CNAME record; skipping"

            try:
                ip = await asyncio.wait_for(_async_resolve_a(cname), timeout=timeout)
            except asyncio.TimeoutError:
                ip = None

            if ip is None:
                dangling.append(host)
                return (
                    f"  [DANGLING] {host}\n"
                    f"    CNAME target: {cname}\n"
                    f"    Target resolves: NO — potential takeover candidate"
                )
            return f"  [OK] {host} → {cname} → {ip}"

        tasks = [_check_one(h) for h in subdomains]
        outputs = await asyncio.gather(*tasks, return_exceptions=True)

        for item in outputs:
            if isinstance(item, Exception):
                results.append(f"  [ERROR] {item}")
            else:
                results.append(item)

        results.append("\n" + "=" * 70)
        results.append(f"Summary: {len(dangling)} dangling / {len(subdomains)} checked")
        if dangling:
            results.append("Dangling subdomains: " + ", ".join(dangling))

        return truncate_output("\n".join(results))


# ---------------------------------------------------------------------------
# DNSZoneTransferTool
# ---------------------------------------------------------------------------


class DNSZoneTransferTool(BaseTool):
    """
    Attempt AXFR DNS zone transfers against all nameservers for a domain.

    A successful zone transfer leaks the complete internal DNS structure of
    a domain, revealing all hostnames, IP addresses, and mail server records.

    OWASP: A05:2021-Security Misconfiguration
    MITRE: T1590.002 (Gather Victim Network Information: DNS)
    """

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="dns_zone_transfer",
            description=(
                "Attempt AXFR DNS zone transfers against all discovered nameservers "
                "for a target domain. Successful transfers expose the full internal "
                "DNS record set (A, MX, TXT, PTR, SRV, CNAME). "
                "OWASP: A05:2021-Security Misconfiguration | MITRE: T1590.002"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain to attempt zone transfer against",
                    },
                    "nameservers": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional explicit nameserver list; auto-discovered if omitted",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Per-nameserver AXFR timeout in seconds (default: 15)",
                        "default": 15,
                    },
                },
                "required": ["domain"],
            },
        )

    async def execute(self, **kwargs: Any) -> str:
        domain: Optional[str] = kwargs.get("domain")
        nameservers: List[str] = kwargs.get("nameservers", [])
        timeout: int = int(kwargs.get("timeout", 15))

        if not domain:
            return "Error: 'domain' parameter is required."

        domain = domain.strip().lower().rstrip(".")

        results: List[str] = [
            f"[DNSZoneTransferTool] Target domain: {domain}\n" + "=" * 70
        ]

        # Discover nameservers when none provided
        if not nameservers:
            results.append("Discovering nameservers...")
            try:
                nameservers = await asyncio.wait_for(_async_resolve_ns(domain), timeout=10)
            except asyncio.TimeoutError:
                nameservers = []

        if not nameservers:
            results.append(f"  No nameservers found for {domain}. Cannot attempt AXFR.")
            return truncate_output("\n".join(results))

        results.append(f"Nameservers found: {', '.join(nameservers)}\n")

        success_count = 0
        for ns in nameservers:
            results.append(f"--- Attempting AXFR from {ns} ---")
            try:
                output = await asyncio.wait_for(_async_axfr(domain, ns), timeout=timeout)
            except asyncio.TimeoutError:
                results.append(f"  [TIMEOUT] Zone transfer to {ns} timed out after {timeout}s")
                continue
            except Exception as exc:
                results.append(f"  [ERROR] {exc}")
                continue

            lower = output.lower()
            if "transfer failed" in lower or "xfr size" not in lower and not any(
                f".{domain}" in line or f"{domain}." in line
                for line in output.splitlines()
                if line.strip()
            ):
                results.append(f"  [BLOCKED] {ns} refused zone transfer (normal/secure)")
            else:
                success_count += 1
                results.append(f"  [SUCCESS] Zone transfer from {ns} succeeded!")
                results.append(output[:3000])

        results.append("\n" + "=" * 70)
        results.append(
            f"Summary: {success_count}/{len(nameservers)} nameservers allowed zone transfer"
        )
        if success_count:
            results.append(
                "CRITICAL: Zone transfer succeeded — full DNS record set exposed. "
                "Disable AXFR on nameservers immediately."
            )

        return truncate_output("\n".join(results))


# ---------------------------------------------------------------------------
# DNSCacheSnoopTool
# ---------------------------------------------------------------------------


class DNSCacheSnoopTool(BaseTool):
    """
    Detect cached DNS records via non-recursive queries (cache snooping).

    By sending non-recursive DNS queries (RD=0) to a resolver, an attacker can
    determine which hostnames have been recently queried — exposing internal
    infrastructure, visited sites, and potentially sensitive hostnames cached
    by the resolver.

    OWASP: A05:2021-Security Misconfiguration
    MITRE: T1590.002 (Gather Victim Network Information: DNS)
    """

    _DEFAULT_SNOOP_TARGETS = [
        "google.com",
        "facebook.com",
        "twitter.com",
        "github.com",
        "amazonaws.com",
        "microsoft.com",
        "office365.com",
        "sharepoint.com",
        "confluence.atlassian.com",
        "jira.atlassian.com",
        "slack.com",
        "zoom.us",
        "dropbox.com",
        "onedrive.live.com",
        "mail.google.com",
        "smtp.gmail.com",
        "internal.corp",
        "intranet.corp",
        "vpn.corp",
        "git.internal",
        "jenkins.internal",
        "kibana.internal",
        "grafana.internal",
        "prometheus.internal",
    ]

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="dns_cache_snoop",
            description=(
                "Detect recently resolved hostnames via DNS cache snooping. "
                "Sends non-recursive (RD=0) queries to a DNS resolver to determine which "
                "hostnames are cached, revealing browsing habits, internal services, and "
                "infrastructure details without direct contact with the target. "
                "OWASP: A05:2021-Security Misconfiguration | MITRE: T1590.002"
            ),
            parameters={
                "type": "object",
                "properties": {
                    "resolver": {
                        "type": "string",
                        "description": "Target DNS resolver IP to probe",
                    },
                    "targets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Hostnames to check in the cache (uses built-in list if omitted)",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Per-query timeout in seconds (default: 3)",
                        "default": 3,
                    },
                },
                "required": ["resolver"],
            },
        )

    async def execute(self, **kwargs: Any) -> str:
        resolver: Optional[str] = kwargs.get("resolver")
        targets: List[str] = kwargs.get("targets") or self._DEFAULT_SNOOP_TARGETS
        timeout: int = int(kwargs.get("timeout", 3))

        if not resolver:
            return "Error: 'resolver' parameter (DNS server IP) is required."

        results: List[str] = [
            f"[DNSCacheSnoopTool] Resolver: {resolver} | Checking {len(targets)} hostnames\n"
            + "=" * 70
        ]
        cached: List[str] = []

        async def _snoop_one(hostname: str) -> str:
            try:
                output = await asyncio.wait_for(
                    asyncio.to_thread(self._non_recursive_query, resolver, hostname),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                return f"  [TIMEOUT] {hostname}"
            except Exception as exc:
                return f"  [ERROR] {hostname}: {exc}"

            if output.get("cached"):
                cached.append(hostname)
                ttl = output.get("ttl", "?")
                return (
                    f"  [CACHED] {hostname}\n"
                    f"    Answer: {output.get('answer', 'N/A')} | TTL: {ttl}s"
                )
            return f"  [NOT-CACHED] {hostname}"

        tasks = [_snoop_one(h) for h in targets]
        outputs = await asyncio.gather(*tasks, return_exceptions=True)

        for item in outputs:
            if isinstance(item, Exception):
                results.append(f"  [ERROR] {item}")
            else:
                results.append(item)

        results.append("\n" + "=" * 70)
        results.append(f"Summary: {len(cached)} cached / {len(targets)} queried")
        if cached:
            results.append("Cached hostnames: " + ", ".join(cached))

        return truncate_output("\n".join(results))

    @staticmethod
    def _non_recursive_query(resolver_ip: str, hostname: str) -> Dict[str, Any]:
        """
        Send a non-recursive DNS query (RD=0) using dig.

        Returns a dict with keys:
          cached  — bool, whether the record was found in cache
          answer  — the resolved address string
          ttl     — TTL value remaining (shorter = more recently added)
        """
        try:
            result = subprocess.run(
                [
                    "dig",
                    f"@{resolver_ip}",
                    "+norecurse",
                    "+time=2",
                    "+tries=1",
                    "A",
                    hostname,
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout

            # Parse ANSWER SECTION
            in_answer = False
            answer_ip: Optional[str] = None
            ttl_val: Optional[int] = None
            for line in output.splitlines():
                if ";; ANSWER SECTION:" in line:
                    in_answer = True
                    continue
                if in_answer and line.strip() and not line.startswith(";"):
                    parts = line.split()
                    if len(parts) >= 5 and parts[3] == "A":
                        try:
                            ttl_val = int(parts[1])
                        except ValueError:
                            ttl_val = None
                        answer_ip = parts[4]
                        break
                elif in_answer and line.strip() == "":
                    break

            return {
                "cached": answer_ip is not None,
                "answer": answer_ip,
                "ttl": ttl_val,
            }
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            # dig not available; fallback always reports not cached
            return {"cached": False, "answer": None, "ttl": None}
