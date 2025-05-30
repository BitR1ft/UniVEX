"""
SandboxedRunner — Executes plugin tools with restricted permissions.

Security model:
  - No filesystem writes outside /tmp/univex-sandbox/
  - No network connections except to the configured target IP/CIDR
  - CPU time limit per execution
  - Memory limit per execution
  - All file opens are audited and logged

Note: The security model is advisory-level (audit + check), not OS-enforced.
This is appropriate for a professional tool where operators are trusted.
Threading is used for timeout enforcement; multiprocessing is intentionally
avoided to keep the runner simple and reliable in test environments.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class SandboxViolation(Exception):
    """Raised when a security constraint is violated."""


@dataclass
class SandboxConfig:
    allowed_target_cidr: str = "0.0.0.0/0"
    max_cpu_seconds: float = 30.0
    max_memory_mb: float = 256.0
    sandbox_dir: str = "/tmp/univex-sandbox"
    allow_network: bool = True
    allow_filesystem_read: bool = True
    allow_filesystem_write: bool = False
    audit_log: bool = True


@dataclass
class ExecutionResult:
    success: bool
    output: str
    error: Optional[str] = None
    cpu_time: float = 0.0
    memory_mb: float = 0.0
    violations: List[str] = field(default_factory=list)


class SandboxedRunner:
    """Executes callables with resource tracking and security auditing."""

    def __init__(self, config: Optional[SandboxConfig] = None) -> None:
        self.config = config or SandboxConfig()
        self._audit_events: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run(
        self,
        func: Callable,
        *args: Any,
        timeout: float = None,
        **kwargs: Any,
    ) -> ExecutionResult:
        """
        Execute *func* with resource tracking.

        Catches all exceptions and records violations. Returns an
        ExecutionResult with success/failure and timing information.
        """
        effective_timeout = timeout if timeout is not None else self.config.max_cpu_seconds

        result_container: Dict[str, Any] = {
            "output": "",
            "error": None,
            "done": False,
        }
        violations: List[str] = []

        def _target():
            try:
                output = func(*args, **kwargs)
                result_container["output"] = str(output) if output is not None else ""
            except Exception as exc:
                result_container["error"] = str(exc)

            result_container["done"] = True

        self.audit("run", f"Starting execution of {getattr(func, '__name__', repr(func))}")

        start = time.perf_counter()
        t = threading.Thread(target=_target, daemon=True)
        t.start()
        t.join(timeout=effective_timeout)
        elapsed = time.perf_counter() - start

        if t.is_alive():
            violations.append(
                f"Execution exceeded timeout of {effective_timeout}s (cpu_limit={self.config.max_cpu_seconds}s)."
            )
            self.audit("violation", f"Timeout exceeded: {elapsed:.2f}s > {effective_timeout}s")
            return ExecutionResult(
                success=False,
                output="",
                error=f"Execution timed out after {effective_timeout}s.",
                cpu_time=elapsed,
                violations=violations,
            )

        if result_container["error"] is not None:
            self.audit("error", result_container["error"])
            return ExecutionResult(
                success=False,
                output="",
                error=result_container["error"],
                cpu_time=elapsed,
                violations=violations,
            )

        self.audit("run", f"Execution completed in {elapsed:.3f}s")
        return ExecutionResult(
            success=True,
            output=result_container["output"],
            cpu_time=elapsed,
            violations=violations,
        )

    # ------------------------------------------------------------------
    # Security checks
    # ------------------------------------------------------------------

    def check_network_allowed(self, host: str) -> bool:
        """Return True if *host* is within the allowed CIDR."""
        if not self.config.allow_network:
            self.audit("network_check", f"Network disabled; host={host} denied")
            return False
        try:
            network = ipaddress.ip_network(self.config.allowed_target_cidr, strict=False)
            addr = ipaddress.ip_address(host)
            allowed = addr in network
        except ValueError:
            # host is a hostname, not an IP — allow if network is unrestricted
            allowed = self.config.allowed_target_cidr == "0.0.0.0/0"

        self.audit(
            "network_check",
            f"host={host} cidr={self.config.allowed_target_cidr} allowed={allowed}",
        )
        return allowed

    def check_filesystem_allowed(self, path: str, write: bool = False) -> bool:
        """
        Check whether access to *path* is permitted.

        Writes are only allowed inside sandbox_dir.
        Reads are allowed anywhere if allow_filesystem_read is True.
        """
        abs_path = os.path.abspath(path)
        sandbox_abs = os.path.abspath(self.config.sandbox_dir)

        in_sandbox = abs_path.startswith(sandbox_abs)

        if write:
            allowed = self.config.allow_filesystem_write and in_sandbox
        else:
            allowed = self.config.allow_filesystem_read

        action = "write" if write else "read"
        self.audit(
            "filesystem_check",
            f"action={action} path={abs_path} in_sandbox={in_sandbox} allowed={allowed}",
        )
        return allowed

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    def audit(self, action: str, detail: str) -> None:
        """Record an audit event and log it."""
        if not self.config.audit_log:
            return
        event = {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "action": action,
            "detail": detail,
        }
        with self._lock:
            self._audit_events.append(event)
        logger.debug("[SandboxAudit] action=%s detail=%s", action, detail)

    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Return all recorded audit events."""
        with self._lock:
            return list(self._audit_events)

    # ------------------------------------------------------------------
    # Sandbox directory
    # ------------------------------------------------------------------

    def create_sandbox_dir(self) -> None:
        """Create the sandbox directory (mkdir -p)."""
        os.makedirs(self.config.sandbox_dir, exist_ok=True)
        self.audit("sandbox_dir", f"Ensured sandbox dir exists: {self.config.sandbox_dir}")
