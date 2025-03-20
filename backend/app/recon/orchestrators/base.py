"""
Base Tool Orchestrator

All concrete tool wrappers (Naabu, Nuclei, Katana, GAU, …) must extend
``BaseOrchestrator``.  The base class provides:

  - Input validation and sanitisation (domain, IP, URL, CIDR)
  - A standard ``run()`` lifecycle with pre/post hooks
  - Output normalisation to :class:`~app.recon.canonical_schemas.ReconResult`
  - Structured logging of execution metadata
"""
from __future__ import annotations

import abc
import ipaddress
import logging
import re
import shutil
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from app.recon.canonical_schemas import Endpoint, Finding, ReconResult, Technology

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def _is_valid_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value))


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_valid_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _is_valid_url(value: str) -> bool:
    try:
        result = urlparse(value)
        return all([result.scheme in ("http", "https"), result.netloc])
    except Exception:
        return False


def validate_target(target: str) -> str:
    """
    Validate and return the sanitised target string.

    Accepted formats: domain, IPv4, IPv6, CIDR block, HTTP/HTTPS URL.

    Raises:
        ValueError: If the target is empty, too long, or not a recognised format.
    """
    target = target.strip()
    if not target:
        raise ValueError("Target must not be empty")
    if len(target) > 2048:
        raise ValueError("Target exceeds maximum length (2048 chars)")

    if (
        _is_valid_domain(target)
        or _is_valid_ip(target)
        or _is_valid_cidr(target)
        or _is_valid_url(target)
    ):
        return target

    raise ValueError(
        f"Invalid target '{target}': must be a domain, IP address, CIDR, or HTTP/HTTPS URL"
    )


# ---------------------------------------------------------------------------
# BaseOrchestrator
# ---------------------------------------------------------------------------

class BaseOrchestrator(abc.ABC):
    """
    Abstract base class for all external tool orchestrators.

    Subclasses must implement :meth:`_execute` and :meth:`_normalise`.

    Lifecycle
    ---------
    ``run()``
      1. ``_pre_run()``  – validate target, check binary availability
      2. ``_execute()``  – invoke the external tool
      3. ``_normalise()``– convert raw output → ``ReconResult``
      4. ``_post_run()`` – log metrics, persist results

    Usage example::

        class NaabuOrchestrator(BaseOrchestrator):
            TOOL_NAME = "naabu"
            BINARY = "naabu"

            async def _execute(self) -> Any:
                ...

            def _normalise(self, raw: Any) -> ReconResult:
                ...
    """

    #: Override in subclasses with the canonical tool name (lower-case)
    TOOL_NAME: str = "unknown"

    #: Name of the binary that must exist on PATH (or None to skip check)
    BINARY: Optional[str] = None

    def __init__(
        self,
        target: str,
        project_id: Optional[str] = None,
        task_id: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.target = validate_target(target)
        self.project_id = project_id
        self.task_id = task_id
        self.config: Dict[str, Any] = config or {}
        self._logger = logging.getLogger(
            f"orchestrator.{self.TOOL_NAME}"
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> ReconResult:
        """
        Execute the full orchestration lifecycle and return a
        ``ReconResult``.

        This method should *not* be overridden; override
        ``_execute`` and ``_normalise`` instead.
        """
        started_at = datetime.utcnow()
        t0 = time.monotonic()

        self._logger.info(
            "Starting %s scan: target=%s project=%s task=%s",
            self.TOOL_NAME, self.target, self.project_id, self.task_id,
        )

        # 1. Pre-run validation
        try:
            await self._pre_run()
        except Exception as exc:
            success = False
            error_message = str(exc)
            self._logger.error(
                "%s pre-run validation failed: %s", self.TOOL_NAME, exc
            )
            # Return a failed result immediately without executing
            result = ReconResult(
                tool_name=self.TOOL_NAME,
                target=self.target,
                project_id=self.project_id,
                task_id=self.task_id,
                started_at=started_at,
                completed_at=datetime.utcnow(),
                duration_seconds=round(time.monotonic() - t0, 3),
                success=False,
                error_message=error_message,
            )
            await self._post_run(result)
            return result

        raw: Any = None
        error_message: Optional[str] = None
        success = True

        try:
            # 2. Execute
            raw = await self._execute()
        except Exception as exc:
            success = False
            error_message = str(exc)
            self._logger.error(
                "%s execution failed: %s", self.TOOL_NAME, exc, exc_info=True
            )

        duration = time.monotonic() - t0
        completed_at = datetime.utcnow()

        # 3. Normalise (even on partial failure)
        try:
            result = self._normalise(raw) if raw is not None else ReconResult(
                tool_name=self.TOOL_NAME,
                target=self.target,
            )
        except Exception as exc:
            self._logger.error("Normalisation failed: %s", exc, exc_info=True)
            result = ReconResult(tool_name=self.TOOL_NAME, target=self.target)
            success = False
            error_message = error_message or str(exc)

        result.project_id = self.project_id
        result.task_id = self.task_id
        result.started_at = started_at
        result.completed_at = completed_at
        result.duration_seconds = round(duration, 3)
        result.success = success
        result.error_message = error_message

        # 4. Post-run
        await self._post_run(result)

        self._logger.info(
            "%s complete: %s",
            self.TOOL_NAME,
            result.summary(),
        )
        return result

    # ------------------------------------------------------------------
    # Hooks (override as needed)
    # ------------------------------------------------------------------

    async def _pre_run(self) -> None:
        """
        Validate prerequisites before execution.

        Default implementation checks that the binary is available on PATH
        if ``BINARY`` is set.  Raise ``RuntimeError`` to abort the scan.
        """
        if self.BINARY and not shutil.which(self.BINARY):
            raise RuntimeError(
                f"Tool binary '{self.BINARY}' not found on PATH. "
                f"Ensure the {self.TOOL_NAME} container is running."
            )

    async def _post_run(self, result: ReconResult) -> None:
        """
        Called after normalisation.  Default implementation is a no-op.

        Override to persist results, update task status, etc.
        """

    # ------------------------------------------------------------------
    # Abstract methods (must implement in subclasses)
    # ------------------------------------------------------------------

    @abc.abstractmethod
    async def _execute(self) -> Any:
        """
        Invoke the external tool and return its raw output.

        The return value is passed verbatim to :meth:`_normalise`.
        Use ``asyncio.create_subprocess_exec`` for CLI tools, or an async
        HTTP client for API-based tools.
        """

    @abc.abstractmethod
    def _normalise(self, raw: Any) -> ReconResult:
        """
        Convert the raw tool output into a :class:`ReconResult`.

        Args:
            raw: The value returned by :meth:`_execute`.

        Returns:
            A fully populated :class:`ReconResult` with
            ``tool_name`` and ``target`` already set.
        """

    # ------------------------------------------------------------------
    # Convenience helpers for subclasses
    # ------------------------------------------------------------------

    def _make_result(
        self,
        endpoints: Optional[List[Endpoint]] = None,
        technologies: Optional[List[Technology]] = None,
        findings: Optional[List[Finding]] = None,
    ) -> ReconResult:
        """Build a ``ReconResult`` pre-filled with tool / target info."""
        return ReconResult(
            tool_name=self.TOOL_NAME,
            target=self.target,
            endpoints=endpoints or [],
            technologies=technologies or [],
            findings=findings or [],
        )
