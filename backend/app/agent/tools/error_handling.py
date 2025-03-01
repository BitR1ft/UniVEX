"""
Tool Error Handling

Defines exceptions and error handling for tool execution.
Includes structured error categorization and output management.

  - with_retry decorator for automatic retry with exponential back-off
  - ToolRateLimitError for rate-limit specific recovery
  - ToolErrorReporter for structured error reporting
  - ErrorCategory enum for consistent classification
"""

import asyncio
import logging
from enum import Enum
from functools import wraps
from typing import Callable, Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class ToolExecutionError(Exception):
    """Raised when a tool execution fails"""
    
    def __init__(self, message: str, tool_name: str = "", recoverable: bool = True):
        self.tool_name = tool_name
        self.recoverable = recoverable
        super().__init__(message)


class ToolTimeoutError(ToolExecutionError):
    """Raised when a tool execution times out"""
    
    def __init__(self, message: str, tool_name: str = "", timeout_seconds: int = 0):
        self.timeout_seconds = timeout_seconds
        super().__init__(message, tool_name=tool_name, recoverable=True)


class ToolValidationError(ToolExecutionError):
    """Raised when tool input validation fails"""
    
    def __init__(self, message: str, tool_name: str = "", invalid_params: list = None):
        self.invalid_params = invalid_params or []
        super().__init__(message, tool_name=tool_name, recoverable=True)


class ToolRateLimitError(ToolExecutionError):
    """Raised when a tool hits an API rate limit — always recoverable with back-off."""

    def __init__(self, message: str, tool_name: str = "", retry_after: int = 60):
        self.retry_after = retry_after
        super().__init__(message, tool_name=tool_name, recoverable=True)


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class ErrorCategory(str, Enum):
    """Standardised error categories for structured reporting."""
    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"
    CONNECTION = "connection"
    PERMISSION = "permission"
    NOT_FOUND = "not_found"
    PARSE = "parse"
    VALIDATION = "validation"
    UNKNOWN = "unknown"


# Map of keyword fragments → ErrorCategory (checked in order)
_CATEGORY_KEYWORDS: List[tuple] = [
    (ErrorCategory.TIMEOUT, ["timeout", "timed out", "time out"]),
    (ErrorCategory.RATE_LIMIT, ["rate limit", "rate-limit", "too many requests", "429"]),
    (ErrorCategory.CONNECTION, ["connection", "connect", "unreachable", "refused", "network"]),
    (ErrorCategory.PERMISSION, ["permission", "forbidden", "403", "unauthorized", "401", "access denied"]),
    (ErrorCategory.NOT_FOUND, ["not found", "404", "no such", "does not exist"]),
    (ErrorCategory.PARSE, ["parse", "json", "decode", "invalid response", "unexpected output"]),
    (ErrorCategory.VALIDATION, ["validation", "invalid param", "required field", "missing"]),
]

#: Per-category human-readable recovery hints
RECOVERY_HINTS: Dict[ErrorCategory, str] = {
    ErrorCategory.TIMEOUT: (
        "The tool timed out. Try reducing scope (fewer ports, smaller wordlist, "
        "shorter target list) or increasing the timeout parameter."
    ),
    ErrorCategory.RATE_LIMIT: (
        "Rate limit hit. Wait 60 seconds before retrying, or reduce the request "
        "rate with the rate_limit parameter."
    ),
    ErrorCategory.CONNECTION: (
        "Connection failed. Verify the target is reachable and the service is "
        "running. Check firewall rules and VPN connectivity."
    ),
    ErrorCategory.PERMISSION: (
        "Permission denied. Verify you have the required access level. "
        "Try with different credentials or a lower-privilege approach."
    ),
    ErrorCategory.NOT_FOUND: (
        "Resource not found. Verify the target path, module name, or CVE "
        "identifier. Check for typos."
    ),
    ErrorCategory.PARSE: (
        "Failed to parse tool output. The target may have returned unexpected "
        "data. Try with verbose mode or examine raw output."
    ),
    ErrorCategory.VALIDATION: (
        "Input validation failed. Check required parameters and their types. "
        "Review the tool's parameter schema."
    ),
    ErrorCategory.UNKNOWN: (
        "An unexpected error occurred. Review the error details and try "
        "alternative parameters or a different tool."
    ),
}


def categorise_error(error_message: str) -> ErrorCategory:
    """
    Classify an error message string into an ErrorCategory.

    Args:
        error_message: The error message to classify

    Returns:
        ErrorCategory enum value
    """
    lower = error_message.lower()
    for category, keywords in _CATEGORY_KEYWORDS:
        if any(kw in lower for kw in keywords):
            return category
    return ErrorCategory.UNKNOWN


def get_recovery_hint(error_message: str) -> str:
    """
    Return a recovery suggestion for an error message.

    Args:
        error_message: The error message to analyse

    Returns:
        Human-readable recovery hint
    """
    category = categorise_error(error_message)
    return RECOVERY_HINTS[category]


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class ToolErrorReporter:
    """
    Centralised structured error reporter for tool execution failures.

    Records all errors with metadata and provides summary/export methods.
    """

    def __init__(self):
        self._records: List[Dict[str, Any]] = []

    def record(
        self,
        tool_name: str,
        error: Exception,
        inputs: Optional[Dict[str, Any]] = None,
        attempt: int = 1,
    ) -> Dict[str, Any]:
        """
        Record a tool execution error.

        Args:
            tool_name: Name of the tool that failed
            error: Exception that was raised
            inputs: Tool input parameters (for debugging)
            attempt: Which retry attempt this was

        Returns:
            The recorded error entry
        """
        import datetime as _dt

        category = categorise_error(str(error))
        entry: Dict[str, Any] = {
            "timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "tool_name": tool_name,
            "error_type": type(error).__name__,
            "error_message": str(error),
            "category": category.value,
            "recovery_hint": RECOVERY_HINTS[category],
            "recoverable": getattr(error, "recoverable", True),
            "attempt": attempt,
            "inputs_summary": {k: str(v)[:100] for k, v in (inputs or {}).items()},
        }
        self._records.append(entry)
        logger.warning(
            f"[ToolError] {tool_name} (attempt {attempt}): "
            f"[{category.value}] {str(error)[:200]}"
        )
        return entry

    def get_records(self) -> List[Dict[str, Any]]:
        """Return all recorded error entries."""
        return list(self._records)

    def get_summary(self) -> Dict[str, Any]:
        """
        Return a summary of all recorded errors.

        Returns:
            Dict with total count, per-tool counts, and per-category counts
        """
        tool_counts: Dict[str, int] = {}
        category_counts: Dict[str, int] = {}
        for record in self._records:
            tool_counts[record["tool_name"]] = tool_counts.get(record["tool_name"], 0) + 1
            category_counts[record["category"]] = category_counts.get(record["category"], 0) + 1

        return {
            "total_errors": len(self._records),
            "per_tool": tool_counts,
            "per_category": category_counts,
        }

    def clear(self) -> None:
        """Clear all recorded errors."""
        self._records.clear()

    def has_unrecoverable(self) -> bool:
        """Return True if any recorded error was not recoverable."""
        return any(not r["recoverable"] for r in self._records)


# Module-level default reporter instance
default_reporter = ToolErrorReporter()


# ---------------------------------------------------------------------------
# Existing decorators (unchanged)
# ---------------------------------------------------------------------------


def with_timeout(timeout_seconds: int = 300):
    """
    Decorator to add timeout to tool execution.
    
    Args:
        timeout_seconds: Maximum execution time in seconds (default: 5 minutes)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            try:
                return await asyncio.wait_for(
                    func(*args, **kwargs),
                    timeout=timeout_seconds
                )
            except asyncio.TimeoutError:
                raise ToolTimeoutError(
                    f"Tool execution timed out after {timeout_seconds} seconds",
                    timeout_seconds=timeout_seconds
                )
        return wrapper
    return decorator


def with_error_context(tool_name: str):
    """
    Decorator to add error context to tool execution.
    
    Wraps generic exceptions with ToolExecutionError including tool name.
    
    Args:
        tool_name: Name of the tool for error context
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            try:
                return await func(*args, **kwargs)
            except (ToolExecutionError, ToolTimeoutError):
                raise  # Re-raise our own exceptions
            except Exception as e:
                raise ToolExecutionError(
                    f"{tool_name} failed: {type(e).__name__}: {str(e)}",
                    tool_name=tool_name,
                    recoverable=True
                ) from e
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


def with_retry(
    max_attempts: int = 3,
    backoff_base: float = 2.0,
    backoff_max: float = 60.0,
    retryable_exceptions: Optional[tuple] = None,
):
    """
    Decorator that retries an async function on failure with exponential back-off.

    Non-recoverable errors (``ToolExecutionError.recoverable = False``) are
    re-raised immediately without retrying.

    Args:
        max_attempts: Maximum number of attempts (including the first). Default: 3
        backoff_base: Base for exponential back-off (seconds). Default: 2.0
        backoff_max: Maximum back-off delay in seconds. Default: 60.0
        retryable_exceptions: Tuple of exception types to retry on.
            Defaults to (ToolExecutionError, ToolTimeoutError, ToolRateLimitError,
            ConnectionError, OSError).

    Usage::

        @with_retry(max_attempts=3)
        async def execute(self, **kwargs):
            ...
    """
    _default_retryable = (
        ToolExecutionError,
        ToolTimeoutError,
        ToolRateLimitError,
        ConnectionError,
        OSError,
    )
    _retryable = retryable_exceptions or _default_retryable

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            last_error: Optional[Exception] = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as exc:
                    last_error = exc

                    # Never retry unrecoverable errors
                    if isinstance(exc, ToolExecutionError) and not exc.recoverable:
                        logger.error(
                            f"[with_retry] Unrecoverable error on attempt {attempt}: {exc}"
                        )
                        raise

                    # Only retry if exception type is in the retryable set
                    if not isinstance(exc, _retryable):
                        raise

                    if attempt == max_attempts:
                        break

                    # Compute back-off delay
                    if isinstance(exc, ToolRateLimitError):
                        delay = min(exc.retry_after, backoff_max)
                    else:
                        delay = min(backoff_base ** (attempt - 1), backoff_max)

                    logger.warning(
                        f"[with_retry] {func.__qualname__} attempt {attempt}/{max_attempts} "
                        f"failed: {exc}. Retrying in {delay:.1f}s…"
                    )
                    await asyncio.sleep(delay)

            # All attempts exhausted
            raise ToolExecutionError(
                f"All {max_attempts} attempts failed. Last error: {last_error}",
                recoverable=False,
            ) from last_error

        return wrapper
    return decorator


def truncate_output(output: str, max_chars: int = 5000) -> str:
    """
    Truncate tool output to prevent overwhelming the LLM context.
    
    Args:
        output: Tool output string
        max_chars: Maximum characters to keep
        
    Returns:
        Truncated output with indicator if truncated
    """
    if len(output) <= max_chars:
        return output
    
    # Keep first 80% and last 10% of allowed chars
    first_part_len = int(max_chars * 0.8)
    last_part_len = int(max_chars * 0.1)
    
    first_part = output[:first_part_len]
    last_part = output[-last_part_len:]
    
    truncation_msg = f"\n\n... [Output truncated: {len(output) - max_chars} chars omitted] ...\n\n"
    
    return first_part + truncation_msg + last_part
