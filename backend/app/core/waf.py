"""
Basic Web Application Firewall (WAF) rules and request sanitization.

Blocks requests that match common attack patterns (SQLi, XSS, path traversal)
before they reach application logic.
"""
from __future__ import annotations

import logging
import re
from typing import Sequence

from fastapi import HTTPException, Request, status

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Attack-pattern signatures (conservative set — tune to your risk profile)
# ---------------------------------------------------------------------------

_SQL_INJECTION_RE = re.compile(
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|CAST|CONVERT)\b"
    r"|\bOR\s+\d+=\d+"
    r"|--\s*$"
    r"|;\s*--)",
    re.IGNORECASE,
)

_XSS_RE = re.compile(
    r"(<\s*script|javascript\s*:|on\w+\s*=|<\s*iframe|<\s*object|<\s*embed)",
    re.IGNORECASE,
)

_PATH_TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\")

_SIGNATURES: Sequence[tuple[str, re.Pattern[str]]] = [
    ("sql_injection", _SQL_INJECTION_RE),
    ("xss", _XSS_RE),
    ("path_traversal", _PATH_TRAVERSAL_RE),
]


def sanitize_string(value: str) -> str:
    """
    Strip leading/trailing whitespace and remove null bytes from a string.
    Does NOT HTML-escape — that is the responsibility of the template/serialiser.
    """
    return value.strip().replace("\x00", "")


def check_for_attacks(value: str, field_name: str = "input") -> None:
    """
    Raise HTTP 400 if ``value`` matches any known attack pattern.

    Args:
        value: The string to check.
        field_name: Human-readable field name for the error message.
    """
    for attack_type, pattern in _SIGNATURES:
        if pattern.search(value):
            logger.warning(
                "WAF blocked potential %s in field '%s': %.80r",
                attack_type,
                field_name,
                value,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Request blocked: potential {attack_type.replace('_', ' ')} detected in {field_name}",
            )


async def waf_check_request(request: Request) -> None:
    """
    FastAPI dependency — scan query parameters for attack patterns.

    Attach as a global dependency or per-router as needed.
    """
    for key, value in request.query_params.items():
        check_for_attacks(value, field_name=f"query:{key}")
