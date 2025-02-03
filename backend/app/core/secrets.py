"""
Secrets management utilities.

Validates required secrets at startup, provides rotation hints, and is
designed to be vault-ready (all secrets loaded exclusively from environment
variables — no hard-coded fallbacks in production).
"""
import logging
import os
import secrets

logger = logging.getLogger(__name__)

# Minimum lengths for secrets (enforced in ALL environments for SECRET_KEY)
_MIN_SECRET_KEY_LEN = 32
_MIN_PASSWORD_LEN = 16

# Well-known placeholder values that must never be used in any environment
_KNOWN_BAD_KEYS = frozenset({
    "your-secret-key-change-this-in-production",
    "secret",
    "changeme",
    "password",
    "insecure",
    "dev",
    "development",
})


class SecretsValidationError(ValueError):
    """Raised when a required secret fails validation."""


def validate_secrets(environment: str = "development") -> None:
    """
    Validate that all required secrets are present and meet minimum standards.

    SECRET_KEY is validated in EVERY environment — a missing, too-short, or
    well-known placeholder key is a hard failure regardless of ``environment``.

    In production, database passwords are also validated.
    In other environments, database password issues log a warning instead.

    Checks:
    - SECRET_KEY: present, NOT a known placeholder, >= 32 chars (always fatal)
    - POSTGRES_PASSWORD: present, >= 16 chars in production
    - NEO4J_PASSWORD: present, >= 16 chars in production
    """
    is_prod = environment.lower() == "production"
    fatal_errors: list[str] = []
    warnings: list[str] = []

    # --- SECRET_KEY: always a fatal error ---
    secret_key = os.getenv("SECRET_KEY", "")
    if not secret_key:
        fatal_errors.append(
            "SECRET_KEY is not set. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    elif secret_key.lower() in _KNOWN_BAD_KEYS:
        fatal_errors.append(
            f"SECRET_KEY is set to a well-known insecure placeholder value "
            f"('{secret_key[:20]}...'). This is a critical security vulnerability. "
            "Generate a safe key with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    elif len(secret_key) < _MIN_SECRET_KEY_LEN:
        fatal_errors.append(
            f"SECRET_KEY does not meet the minimum length requirement "
            f"({len(secret_key)} chars provided, {_MIN_SECRET_KEY_LEN} required)."
        )

    # --- Database passwords: fatal in production, warning otherwise ---
    for var in ("POSTGRES_PASSWORD", "NEO4J_PASSWORD"):
        val = os.getenv(var, "")
        if len(val) < _MIN_PASSWORD_LEN:
            msg = (
                f"{var} does not meet the minimum length requirement for production "
                f"({_MIN_PASSWORD_LEN} characters)."
            )
            if is_prod:
                fatal_errors.append(msg)
            else:
                warnings.append(msg)

    # Emit warnings
    if warnings:
        warn_msg = "Secrets warnings (acceptable in dev, fix before production): " + "; ".join(warnings)
        logger.warning(warn_msg)

    # Emit fatal errors — always raise, regardless of environment
    if fatal_errors:
        msg = "Secrets validation FAILED: " + "; ".join(fatal_errors)
        logger.critical(msg)
        raise SecretsValidationError(msg)


def generate_secret(length: int = 64) -> str:
    """Generate a cryptographically secure random secret string."""
    return secrets.token_urlsafe(length)


def rotation_hint(secret_name: str) -> str:
    """Return a human-readable hint for rotating a named secret."""
    return (
        f"To rotate {secret_name}: "
        "1) generate a new value with `generate_secret()`, "
        "2) update it in your secrets manager / .env, "
        "3) restart all services that consume it."
    )
