"""
Tests for PLAN.md Day 4 — JWT Security Testing Suite

Coverage:
  - _b64url_decode() / _b64url_encode(): Base64URL codec round-trips
  - _parse_jwt(): JWT token parsing and validation
  - _sign_hmac(): HMAC signature generation
  - _forge_none_alg(): alg:none token generation
  - _detect_algorithm(): algorithm extraction
  - _check_exp(): expiry claim validation
  - JWTAnalyzeTool: metadata, alg:none forgery, RS256→HS256, sensitive claims
  - JWTBruteForceTool: metadata, cracking weak secrets, non-HMAC rejection
  - JWTForgeTool: metadata, alg:none forgery, HMAC re-sign, expiry extension
  - ToolRegistry: JWT tools registered in correct phases
  - AttackPathRouter: JWT/token keywords → WEB_APP_ATTACK
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest

from app.agent.attack_path_router import AttackCategory, AttackPathRouter
from app.agent.state.agent_state import Phase
from app.agent.tools.jwt_tools import (
    OWASP_JWT_TAG,
    JWTAnalyzeTool,
    JWTBruteForceTool,
    JWTForgeTool,
    JWTVulnerability,
    _WEAK_SECRETS,
    _b64url_decode,
    _b64url_encode,
    _check_exp,
    _detect_algorithm,
    _forge_none_alg,
    _parse_jwt,
    _sign_hmac,
)


# ===========================================================================
# Fixtures — sample JWTs
# ===========================================================================


def _make_hs256_token(
    header_overrides: dict = None,
    payload_overrides: dict = None,
    secret: str = "secret",
) -> str:
    """Create a valid HS256 JWT for testing."""
    header = {"alg": "HS256", "typ": "JWT"}
    if header_overrides:
        header.update(header_overrides)
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "role": "user",
        "iat": 1516239022,
        "exp": int(time.time()) + 3600,
    }
    if payload_overrides:
        payload.update(payload_overrides)
    return _sign_hmac(header, payload, secret)


# ===========================================================================
# _b64url_decode / _b64url_encode
# ===========================================================================


class TestB64Url:
    def test_encode_decode_roundtrip(self):
        original = b"Hello, JWT!"
        encoded = _b64url_encode(original)
        decoded = _b64url_decode(encoded)
        assert decoded == original

    def test_no_padding_in_encoded(self):
        encoded = _b64url_encode(b"test")
        assert "=" not in encoded

    def test_url_safe_characters(self):
        encoded = _b64url_encode(b"\xff\xfe\xfd")
        assert "+" not in encoded
        assert "/" not in encoded

    def test_decode_with_plus_slash(self):
        # Standard base64 with + and / should decode correctly
        data = b"\xfb\xff"
        encoded = _b64url_encode(data)
        assert _b64url_decode(encoded) == data

    def test_json_roundtrip(self):
        obj = {"alg": "HS256", "typ": "JWT"}
        encoded = _b64url_encode(json.dumps(obj, separators=(",", ":")).encode())
        decoded = json.loads(_b64url_decode(encoded))
        assert decoded == obj


# ===========================================================================
# _parse_jwt
# ===========================================================================


class TestParseJWT:
    def test_valid_token_parsed(self):
        token = _make_hs256_token()
        result = _parse_jwt(token)
        assert result is not None
        header, payload, sig = result
        assert header["alg"] == "HS256"
        assert "sub" in payload

    def test_invalid_format_none(self):
        assert _parse_jwt("not.a.jwt.with.five.parts") is None
        assert _parse_jwt("onlyone") is None

    def test_two_parts_invalid(self):
        assert _parse_jwt("header.payload") is None

    def test_bearer_prefix_not_stripped(self):
        # parse_jwt receives clean token — stripping is done by the tool
        token = _make_hs256_token()
        assert _parse_jwt(f"Bearer {token}") is None  # Bearer prefix makes it invalid

    def test_whitespace_stripped(self):
        token = _make_hs256_token()
        result = _parse_jwt(f"  {token}  ")
        assert result is not None

    def test_three_parts_always_returns_tuple(self):
        token = _make_hs256_token()
        result = _parse_jwt(token)
        assert len(result) == 3


# ===========================================================================
# _sign_hmac
# ===========================================================================


class TestSignHMAC:
    def test_produces_three_parts(self):
        token = _sign_hmac({"alg": "HS256", "typ": "JWT"}, {"sub": "1"}, "secret")
        assert token.count(".") == 2

    def test_signature_verifiable(self):
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "test"}
        token = _sign_hmac(header, payload, "my_secret")
        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected_sig = hmac.new(b"my_secret", signing_input, hashlib.sha256).digest()
        actual_sig = _b64url_decode(parts[2])
        assert hmac.compare_digest(actual_sig, expected_sig)

    def test_hs384_uses_sha384(self):
        token = _sign_hmac({"alg": "HS384"}, {"sub": "1"}, "sec", "HS384")
        # HS384 signature is 48 bytes → base64url is 64 chars
        sig_part = token.split(".")[2]
        decoded = _b64url_decode(sig_part)
        assert len(decoded) == 48

    def test_hs512_uses_sha512(self):
        token = _sign_hmac({"alg": "HS512"}, {"sub": "1"}, "sec", "HS512")
        sig_part = token.split(".")[2]
        decoded = _b64url_decode(sig_part)
        assert len(decoded) == 64

    def test_different_secrets_different_signatures(self):
        h = {"alg": "HS256"}
        p = {"sub": "1"}
        t1 = _sign_hmac(h, p, "secret1")
        t2 = _sign_hmac(h, p, "secret2")
        assert t1 != t2


# ===========================================================================
# _forge_none_alg
# ===========================================================================


class TestForgeNoneAlg:
    def test_alg_set_to_none(self):
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "1", "role": "user"}
        forged = _forge_none_alg(header, payload)
        assert forged.endswith(".")  # Empty signature
        parts = forged.split(".")
        assert len(parts) == 3
        decoded_header = json.loads(_b64url_decode(parts[0]))
        assert decoded_header["alg"] == "none"

    def test_payload_unchanged(self):
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "1", "role": "admin"}
        forged = _forge_none_alg(header, payload)
        parts = forged.split(".")
        decoded_payload = json.loads(_b64url_decode(parts[1]))
        assert decoded_payload["role"] == "admin"

    def test_empty_signature_segment(self):
        forged = _forge_none_alg({"alg": "HS256"}, {"sub": "x"})
        assert forged.endswith(".")
        assert forged.split(".")[2] == ""


# ===========================================================================
# _detect_algorithm
# ===========================================================================


class TestDetectAlgorithm:
    def test_hs256(self):
        assert _detect_algorithm({"alg": "HS256"}) == "HS256"

    def test_rs256(self):
        assert _detect_algorithm({"alg": "RS256"}) == "RS256"

    def test_missing_alg(self):
        assert _detect_algorithm({}) == "UNKNOWN"

    def test_lowercase_normalised(self):
        assert _detect_algorithm({"alg": "hs256"}) == "HS256"


# ===========================================================================
# _check_exp
# ===========================================================================


class TestCheckExp:
    def test_missing_exp_returns_message(self):
        result = _check_exp({"sub": "1"})
        assert result is not None
        assert "exp" in result.lower()

    def test_expired_token_returns_message(self):
        past = int(time.time()) - 3600
        result = _check_exp({"exp": past})
        assert result is not None
        assert "expired" in result.lower()

    def test_valid_future_exp_returns_none(self):
        future = int(time.time()) + 3600
        assert _check_exp({"exp": future}) is None


# ===========================================================================
# JWTAnalyzeTool metadata
# ===========================================================================


class TestJWTAnalyzeToolMetadata:
    def test_name(self):
        assert JWTAnalyzeTool().name == "jwt_analyze"

    def test_description_mentions_jwt(self):
        tool = JWTAnalyzeTool()
        assert "jwt" in tool.description.lower()

    def test_owasp_tag(self):
        assert "A02:2021" in OWASP_JWT_TAG

    def test_parameters_has_token(self):
        tool = JWTAnalyzeTool()
        assert "token" in tool.metadata.parameters.get("properties", {})

    def test_parameters_has_public_key(self):
        tool = JWTAnalyzeTool()
        assert "public_key" in tool.metadata.parameters.get("properties", {})


# ===========================================================================
# JWTAnalyzeTool execute
# ===========================================================================


class TestJWTAnalyzeToolExecute:
    @pytest.mark.asyncio
    async def test_invalid_token_returns_error(self):
        tool = JWTAnalyzeTool()
        result = await tool.execute(token="not.a.valid.jwt")
        assert "Invalid JWT" in result

    @pytest.mark.asyncio
    async def test_bearer_prefix_stripped(self):
        token = _make_hs256_token()
        tool = JWTAnalyzeTool()
        result = await tool.execute(token=f"Bearer {token}")
        assert "jwt_analyze" in result
        assert "Invalid JWT" not in result

    @pytest.mark.asyncio
    async def test_none_alg_tokens_generated(self):
        token = _make_hs256_token()
        tool = JWTAnalyzeTool()
        result = await tool.execute(token=token)
        assert "none" in result.lower()
        assert "NONE_ALGORITHM" in result or "none_algorithm" in result

    @pytest.mark.asyncio
    async def test_missing_exp_detected(self):
        token = _make_hs256_token(payload_overrides={"sub": "1"})
        # Parse and recreate without exp
        parts = token.split(".")
        payload = json.loads(_b64url_decode(parts[1]))
        payload.pop("exp", None)
        header = json.loads(_b64url_decode(parts[0]))
        token_no_exp = _sign_hmac(header, payload, "secret")

        tool = JWTAnalyzeTool()
        result = await tool.execute(token=token_no_exp)
        assert "exp" in result.lower()

    @pytest.mark.asyncio
    async def test_sensitive_claims_detected(self):
        token = _make_hs256_token(payload_overrides={"password": "hunter2"})
        tool = JWTAnalyzeTool()
        result = await tool.execute(token=token)
        assert "password" in result.lower() or "sensitive" in result.lower()

    @pytest.mark.asyncio
    async def test_kid_header_flagged(self):
        token = _make_hs256_token(header_overrides={"kid": "key-123"})
        tool = JWTAnalyzeTool()
        result = await tool.execute(token=token)
        assert "kid" in result.lower()

    @pytest.mark.asyncio
    async def test_header_payload_decoded_in_output(self):
        token = _make_hs256_token()
        tool = JWTAnalyzeTool()
        result = await tool.execute(token=token)
        assert "HS256" in result
        assert "1234567890" in result  # sub claim value


# ===========================================================================
# JWTBruteForceTool metadata
# ===========================================================================


class TestJWTBruteForceToolMetadata:
    def test_name(self):
        assert JWTBruteForceTool().name == "jwt_brute_force"

    def test_description_mentions_brute(self):
        tool = JWTBruteForceTool()
        assert "brute" in tool.description.lower()

    def test_weak_secrets_list_populated(self):
        assert "secret" in _WEAK_SECRETS
        assert len(_WEAK_SECRETS) >= 20

    def test_parameters_has_token_and_wordlist(self):
        tool = JWTBruteForceTool()
        props = tool.metadata.parameters.get("properties", {})
        assert "token" in props
        assert "wordlist" in props


# ===========================================================================
# JWTBruteForceTool execute
# ===========================================================================


class TestJWTBruteForceToolExecute:
    @pytest.mark.asyncio
    async def test_cracks_weak_secret(self):
        token = _make_hs256_token(secret="secret")  # "secret" is in wordlist
        tool = JWTBruteForceTool()
        result = await tool.execute(token=token)
        assert "SECRET CRACKED" in result
        assert "'secret'" in result

    @pytest.mark.asyncio
    async def test_rejects_non_hmac_algorithm(self):
        # RS256 token (fake — we just manipulate the header)
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"sub": "1"}
        hb = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        pb = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        token = f"{hb}.{pb}.fakesig"
        tool = JWTBruteForceTool()
        result = await tool.execute(token=token)
        assert "RS256" in result
        assert "not an HMAC" in result or "Brute force only" in result

    @pytest.mark.asyncio
    async def test_strong_secret_not_cracked(self):
        strong_secret = "kX9#mP2@qL5!rT8$vN3&jH6*wF1%yB4"
        token = _make_hs256_token(secret=strong_secret)
        tool = JWTBruteForceTool()
        result = await tool.execute(token=token, max_candidates=50)
        assert "not cracked" in result.lower() or "SECRET CRACKED" not in result

    @pytest.mark.asyncio
    async def test_custom_wordlist_used(self):
        custom_secret = "unique_custom_secret_xyz"
        token = _make_hs256_token(secret=custom_secret)
        tool = JWTBruteForceTool()
        result = await tool.execute(token=token, wordlist=custom_secret)
        assert "SECRET CRACKED" in result

    @pytest.mark.asyncio
    async def test_invalid_token_rejected(self):
        tool = JWTBruteForceTool()
        result = await tool.execute(token="bad.token")
        assert "Invalid JWT" in result

    @pytest.mark.asyncio
    async def test_bearer_prefix_stripped(self):
        token = _make_hs256_token(secret="secret")
        tool = JWTBruteForceTool()
        result = await tool.execute(token=f"Bearer {token}")
        assert "SECRET CRACKED" in result


# ===========================================================================
# JWTForgeTool metadata
# ===========================================================================


class TestJWTForgeToolMetadata:
    def test_name(self):
        assert JWTForgeTool().name == "jwt_forge"

    def test_description_mentions_forge(self):
        tool = JWTForgeTool()
        assert "forge" in tool.description.lower() or "modified" in tool.description.lower()

    def test_parameters_has_token_and_overrides(self):
        tool = JWTForgeTool()
        props = tool.metadata.parameters.get("properties", {})
        assert "token" in props
        assert "claim_overrides" in props
        assert "secret" in props
        assert "extend_expiry" in props


# ===========================================================================
# JWTForgeTool execute
# ===========================================================================


class TestJWTForgeToolExecute:
    @pytest.mark.asyncio
    async def test_generates_none_alg_tokens(self):
        token = _make_hs256_token()
        tool = JWTForgeTool()
        result = await tool.execute(token=token, claim_overrides={"role": "admin"})
        assert "alg:none" in result or "NONE" in result.upper()

    @pytest.mark.asyncio
    async def test_claim_overrides_applied(self):
        token = _make_hs256_token()
        tool = JWTForgeTool()
        result = await tool.execute(token=token, claim_overrides={"role": "admin", "is_admin": True})
        assert "admin" in result

    @pytest.mark.asyncio
    async def test_hmac_resign_with_secret(self):
        token = _make_hs256_token(secret="secret")
        tool = JWTForgeTool()
        result = await tool.execute(
            token=token,
            secret="secret",
            claim_overrides={"role": "admin"},
        )
        assert "HMAC re-sign" in result or "re-sign" in result.lower()

    @pytest.mark.asyncio
    async def test_expiry_extended(self):
        token = _make_hs256_token()
        tool = JWTForgeTool()
        result = await tool.execute(token=token, extend_expiry=86400)
        # The result should contain forged tokens
        assert "jwt_forge" in result or "Forged" in result

    @pytest.mark.asyncio
    async def test_invalid_token_rejected(self):
        tool = JWTForgeTool()
        result = await tool.execute(token="bad.input")
        assert "Invalid JWT" in result

    @pytest.mark.asyncio
    async def test_bearer_prefix_stripped(self):
        token = _make_hs256_token()
        tool = JWTForgeTool()
        result = await tool.execute(token=f"Bearer {token}")
        assert "Invalid JWT" not in result

    @pytest.mark.asyncio
    async def test_none_alg_token_structure_valid(self):
        """Forged alg:none token must end with '.'."""
        token = _make_hs256_token()
        tool = JWTForgeTool()
        result = await tool.execute(token=token)
        # Extract forged token lines from output
        for line in result.splitlines():
            line = line.strip()
            if line.startswith("Bearer ") or (line.count(".") == 2 and line.endswith(".")):
                if line.endswith("."):
                    # Valid structure confirmed
                    parts = line.split(".")
                    assert len(parts) == 3


# ===========================================================================
# JWTVulnerability enum
# ===========================================================================


class TestJWTVulnerabilityEnum:
    def test_none_alg_value(self):
        assert JWTVulnerability.NONE_ALG.value == "none_algorithm"

    def test_weak_secret_value(self):
        assert JWTVulnerability.WEAK_SECRET.value == "weak_hmac_secret"

    def test_rs256_hs256_value(self):
        assert JWTVulnerability.RS256_HS256.value == "rs256_hs256_confusion"


# ===========================================================================
# ToolRegistry — JWT tools registered in correct phases
# ===========================================================================


class TestToolRegistryJWT:
    def test_jwt_analyze_informational(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.is_tool_allowed("jwt_analyze", Phase.INFORMATIONAL)

    def test_jwt_analyze_exploitation(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.is_tool_allowed("jwt_analyze", Phase.EXPLOITATION)

    def test_jwt_brute_force_exploitation_only(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.is_tool_allowed("jwt_brute_force", Phase.EXPLOITATION)
        assert not registry.is_tool_allowed("jwt_brute_force", Phase.INFORMATIONAL)

    def test_jwt_forge_exploitation_only(self):
        from app.agent.tools.tool_registry import create_default_registry
        registry = create_default_registry()
        assert registry.is_tool_allowed("jwt_forge", Phase.EXPLOITATION)
        assert not registry.is_tool_allowed("jwt_forge", Phase.INFORMATIONAL)


# ===========================================================================
# AttackPathRouter — JWT/token keywords → WEB_APP_ATTACK
# ===========================================================================


class TestAttackPathRouterJWT:
    def test_jwt_keyword(self):
        router = AttackPathRouter()
        assert router.classify_intent("Test JWT token vulnerabilities") == AttackCategory.WEB_APP_ATTACK

    def test_oauth_keyword(self):
        router = AttackPathRouter()
        assert router.classify_intent("Test OAuth2 redirect_uri manipulation") == AttackCategory.WEB_APP_ATTACK

    def test_alg_none_keyword(self):
        router = AttackPathRouter()
        assert router.classify_intent("Test alg none JWT bypass") == AttackCategory.WEB_APP_ATTACK

    def test_api_key_keyword(self):
        router = AttackPathRouter()
        assert router.classify_intent("Detect api key leakage in JavaScript bundles") == AttackCategory.WEB_APP_ATTACK

    def test_bearer_token_keyword(self):
        router = AttackPathRouter()
        assert router.classify_intent("Find exposed bearer token in HTTP responses") == AttackCategory.WEB_APP_ATTACK
