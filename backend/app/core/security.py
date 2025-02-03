"""
Security utilities for authentication and authorization
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
import hashlib
import hmac
import secrets
from fastapi import HTTPException, Response, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.core.config import settings

security = HTTPBearer()


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    # Salted SHA256 password hashing (upgrade to bcrypt/argon2 is recommended for production)
    salt = hashed_password.split(':')[0]
    password_hash = hashed_password.split(':')[1]
    computed_hash = hashlib.sha256((salt + plain_password).encode()).hexdigest()
    return computed_hash == password_hash


def get_password_hash(password: str) -> str:
    """Hash a password"""
    # Salted SHA256 password hashing (upgrade to bcrypt/argon2 is recommended for production)
    salt = secrets.token_hex(16)
    password_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{password_hash}"


# ---------------------------------------------------------------------------
# JWT tokens
# ---------------------------------------------------------------------------


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token
    
    Args:
        data: Data to encode in the token
        expires_delta: Optional custom expiration time
        
    Returns:
        Encoded JWT token
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    
    return encoded_jwt


def create_refresh_token(data: Dict[str, Any]) -> str:
    """
    Create a JWT refresh token
    
    Args:
        data: Data to encode in the token
        
    Returns:
        Encoded JWT refresh token
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "iat": datetime.utcnow(), "type": "refresh"})
    
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> Dict[str, Any]:
    """
    Decode and verify a JWT token
    
    Args:
        token: JWT token to decode
        
    Returns:
        Decoded token payload
        
    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """
    Dependency to get current user from token
    
    Args:
        credentials: HTTP authorization credentials
        
    Returns:
        Decoded token payload with user information
        
    Raises:
        HTTPException: If credentials are invalid
    """
    token_data = decode_token(credentials.credentials)
    user_id = token_data.get("sub")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )
    
    return token_data


# ---------------------------------------------------------------------------
# Cookie signing — Cookie Security
# ---------------------------------------------------------------------------

_COOKIE_DELIMITER = "."
_HMAC_DIGEST = "sha256"


def _get_cookie_signing_salt() -> bytes:
    """Return the COOKIE_SIGNING_SALT from settings as bytes."""
    return settings.COOKIE_SIGNING_SALT.encode("utf-8")


def sign_cookie(value: str) -> str:
    """
    Sign *value* with HMAC-SHA256 using ``COOKIE_SIGNING_SALT``.

    If ``COOKIE_SIGNING_SALT`` is empty (not configured), returns *value*
    unchanged — signing is silently skipped with a warning logged.

    Args:
        value: Plain cookie value to sign.

    Returns:
        ``"<value>.<hex-signature>"`` when signing is enabled, or *value*
        unchanged when ``COOKIE_SIGNING_SALT`` is not set.
    """
    salt = _get_cookie_signing_salt()
    if not salt:
        return value
    sig = hmac.new(key=salt, msg=value.encode("utf-8"), digestmod=_HMAC_DIGEST).hexdigest()
    return f"{value}{_COOKIE_DELIMITER}{sig}"


def verify_cookie(signed_value: str) -> Optional[str]:
    """
    Verify a signed cookie and return the original value.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        signed_value: Signed cookie string (``"<value>.<hex-signature>"``).

    Returns:
        The original *value* if the signature is valid, ``None`` otherwise.
        When signing is disabled (no salt), returns *signed_value* unchanged.
    """
    salt = _get_cookie_signing_salt()
    if not salt:
        return signed_value

    parts = signed_value.rsplit(_COOKIE_DELIMITER, maxsplit=1)
    if len(parts) != 2:
        return None

    value, sig = parts
    expected_sig = hmac.new(
        key=salt, msg=value.encode("utf-8"), digestmod=_HMAC_DIGEST
    ).hexdigest()

    if hmac.compare_digest(sig, expected_sig):
        return value
    return None


def set_secure_cookie(
    response: Response,
    key: str,
    value: str,
    sign: bool = True,
) -> None:
    """
    Set a cookie on *response* with security flags from settings.

    Applies ``SESSION_COOKIE_SECURE``, ``SESSION_COOKIE_HTTPONLY``,
    ``SESSION_COOKIE_SAMESITE``, ``SESSION_COOKIE_MAX_AGE`` and
    (when *sign* is True and ``COOKIE_SIGNING_SALT`` is set) an
    HMAC-SHA256 signature.

    Args:
        response:  FastAPI ``Response`` object (or ``JSONResponse``, etc.).
        key:       Cookie name.
        value:     Cookie value (will be signed if signing is enabled).
        sign:      Whether to apply HMAC signing (default True).
    """
    cookie_value = sign_cookie(value) if sign else value
    kwargs: Dict[str, Any] = {
        "key": key,
        "value": cookie_value,
        "httponly": settings.SESSION_COOKIE_HTTPONLY,
        "secure": settings.SESSION_COOKIE_SECURE,
        "samesite": settings.SESSION_COOKIE_SAMESITE,
        "path": settings.SESSION_COOKIE_PATH,
        "max_age": settings.SESSION_COOKIE_MAX_AGE,
    }
    if settings.SESSION_COOKIE_DOMAIN:
        kwargs["domain"] = settings.SESSION_COOKIE_DOMAIN
    response.set_cookie(**kwargs)

