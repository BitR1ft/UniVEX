"""
Authentication Service
Orchestrates user registration, login, token refresh, and logout by
coordinating UsersRepository and SessionsRepository.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Optional

from app.core.security import create_access_token, create_refresh_token, decode_token
from app.db.repositories.sessions_repo import SessionsRepository
from app.db.repositories.users_repo import UsersRepository
from app.schemas import Token, UserCreate

if TYPE_CHECKING:
    from prisma.models import User

logger = logging.getLogger(__name__)


class AuthService:
    """Business-logic layer for authentication operations."""

    def __init__(self, db: Any) -> None:
        self.users = UsersRepository(db)
        self.sessions = SessionsRepository(db)

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    async def register(self, user_data: UserCreate) -> User:
        """
        Register a new user after checking for duplicates.

        Args:
            user_data: Validated user creation payload.

        Returns:
            The newly created User record.

        Raises:
            ValueError: If the username or e-mail is already taken.
        """
        if await self.users.get_by_username(user_data.username):
            raise ValueError("Username already registered")
        if await self.users.get_by_email(user_data.email):
            raise ValueError("Email already registered")

        user = await self.users.create_user(
            email=user_data.email,
            username=user_data.username,
            password=user_data.password,
            full_name=user_data.full_name,
        )
        logger.info("Registered new user %s (%s)", user.id, user.username)
        return user

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------

    async def login(self, username: str, password: str) -> Token:
        """
        Authenticate a user and issue an access / refresh token pair.

        The refresh token is persisted in the sessions table so that it can
        be revoked later.

        Args:
            username: User's username.
            password: Plain-text password.

        Returns:
            A :class:`~app.schemas.Token` containing both tokens.

        Raises:
            ValueError: If credentials are invalid or the account is inactive.
        """
        user = await self.users.authenticate(username, password)
        if user is None:
            raise ValueError("Incorrect username or password")
        if not user.is_active:
            raise ValueError("User account is inactive")

        access_token = create_access_token(data={"sub": user.id, "username": user.username})
        refresh_token = create_refresh_token(data={"sub": user.id})

        # Persist refresh token
        await self.sessions.create_session(user_id=user.id, token=refresh_token)

        return Token(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
        )

    # ------------------------------------------------------------------
    # Token refresh
    # ------------------------------------------------------------------

    async def refresh(self, refresh_token: str) -> Token:
        """
        Issue a new token pair from a valid refresh token.

        The old refresh token is revoked and replaced.

        Args:
            refresh_token: The raw JWT refresh token string.

        Returns:
            A new :class:`~app.schemas.Token` pair.

        Raises:
            ValueError: If the token is invalid, revoked, or expired.
        """
        # Validate token signature / expiry
        payload = decode_token(refresh_token)
        if payload.get("type") != "refresh":
            raise ValueError("Invalid token type")

        # Check it exists and is not revoked in DB
        if not await self.sessions.is_valid(refresh_token):
            raise ValueError("Token has been revoked or has expired")

        user_id: Optional[str] = payload.get("sub")
        if not user_id:
            raise ValueError("Invalid token payload")

        user = await self.users.get_by_id(user_id)
        if user is None or not user.is_active:
            raise ValueError("User not found or inactive")

        # Revoke old token and issue new pair
        await self.sessions.revoke_session(refresh_token)
        new_access = create_access_token(data={"sub": user.id, "username": user.username})
        new_refresh = create_refresh_token(data={"sub": user.id})
        await self.sessions.create_session(user_id=user.id, token=new_refresh)

        return Token(
            access_token=new_access,
            refresh_token=new_refresh,
            token_type="bearer",
        )

    # ------------------------------------------------------------------
    # Logout
    # ------------------------------------------------------------------

    async def logout(self, refresh_token: str) -> None:
        """Revoke a single refresh token (logout from one device)."""
        await self.sessions.revoke_session(refresh_token)

    async def logout_all(self, user_id: str) -> None:
        """Revoke all refresh tokens for a user (logout from every device)."""
        await self.sessions.revoke_all_user_sessions(user_id)

    # ------------------------------------------------------------------
    # Get current user (used by API dependencies)
    # ------------------------------------------------------------------

    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Convenience wrapper for the users repository lookup."""
        return await self.users.get_by_id(user_id)
