"""
Session Repository
Handles all database operations for the Session model (JWT refresh tokens).
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, List, Optional

from app.core.config import settings
from app.db.repositories.base import BaseRepository

if TYPE_CHECKING:
    from prisma.models import Session

logger = logging.getLogger(__name__)


class SessionsRepository(BaseRepository):
    """Repository for Session CRUD, token validation, and cleanup."""

    def __init__(self, db: Any) -> None:
        super().__init__(db)

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    async def create_session(self, user_id: str, token: str) -> Session:
        """
        Persist a refresh-token session record.

        The expiry date is calculated from
        ``settings.REFRESH_TOKEN_EXPIRE_DAYS``.

        Args:
            user_id: Owner of the session.
            token: The raw JWT refresh token string.

        Returns:
            The created Session record.
        """
        expires_at = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        session = await self.db.session.create(
            data={
                "user_id": user_id,
                "token": token,
                "expires_at": expires_at,
            }
        )
        logger.info("Created session %s for user %s", session.id, user_id)
        return session

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def get_by_token(self, token: str) -> Optional[Session]:
        """Return a Session by its raw token value, or *None*."""
        return await self.db.session.find_unique(where={"token": token})

    async def get_active_sessions(self, user_id: str) -> List[Session]:
        """Return all non-revoked, non-expired sessions for a user."""
        now = datetime.utcnow()
        return await self.db.session.find_many(
            where={
                "user_id": user_id,
                "is_revoked": False,
                "expires_at": {"gt": now},
            }
        )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    async def is_valid(self, token: str) -> bool:
        """
        Return *True* if the token exists, is not revoked, and has not
        expired.
        """
        session = await self.get_by_token(token)
        if session is None:
            return False
        if session.is_revoked:
            return False
        if session.expires_at < datetime.utcnow():
            return False
        return True

    # ------------------------------------------------------------------
    # Revoke
    # ------------------------------------------------------------------

    async def revoke_session(self, token: str) -> Optional[Session]:
        """
        Mark a session as revoked.

        Returns:
            The updated Session, or *None* if the token was not found.
        """
        session = await self.get_by_token(token)
        if session is None:
            return None
        updated = await self.db.session.update(
            where={"token": token},
            data={"is_revoked": True},
        )
        logger.info("Revoked session %s", session.id)
        return updated

    async def revoke_all_user_sessions(self, user_id: str) -> int:
        """
        Revoke every active session for *user_id* (e.g. on password change).

        Returns:
            Number of sessions revoked.
        """
        result = await self.db.session.update_many(
            where={"user_id": user_id, "is_revoked": False},
            data={"is_revoked": True},
        )
        logger.info("Revoked %d sessions for user %s", result, user_id)
        return result

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    async def cleanup_expired(self) -> int:
        """
        Delete all expired or revoked sessions from the database.

        Returns:
            Number of sessions deleted.
        """
        now = datetime.utcnow()
        count = await self.db.session.delete_many(
            where={
                "OR": [
                    {"expires_at": {"lt": now}},
                    {"is_revoked": True},
                ]
            }
        )
        logger.info("Cleaned up %d expired/revoked sessions", count)
        return count
