"""
User Repository
Handles all database operations for the User model.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, List, Optional

from app.core.security import get_password_hash, verify_password
from app.db.repositories.base import BaseRepository

if TYPE_CHECKING:
    from prisma.models import User

logger = logging.getLogger(__name__)


class UsersRepository(BaseRepository):
    """Repository for User CRUD operations."""

    def __init__(self, db: Any) -> None:
        super().__init__(db)

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    async def create_user(
        self,
        email: str,
        username: str,
        password: str,
        full_name: Optional[str] = None,
        is_admin: bool = False,
    ) -> User:
        """
        Create a new user with a hashed password.

        Args:
            email: Unique e-mail address.
            username: Unique username (3-50 chars, alphanumeric).
            password: Plain-text password (will be hashed).
            full_name: Optional display name.
            is_admin: Grant admin privileges (default: False).

        Returns:
            The newly created User record.
        """
        hashed = get_password_hash(password)
        user = await self.db.user.create(
            data={
                "email": email,
                "username": username,
                "hashed_password": hashed,
                "full_name": full_name,
                "is_admin": is_admin,
            }
        )
        logger.info("Created user %s (%s)", user.id, username)
        return user

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def get_by_id(self, user_id: str) -> Optional[User]:
        """Return a user by primary key, or *None* if not found."""
        return await self.db.user.find_unique(where={"id": user_id})

    async def get_by_email(self, email: str) -> Optional[User]:
        """Return a user by e-mail address, or *None* if not found."""
        return await self.db.user.find_unique(where={"email": email})

    async def get_by_username(self, username: str) -> Optional[User]:
        """Return a user by username, or *None* if not found."""
        return await self.db.user.find_unique(where={"username": username})

    async def list_users(self, skip: int = 0, take: int = 50) -> List[User]:
        """Return a paginated list of all users."""
        return await self.db.user.find_many(skip=skip, take=take)

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    async def update_user(
        self,
        user_id: str,
        email: Optional[str] = None,
        full_name: Optional[str] = None,
        is_active: Optional[bool] = None,
        is_admin: Optional[bool] = None,
    ) -> Optional[User]:
        """
        Partially update a user record.

        Only the supplied (non-None) fields are written.

        Returns:
            Updated User record, or *None* if the user does not exist.
        """
        data = self._strip_none(
            {
                "email": email,
                "full_name": full_name,
                "is_active": is_active,
                "is_admin": is_admin,
            }
        )
        if not data:
            return await self.get_by_id(user_id)
        return await self.db.user.update(where={"id": user_id}, data=data)

    async def update_password(self, user_id: str, new_password: str) -> Optional[User]:
        """Replace a user's hashed password."""
        hashed = get_password_hash(new_password)
        return await self.db.user.update(
            where={"id": user_id},
            data={"hashed_password": hashed},
        )

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    async def delete_user(self, user_id: str) -> Optional[User]:
        """
        Delete a user and all their data (cascade enforced by schema).

        Returns:
            The deleted User record, or *None* if not found.
        """
        try:
            user = await self.db.user.delete(where={"id": user_id})
            logger.info("Deleted user %s", user_id)
            return user
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Auth helper
    # ------------------------------------------------------------------

    async def authenticate(self, username: str, password: str) -> Optional[User]:
        """
        Verify credentials and return the matching User.

        Returns *None* if the username does not exist or the password is
        wrong.
        """
        user = await self.get_by_username(username)
        if user is None:
            return None
        if not verify_password(password, user.hashed_password):
            return None
        return user
