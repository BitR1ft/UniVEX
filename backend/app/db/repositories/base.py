"""
Base Repository
Provides common CRUD helpers shared by all concrete repositories.
"""
from typing import Any, Dict, Generic, List, TypeVar

ModelT = TypeVar("ModelT")


class BaseRepository(Generic[ModelT]):
    """
    Generic base repository with common CRUD helpers.

    Concrete repositories inject the Prisma client and call the
    underlying model accessor (``self.db.<model>``) directly, but they
    can delegate shared logic to this base class.
    """

    def __init__(self, db: Any) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # Helpers used by concrete repositories
    # ------------------------------------------------------------------

    @staticmethod
    def _strip_none(data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove keys whose value is *None* (for partial updates)."""
        return {k: v for k, v in data.items() if v is not None}

    @staticmethod
    def _paginate(items: List[Any], skip: int, take: int) -> List[Any]:
        """Apply in-memory pagination (used in tests without a real DB)."""
        return items[skip : skip + take]
