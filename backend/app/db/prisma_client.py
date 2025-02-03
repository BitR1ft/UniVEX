"""
Async Prisma Client Singleton
Manages the shared Prisma client instance with connection pooling
"""
import logging

logger = logging.getLogger(__name__)

_prisma_client = None


async def get_prisma():
    """
    Return the global Prisma client, connecting on first call.

    Usage (FastAPI dependency)::

        @router.get("/")
        async def handler(db = Depends(get_prisma)):
            ...
    """
    global _prisma_client
    if _prisma_client is None:
        from prisma import Prisma  # lazy – only needs generated client at call time
        _prisma_client = Prisma()
        await _prisma_client.connect()
        logger.info("Prisma client connected")
    return _prisma_client


async def disconnect_prisma() -> None:
    """Disconnect the global Prisma client (call on application shutdown)."""
    global _prisma_client
    if _prisma_client is not None:
        await _prisma_client.disconnect()
        _prisma_client = None
        logger.info("Prisma client disconnected")
