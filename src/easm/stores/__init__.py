"""Domain-specific store modules replacing the monolithic ``Store`` class.

Each submodule (``run_store``, ``entity_store``, ``finding_store``, ...)
exposes a single ``BaseStore`` subclass that owns one bounded area of
persistence. The top-level :class:`easm.store.Store` facade instantiates
every domain store and delegates to it, so existing callers continue to
work unchanged.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import asyncpg


class BaseStore:
    """Shared base for domain stores.

    Provides a typed view over an ``asyncpg`` connection pool plus two
    context managers (read connection, transactional connection) that
    subclasses use to scope work.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    @property
    def pool(self) -> asyncpg.Pool:
        """Underlying connection pool (exposed for legacy adapters)."""
        return self._pool

    async def _conn(self) -> AsyncIterator[asyncpg.Connection]:
        async with self._pool.acquire() as conn:
            yield conn

    async def _tx(self) -> AsyncIterator[asyncpg.Connection]:
        async with self._pool.acquire() as conn, conn.transaction():
            yield conn


__all__ = ["BaseStore"]
