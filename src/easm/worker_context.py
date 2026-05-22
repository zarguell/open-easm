from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import asyncpg
    from easm.store import Store

_pool: asyncpg.Pool | None = None
_store: Store | None = None
_config: Any = None


def set_context(pool: Any, store: Any, config: Any) -> None:
    global _pool, _store, _config
    _pool = pool
    _store = store
    _config = config


def get_pool() -> Any:
    assert _pool is not None, "Worker context not initialized"
    return _pool


def get_store() -> Any:
    assert _store is not None, "Worker context not initialized"
    return _store


def get_config() -> Any:
    return _config
