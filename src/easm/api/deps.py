from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from easm.store import Store
    from easm.scheduler import Scheduler
    from easm.config import Config


_config: Config | None = None
_store: Store | None = None
_scheduler: Scheduler | None = None


def set_config(config: Config) -> None:
    global _config
    _config = config


def set_store(store: Store) -> None:
    global _store
    _store = store


def set_scheduler(scheduler: Scheduler) -> None:
    global _scheduler
    _scheduler = scheduler


def get_config() -> Config:
    if _config is None:
        raise RuntimeError("config not initialized")
    return _config


def get_store() -> Store:
    if _store is None:
        raise RuntimeError("store not initialized")
    return _store


def get_scheduler() -> Scheduler:
    if _scheduler is None:
        raise RuntimeError("scheduler not initialized")
    return _scheduler
