from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Request

from easm.api.authz import current_org_id, require_admin  # noqa: F401  # re-exports

if TYPE_CHECKING:
    from easm.auth.config import AuthConfig
    from easm.config import Config
    from easm.scheduler import Scheduler
    from easm.store import Store

_config: Config | None = None
_store: Store | None = None
_scheduler: Scheduler | None = None
_auth_config: AuthConfig | None = None


def set_config(config: Config) -> None:
    global _config
    _config = config
    from easm.runtime import configure_runtime
    configure_runtime(config.runtime)


def set_store(store: Store) -> None:
    global _store
    _store = store


def set_scheduler(scheduler: Scheduler) -> None:
    global _scheduler
    _scheduler = scheduler


def set_auth_config(auth_config: AuthConfig) -> None:
    global _auth_config
    _auth_config = auth_config


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


def get_auth_config() -> AuthConfig:
    if _auth_config is None:
        from easm.auth.config import AuthConfig
        return AuthConfig()
    return _auth_config


def get_current_user(request: Request) -> dict | None:
    return getattr(request.state, "user", None)
