from __future__ import annotations

import os

import pytest
from httpx import ASGITransport, AsyncClient

from easm.api.app import create_app
from easm.api.deps import set_auth_config, set_config, set_store
from easm.auth.config import AuthConfig, ApiKeyConfig
from easm.config import Config, RuntimeConfig
from easm.store import Store


@pytest.fixture
def _make_app():
    return create_app


@pytest.mark.asyncio
async def test_none_mode_passes_through(db_pool):
    """In 'none' mode, requests pass through without auth."""
    app = create_app()
    auth_cfg = AuthConfig(mode="none")
    set_auth_config(auth_cfg)

    test_config = Config(targets=[], runtime=RuntimeConfig())
    set_config(test_config)
    set_store(Store(db_pool))

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/healthz")
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_api_key_auth_with_none_mode(db_pool):
    """API keys work even in 'none' mode — user identity is extracted."""
    app = create_app()
    auth_cfg = AuthConfig(
        mode="none",
        api_keys=ApiKeyConfig(enabled=True, header_name="X-API-Key"),
    )
    set_auth_config(auth_cfg)

    test_config = Config(targets=[], runtime=RuntimeConfig())
    set_config(test_config)

    store = Store(db_pool)
    set_store(store)

    user = await store.create_user(
        org_id="default", username="keyuser", email="k@test.com", role="admin",
        password_hash="unused",
    )
    from easm.auth.api_keys import hash_api_key as _hash_key

    raw_key = "easm_testkey1234567890abcdef"
    key_hash = _hash_key(raw_key)
    await store.create_api_key(
        user_id=user["id"], name="test", key_prefix="easm_test", key_hash=key_hash,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # /api/auth/me requires a valid identity — tests API key sets request.state.user
        resp = await client.get("/api/auth/me", headers={"X-API-Key": raw_key})
        assert resp.status_code == 200
        body = resp.json()
        assert body["username"] == "keyuser"


@pytest.mark.asyncio
async def test_invalid_api_key_returns_401(db_pool):
    """An invalid API key returns 401."""
    app = create_app()
    auth_cfg = AuthConfig(
        mode="none",
        api_keys=ApiKeyConfig(enabled=True, header_name="X-API-Key"),
    )
    set_auth_config(auth_cfg)

    test_config = Config(targets=[], runtime=RuntimeConfig())
    set_config(test_config)
    set_store(Store(db_pool))

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/auth/me", headers={"X-API-Key": "easm_invalid_key"})
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_reverse_proxy_mode_rejects_untrusted(db_pool):
    """Reverse proxy mode rejects requests from untrusted IPs."""
    app = create_app()
    from easm.auth.config import ReverseProxyAuthConfig

    auth_cfg = AuthConfig(
        mode="reverse_proxy",
        reverse_proxy=ReverseProxyAuthConfig(
            header="X-Forwarded-User",
            trusted_proxies=["10.0.0.0/8"],
        ),
    )
    set_auth_config(auth_cfg)

    test_config = Config(targets=[], runtime=RuntimeConfig())
    set_config(test_config)
    set_store(Store(db_pool))

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/targets", headers={"X-Forwarded-User": "admin"})
        assert resp.status_code == 401
