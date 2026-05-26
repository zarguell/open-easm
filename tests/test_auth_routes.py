from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from easm.api.app import create_app
from easm.api.deps import set_auth_config, set_config, set_store
from easm.auth.config import AuthConfig, LocalAuthConfig
from easm.auth.password import hash_password
from easm.config import Config, RuntimeConfig
from easm.store import Store


@pytest.fixture
async def auth_app(db_pool):
    app = create_app()
    auth_cfg = AuthConfig(
        mode="local",
        local=LocalAuthConfig(
            session_secret="test-secret-key-at-least-32-chars!!",
            session_max_age_seconds=3600,
            cookie_name="easm_session",
            cookie_secure=False,
        ),
    )
    set_auth_config(auth_cfg)
    test_config = Config(targets=[], runtime=RuntimeConfig())
    set_config(test_config)
    store = Store(db_pool)
    set_store(store)
    return app, store


@pytest.mark.db
@pytest.mark.asyncio
async def test_register_first_user(db_pool, auth_app):
    app, store = auth_app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/auth/register", json={
            "username": "admin",
            "password": "securepassword123",
            "email": "admin@test.com",
        })
        assert resp.status_code == 201
        body = resp.json()
        assert body["username"] == "admin"
        assert "id" in body
        assert "password_hash" not in body


@pytest.mark.db
@pytest.mark.asyncio
async def test_register_second_user_rejected(db_pool, auth_app):
    app, store = auth_app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/auth/register", json={
            "username": "admin",
            "password": "securepassword123",
            "email": "admin@test.com",
        })
        resp = await client.post("/api/auth/register", json={
            "username": "second",
            "password": "securepassword456",
            "email": "second@test.com",
        })
        assert resp.status_code == 403


@pytest.mark.db
@pytest.mark.asyncio
async def test_login_success(db_pool, auth_app):
    app, store = auth_app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/auth/register", json={
            "username": "admin",
            "password": "securepassword123",
            "email": "admin@test.com",
        })
        resp = await client.post("/api/auth/login", json={
            "username": "admin",
            "password": "securepassword123",
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["username"] == "admin"
        assert "easm_session" in resp.cookies


@pytest.mark.db
@pytest.mark.asyncio
async def test_login_wrong_password(db_pool, auth_app):
    app, store = auth_app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/auth/register", json={
            "username": "admin",
            "password": "securepassword123",
            "email": "admin@test.com",
        })
        resp = await client.post("/api/auth/login", json={
            "username": "admin",
            "password": "wrongpassword",
        })
        assert resp.status_code == 401


@pytest.mark.db
@pytest.mark.asyncio
async def test_logout(db_pool, auth_app):
    app, store = auth_app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/auth/register", json={
            "username": "admin",
            "password": "securepassword123",
            "email": "admin@test.com",
        })
        login_resp = await client.post("/api/auth/login", json={
            "username": "admin",
            "password": "securepassword123",
        })
        assert login_resp.status_code == 200
        resp = await client.post("/api/auth/logout")
        assert resp.status_code == 200
        assert "easm_session" not in resp.cookies or resp.cookies.get("easm_session") == ""


@pytest.mark.db
@pytest.mark.asyncio
async def test_me_authenticated(db_pool, auth_app):
    app, store = auth_app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/auth/register", json={
            "username": "admin",
            "password": "securepassword123",
            "email": "admin@test.com",
        })
        await client.post("/api/auth/login", json={
            "username": "admin",
            "password": "securepassword123",
        })
        resp = await client.get("/api/auth/me")
        assert resp.status_code == 200
        assert resp.json()["username"] == "admin"


@pytest.mark.db
@pytest.mark.asyncio
async def test_create_api_key(db_pool, auth_app):
    app, store = auth_app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/auth/register", json={
            "username": "admin",
            "password": "securepassword123",
        })
        await client.post("/api/auth/login", json={
            "username": "admin",
            "password": "securepassword123",
        })
        resp = await client.post("/api/auth/api-keys", json={
            "name": "ci-key",
            "expires_in_days": 90,
        })
        assert resp.status_code == 201
        body = resp.json()
        assert body["name"] == "ci-key"
        assert "key" in body
        assert body["key"].startswith("easm_")
        assert "id" in body


@pytest.mark.db
@pytest.mark.asyncio
async def test_list_api_keys(db_pool, auth_app):
    app, store = auth_app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/auth/register", json={
            "username": "admin",
            "password": "securepassword123",
        })
        await client.post("/api/auth/login", json={
            "username": "admin",
            "password": "securepassword123",
        })
        await client.post("/api/auth/api-keys", json={"name": "key1"})
        await client.post("/api/auth/api-keys", json={"name": "key2"})
        resp = await client.get("/api/auth/api-keys")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 2
        assert all("key" not in k for k in body)


@pytest.mark.db
@pytest.mark.asyncio
async def test_delete_api_key(db_pool, auth_app):
    app, store = auth_app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/auth/register", json={
            "username": "admin",
            "password": "securepassword123",
        })
        await client.post("/api/auth/login", json={
            "username": "admin",
            "password": "securepassword123",
        })
        create_resp = await client.post("/api/auth/api-keys", json={"name": "to-delete"})
        key_id = create_resp.json()["id"]
        resp = await client.delete(f"/api/auth/api-keys/{key_id}")
        assert resp.status_code == 204
        list_resp = await client.get("/api/auth/api-keys")
        assert len(list_resp.json()) == 0


@pytest.mark.db
@pytest.mark.asyncio
async def test_api_key_authenticates_requests(db_pool, auth_app):
    app, store = auth_app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/auth/register", json={
            "username": "admin",
            "password": "securepassword123",
        })
        await client.post("/api/auth/login", json={
            "username": "admin",
            "password": "securepassword123",
        })
        create_resp = await client.post("/api/auth/api-keys", json={"name": "test-key"})
        raw_key = create_resp.json()["key"]

        resp = await client.get("/api/auth/me", headers={"X-API-Key": raw_key})
        assert resp.status_code == 200
        assert resp.json()["username"] == "admin"
