from __future__ import annotations

import pytest

from easm.store import Store


@pytest.fixture
def user_data():
    return {
        "org_id": "default",
        "username": "admin",
        "email": "admin@example.com",
        "password_hash": "bcrypt_hash_placeholder",
        "role": "admin",
    }


@pytest.mark.db
async def test_create_user(db_pool, user_data):
    store = Store(db_pool)
    user = await store.create_user(**user_data)
    assert user["id"] is not None
    assert user["username"] == "admin"
    assert user["org_id"] == "default"
    assert user["role"] == "admin"
    assert user["is_active"] is True


@pytest.mark.db
async def test_get_user_by_username(db_pool, user_data):
    store = Store(db_pool)
    created = await store.create_user(**user_data)
    found = await store.get_user_by_username("default", "admin")
    assert found is not None
    assert found["id"] == created["id"]


@pytest.mark.db
async def test_get_user_by_username_not_found(db_pool):
    store = Store(db_pool)
    found = await store.get_user_by_username("default", "nonexistent")
    assert found is None


@pytest.mark.db
async def test_get_user_by_id(db_pool, user_data):
    store = Store(db_pool)
    created = await store.create_user(**user_data)
    found = await store.get_user_by_id(created["id"])
    assert found is not None
    assert found["username"] == "admin"


@pytest.mark.db
async def test_create_user_duplicate_username_fails(db_pool, user_data):
    store = Store(db_pool)
    await store.create_user(**user_data)
    with pytest.raises(Exception):
        await store.create_user(**user_data)


@pytest.mark.db
async def test_user_count(db_pool, user_data):
    store = Store(db_pool)
    assert await store.user_count() == 0
    await store.create_user(**user_data)
    assert await store.user_count() == 1


@pytest.mark.db
async def test_create_sso_user(db_pool):
    store = Store(db_pool)
    user = await store.create_user(
        org_id="default",
        username="sso_user",
        email="sso@example.com",
        role="admin",
        sso_provider="google",
        sso_provider_id="google_12345",
    )
    assert user["sso_provider"] == "google"
    assert user["sso_provider_id"] == "google_12345"
    assert user["password_hash"] is None


@pytest.mark.db
async def test_get_user_by_sso(db_pool):
    store = Store(db_pool)
    await store.create_user(
        org_id="default",
        username="sso_user",
        email="sso@example.com",
        role="admin",
        sso_provider="google",
        sso_provider_id="google_12345",
    )
    found = await store.get_user_by_sso("google", "google_12345")
    assert found is not None
    assert found["username"] == "sso_user"


@pytest.mark.db
async def test_update_user_last_seen(db_pool, user_data):
    store = Store(db_pool)
    created = await store.create_user(**user_data)
    await store.update_user_last_seen(created["id"])
    found = await store.get_user_by_id(created["id"])
    assert found["updated_at"] is not None
