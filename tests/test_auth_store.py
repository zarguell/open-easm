from __future__ import annotations

import hashlib
import uuid

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


@pytest.mark.db
async def test_create_api_key(db_pool, user_data):
    store = Store(db_pool)
    user = await store.create_user(**user_data)
    key_hash = hashlib.sha256(b"test_key").hexdigest()
    api_key = await store.create_api_key(
        user_id=user["id"],
        name="test-key",
        key_prefix="easm_abc",
        key_hash=key_hash,
    )
    assert api_key["id"] is not None
    assert api_key["name"] == "test-key"
    assert api_key["key_prefix"] == "easm_abc"
    assert api_key["key_hash"] == key_hash
    assert api_key["expires_at"] is None


@pytest.mark.db
async def test_validate_api_key(db_pool, user_data):
    store = Store(db_pool)
    user = await store.create_user(**user_data)
    key_hash = hashlib.sha256(b"test_key").hexdigest()
    await store.create_api_key(
        user_id=user["id"],
        name="test-key",
        key_prefix="easm_abc",
        key_hash=key_hash,
    )
    result = await store.validate_api_key(key_hash)
    assert result is not None
    assert result["user_id"] == user["id"]
    assert result["username"] == "admin"


@pytest.mark.db
async def test_validate_api_key_not_found(db_pool):
    store = Store(db_pool)
    fake_hash = hashlib.sha256(b"nonexistent").hexdigest()
    result = await store.validate_api_key(fake_hash)
    assert result is None


@pytest.mark.db
async def test_validate_api_key_expired(db_pool, user_data):
    from datetime import datetime, timedelta, UTC

    store = Store(db_pool)
    user = await store.create_user(**user_data)
    key_hash = hashlib.sha256(b"expired_key").hexdigest()
    await store.create_api_key(
        user_id=user["id"],
        name="expired-key",
        key_prefix="easm_exp",
        key_hash=key_hash,
        expires_at=datetime.now(UTC) - timedelta(hours=1),
    )
    result = await store.validate_api_key(key_hash)
    assert result is None


@pytest.mark.db
async def test_list_api_keys(db_pool, user_data):
    store = Store(db_pool)
    user = await store.create_user(**user_data)
    for i in range(3):
        key_hash = hashlib.sha256(f"key_{i}".encode()).hexdigest()
        await store.create_api_key(
            user_id=user["id"],
            name=f"key-{i}",
            key_prefix=f"easm_{i}",
            key_hash=key_hash,
        )
    keys = await store.list_api_keys(user["id"])
    assert len(keys) == 3


@pytest.mark.db
async def test_delete_api_key(db_pool, user_data):
    store = Store(db_pool)
    user = await store.create_user(**user_data)
    key_hash = hashlib.sha256(b"del_key").hexdigest()
    created = await store.create_api_key(
        user_id=user["id"],
        name="to-delete",
        key_prefix="easm_del",
        key_hash=key_hash,
    )
    deleted = await store.delete_api_key(created["id"], user["id"])
    assert deleted is True
    keys = await store.list_api_keys(user["id"])
    assert len(keys) == 0


@pytest.mark.db
async def test_delete_api_key_not_owned(db_pool, user_data):
    store = Store(db_pool)
    user = await store.create_user(**user_data)
    key_hash = hashlib.sha256(b"other_key").hexdigest()
    created = await store.create_api_key(
        user_id=user["id"],
        name="owned",
        key_prefix="easm_own",
        key_hash=key_hash,
    )
    fake_user_id = uuid.uuid4()
    deleted = await store.delete_api_key(created["id"], fake_user_id)
    assert deleted is False
