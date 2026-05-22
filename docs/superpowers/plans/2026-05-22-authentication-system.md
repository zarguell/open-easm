# Authentication System Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a configurable authentication system supporting four modes (none, reverse proxy, local credentials, SSO) plus API key lifecycle management.

**Architecture:** Auth is implemented as FastAPI HTTP middleware that intercepts all requests except healthz and auth routes. The mode is selected via `auth.mode` in config.yaml. API keys are validated against a hashed database table and work in any mode. User sessions use JWT tokens stored in httpOnly cookies (local and SSO modes). The existing `Store` class gains user and API key query methods. A `get_current_user` FastAPI dependency provides per-request user context.

**Tech Stack:** FastAPI middleware, PyJWT (JWT signing), passlib/bcrypt (password hashing), fastapi-sso (OAuth2 SSO), asyncpg raw SQL, React context + ky interceptor (frontend).

---

## File Structure

### New Files
- `src/easm/auth/__init__.py` — Package init (empty)
- `src/easm/auth/config.py` — AuthConfig + nested Pydantic models
- `src/easm/auth/password.py` — Password hashing helpers (passlib)
- `src/easm/auth/session.py` — JWT session token create/decode
- `src/easm/auth/api_keys.py` — API key generation + hash utilities
- `src/easm/auth/middleware.py` — Auth middleware (mode dispatch)
- `src/easm/auth/sso.py` — SSO provider factory + handlers
- `src/easm/api/routes/auth.py` — Auth endpoints (login, logout, register, me, api-keys, sso)
- `alembic/versions/0014_auth_tables.py` — Users + api_keys migration
- `tests/test_auth_config.py` — Auth config model tests
- `tests/test_auth_password.py` — Password hashing tests
- `tests/test_auth_session.py` — JWT session tests
- `tests/test_auth_api_keys.py` — API key utility + endpoint tests
- `tests/test_auth_middleware.py` — Middleware integration tests
- `tests/test_auth_routes.py` — Auth route tests
- `ui/src/api/auth.ts` — Frontend auth API client
- `ui/src/components/auth/LoginPage.tsx` — Login page component
- `ui/src/components/auth/RegisterPage.tsx` — Registration page component
- `ui/src/hooks/useAuth.tsx` — Auth state context + hook

### Modified Files
- `pyproject.toml` — Add PyJWT, passlib[bcrypt], fastapi-sso
- `src/easm/config.py` — Add `auth` field to `Config` model
- `src/easm/store.py` — Add user and API key query methods
- `src/easm/api/deps.py` — Add `get_current_user`, `set_auth_config`, `get_auth_config`
- `src/easm/api/app.py` — Register auth middleware + auth router
- `src/easm/main.py` — Wire auth config at startup
- `config.yaml.example` — Add `auth` section
- `.env.example` — Add `EASM_SESSION_SECRET`
- `ui/src/api/client.ts` — Add 401 interceptor
- `ui/src/App.tsx` — Add login/register routes + auth guard

---

## Phase 1: Foundation (Config, Database, Utilities)

### Task 1: Add Python Dependencies

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Add auth dependencies to pyproject.toml**

Add these three packages to the `dependencies` list in `pyproject.toml` (after `"openpyxl>=3.1.0"`):

```toml
    "PyJWT>=2.9.0",
    "passlib[bcrypt]>=1.7.4",
    "fastapi-sso>=0.16.0",
```

- [ ] **Step 2: Install dependencies**

Run: `pip install -e ".[dev]"`
Expected: All three packages install successfully.

- [ ] **Step 3: Verify imports**

Run: `python -c "import jwt; import passlib; import fastapi_sso; print('OK')"`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml
git commit -m "feat(auth): add PyJWT, passlib, fastapi-sso dependencies"
```

---

### Task 2: Auth Config Models

**Files:**
- Create: `src/easm/auth/__init__.py`
- Create: `src/easm/auth/config.py`
- Create: `tests/test_auth_config.py`

- [ ] **Step 1: Write failing tests for auth config**

Create `tests/test_auth_config.py`:

```python
from __future__ import annotations

import pytest

from easm.auth.config import (
    ApiKeyConfig,
    AuthConfig,
    LocalAuthConfig,
    ReverseProxyAuthConfig,
    SSOProviderConfig,
)


def test_default_auth_mode_is_none():
    cfg = AuthConfig()
    assert cfg.mode == "none"


def test_default_api_keys_enabled():
    cfg = AuthConfig()
    assert cfg.api_keys.enabled is True
    assert cfg.api_keys.header_name == "X-API-Key"


def test_reverse_proxy_config():
    cfg = AuthConfig(
        mode="reverse_proxy",
        reverse_proxy=ReverseProxyAuthConfig(
            header="X-Auth-Request-User",
            trusted_proxies=["10.0.0.0/8", "172.16.0.0/12"],
        ),
    )
    assert cfg.mode == "reverse_proxy"
    assert cfg.reverse_proxy.header == "X-Auth-Request-User"
    assert cfg.reverse_proxy.trusted_proxies == ["10.0.0.0/8", "172.16.0.0/12"]


def test_local_auth_config():
    cfg = AuthConfig(
        mode="local",
        local=LocalAuthConfig(
            session_secret="super-secret-key-at-least-32-chars",
            session_max_age_seconds=3600,
        ),
    )
    assert cfg.local.session_secret == "super-secret-key-at-least-32-chars"
    assert cfg.local.session_max_age_seconds == 3600


def test_sso_config():
    cfg = AuthConfig(
        mode="sso",
        sso=SSOProviderConfig(
            provider="google",
            client_id="abc123",
            client_secret="secret",
        ),
    )
    assert cfg.sso.provider == "google"
    assert cfg.sso.client_id == "abc123"


def test_invalid_mode_rejected():
    with pytest.raises(Exception):
        AuthConfig(mode="invalid")


def test_local_mode_without_local_config():
    """Local mode should work if config is provided."""
    cfg = AuthConfig(
        mode="local",
        local=LocalAuthConfig(session_secret="a" * 32),
    )
    assert cfg.mode == "local"


def test_api_key_custom_header():
    cfg = AuthConfig(
        api_keys=ApiKeyConfig(header_name="Authorization"),
    )
    assert cfg.api_keys.header_name == "Authorization"


def test_local_mode_without_session_secret_rejected():
    """Local mode requires session_secret."""
    with pytest.raises(Exception):
        AuthConfig(mode="local")


def test_sso_mode_without_any_session_secret_rejected():
    """SSO mode requires session_secret via sso or local config."""
    with pytest.raises(Exception):
        AuthConfig(
            mode="sso",
            sso=SSOProviderConfig(
                provider="google",
                client_id="abc",
                client_secret="secret",
            ),
        )


def test_sso_mode_with_sso_session_secret():
    cfg = AuthConfig(
        mode="sso",
        sso=SSOProviderConfig(
            provider="google",
            client_id="abc",
            client_secret="secret",
            session_secret="sso-secret-at-least-32-characters!!",
        ),
    )
    assert cfg.mode == "sso"


def test_reverse_proxy_auto_provision_defaults():
    cfg = ReverseProxyAuthConfig()
    assert cfg.auto_provision is False
    assert cfg.auto_provision_role == "viewer"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_auth_config.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'easm.auth'`

- [ ] **Step 3: Create auth package and config module**

Create `src/easm/auth/__init__.py` (empty file):

```python
```

Create `src/easm/auth/config.py`:

```python
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator


class ReverseProxyAuthConfig(BaseModel):
    header: str = "X-Forwarded-User"
    trusted_proxies: list[str] = Field(default_factory=list)
    auto_provision: bool = False
    auto_provision_role: str = "viewer"


class LocalAuthConfig(BaseModel):
    session_secret: str
    session_max_age_seconds: int = 86400
    cookie_name: str = "easm_session"
    cookie_secure: bool = True


class SSOProviderConfig(BaseModel):
    provider: Literal["google", "github", "microsoft", "okta"]
    client_id: str
    client_secret: str
    redirect_uri: str | None = None
    session_secret: str | None = None


class ApiKeyConfig(BaseModel):
    enabled: bool = True
    header_name: str = "X-API-Key"


class AuthConfig(BaseModel):
    mode: Literal["none", "reverse_proxy", "local", "sso"] = "none"
    reverse_proxy: ReverseProxyAuthConfig | None = None
    local: LocalAuthConfig | None = None
    sso: SSOProviderConfig | None = None
    api_keys: ApiKeyConfig = Field(default_factory=ApiKeyConfig)

    @model_validator(mode="after")
    def validate_session_secret_for_mode(self) -> AuthConfig:
        if self.mode == "local" and (
            self.local is None or not self.local.session_secret
        ):
            raise ValueError("local mode requires auth.local.session_secret")
        if self.mode == "sso":
            has_sso_secret = self.sso and self.sso.session_secret
            has_local_secret = self.local and self.local.session_secret
            if not has_sso_secret and not has_local_secret:
                raise ValueError(
                    "sso mode requires auth.sso.session_secret or auth.local.session_secret"
                )
        return self
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_auth_config.py -v`
Expected: All 12 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/easm/auth/__init__.py src/easm/auth/config.py tests/test_auth_config.py
git commit -m "feat(auth): add AuthConfig models with four modes"
```

---

### Task 3: Integrate Auth Config into Main Config

**Files:**
- Modify: `src/easm/config.py`
- Modify: `config.yaml.example`
- Modify: `.env.example`

- [ ] **Step 1: Add auth field to Config model**

In `src/easm/config.py`, add the import near the top (after the existing imports):

```python
from easm.auth.config import AuthConfig
```

Add the `auth` field to the `Config` class (after the `notifications` field, around line 274):

```python
    auth: AuthConfig = Field(default_factory=AuthConfig)
```

- [ ] **Step 2: Verify config loads with defaults**

Run: `python -c "from easm.config import Config; c = Config.model_validate({'targets': []}); print(c.auth.mode)"`
Expected: `none`

- [ ] **Step 3: Update config.yaml.example**

Append this block at the end of `config.yaml.example`:

```yaml

# Authentication configuration
# auth:
#   mode: none  # none | reverse_proxy | local | sso
#
#   # API key authentication (works in any mode)
#   api_keys:
#     enabled: true
#     header_name: X-API-Key
#
#   # Reverse proxy mode: trust header from trusted proxy IPs
#   # reverse_proxy:
#   #   header: X-Forwarded-User
#   #   trusted_proxies:
#   #     - 10.0.0.0/8
#   #     - 172.16.0.0/12
#   #   auto_provision: false  # Create users from header on first request
#   #   auto_provision_role: viewer
#
#   # Local mode: username/password with JWT sessions
#   # local:
#   #   session_secret: ${EASM_SESSION_SECRET}
#   #   session_max_age_seconds: 86400
#   #   cookie_name: easm_session
#   #   cookie_secure: true  # Set false only in development without HTTPS
#
#   # SSO mode: OAuth2 via external provider
#   # sso:
#   #   provider: google  # google | github | microsoft | okta
#   #   client_id: your-client-id
#   #   client_secret: your-client-secret
#   #   redirect_uri: https://your-domain/api/auth/sso/callback
#   #   session_secret: ${EASM_SESSION_SECRET}  # Required if auth.local not set
```

- [ ] **Step 4: Update .env.example**

Append this line to `.env.example`:

```
# EASM_SESSION_SECRET=change-me-to-a-long-random-string  # Required for local and sso auth modes
# EASM_API_KEY_PEPPER=change-me-to-a-random-string       # Server-side pepper for API key hashing
```

- [ ] **Step 5: Commit**

```bash
git add src/easm/config.py config.yaml.example .env.example
git commit -m "feat(auth): integrate AuthConfig into main Config model"
```

---

### Task 4: Database Migration — Users and API Keys Tables

**Files:**
- Create: `alembic/versions/0014_auth_tables.py`

- [ ] **Step 1: Create migration file**

Create `alembic/versions/0014_auth_tables.py`:

```python
"""add users and api_keys tables

Revision ID: 0014
Revises: 0013
Create Date: 2026-05-22

"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0014"
down_revision: str | Sequence[str] | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", sa.Text(), nullable=False, server_default="default"),
        sa.Column("username", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=True),
        sa.Column("email", sa.Text(), nullable=True),
        sa.Column("password_hash", sa.Text(), nullable=True),
        sa.Column("role", sa.Text(), nullable=False, server_default="admin"),
        sa.Column("sso_provider", sa.Text(), nullable=True),
        sa.Column("sso_provider_id", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["org_id"], ["organizations(id)"]),
        sa.UniqueConstraint("org_id", "username", name="uq_users_org_username"),
        sa.CheckConstraint(
            "role IN ('admin', 'viewer')",
            name="ck_users_role",
        ),
    )
    op.create_index("idx_users_org_id", "users", ["org_id"])
    op.create_index("idx_users_sso", "users", ["sso_provider", "sso_provider_id"], unique=True)

    op.create_table(
        "api_keys",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users(id)", ondelete="CASCADE"), nullable=False),
        sa.Column("org_id", sa.Text(), nullable=False, server_default="default"),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("key_prefix", sa.Text(), nullable=False),
        sa.Column("key_hash", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("idx_api_keys_user_id", "api_keys", ["user_id"])
    op.create_index("idx_api_keys_key_hash", "api_keys", ["key_hash"])
    op.create_index(
        "idx_api_keys_expires_at",
        "api_keys",
        ["expires_at"],
        postgresql_where=sa.text("expires_at IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_table("api_keys")
    op.drop_table("users")
```

Note: The `down_revision` chain follows `0013` (domain verification). If `20260518_0002` created a branch, adjust to point to the correct parent by checking `alembic heads`.

- [ ] **Step 2: Verify migration SQL**

Run: `python -c "from alembic.config import Config; print('migration file loads OK')"`
Expected: `migration file loads OK`

If you have a test database available, run: `alembic upgrade head` to verify the migration applies cleanly.

- [ ] **Step 3: Commit**

```bash
git add alembic/versions/0014_auth_tables.py
git commit -m "feat(auth): add users and api_keys table migration"
```

---

### Task 5: Store Methods — User CRUD

**Files:**
- Modify: `src/easm/store.py`
- Create: `tests/test_auth_store.py`

- [ ] **Step 1: Write failing tests for user store methods**

Create `tests/test_auth_store.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_auth_store.py -v -m db`
Expected: FAIL — `AttributeError: 'Store' object has no attribute 'create_user'`

- [ ] **Step 3: Add user store methods**

Append these methods to the `Store` class in `src/easm/store.py`:

```python
    # ── User methods ──────────────────────────────────────────────

    async def user_count(self) -> int:
        return await self.pool.fetchval("SELECT COUNT(*) FROM users")

    async def is_first_user(self) -> bool:
        """Atomically check if no users exist. Use inside a transaction for bootstrap."""
        return await self.pool.fetchval("SELECT COUNT(*) = 0 FROM users")

    async def create_user(
        self,
        *,
        org_id: str = "default",
        username: str,
        email: str | None = None,
        display_name: str | None = None,
        password_hash: str | None = None,
        role: str = "admin",
        sso_provider: str | None = None,
        sso_provider_id: str | None = None,
    ) -> dict:
        row = await self.pool.fetchrow(
            """
            INSERT INTO users (org_id, username, email, display_name, password_hash, role, sso_provider, sso_provider_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            """,
            org_id,
            username,
            email,
            display_name,
            password_hash,
            role,
            sso_provider,
            sso_provider_id,
        )
        return dict(row)

    async def get_user_by_username(self, org_id: str, username: str) -> dict | None:
        row = await self.pool.fetchrow(
            "SELECT * FROM users WHERE org_id = $1 AND username = $2 AND is_active = true",
            org_id,
            username,
        )
        return dict(row) if row else None

    async def get_user_by_id(self, user_id) -> dict | None:
        row = await self.pool.fetchrow(
            "SELECT * FROM users WHERE id = $1 AND is_active = true",
            user_id,
        )
        return dict(row) if row else None

    async def get_user_by_sso(self, provider: str, provider_id: str) -> dict | None:
        row = await self.pool.fetchrow(
            "SELECT * FROM users WHERE sso_provider = $1 AND sso_provider_id = $2 AND is_active = true",
            provider,
            provider_id,
        )
        return dict(row) if row else None

    async def update_user_last_seen(self, user_id) -> None:
        await self.pool.execute(
            "UPDATE users SET updated_at = NOW() WHERE id = $1",
            user_id,
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_auth_store.py -v -m db`
Expected: All 10 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/easm/store.py tests/test_auth_store.py
git commit -m "feat(auth): add user CRUD methods to Store"
```

---

### Task 6: Store Methods — API Key CRUD + Validation

**Files:**
- Modify: `src/easm/store.py`
- Modify: `tests/test_auth_store.py`

- [ ] **Step 1: Write failing tests for API key store methods**

Append to `tests/test_auth_store.py`:

```python
import hashlib
import uuid


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_auth_store.py::test_create_api_key -v -m db`
Expected: FAIL — `AttributeError: 'Store' object has no attribute 'create_api_key'`

- [ ] **Step 3: Add API key store methods**

Append to the `Store` class in `src/easm/store.py`:

```python
    # ── API key methods ───────────────────────────────────────────

    async def create_api_key(
        self,
        *,
        user_id,
        org_id: str = "default",
        name: str,
        key_prefix: str,
        key_hash: str,
        expires_at=None,
    ) -> dict:
        row = await self.pool.fetchrow(
            """
            INSERT INTO api_keys (user_id, org_id, name, key_prefix, key_hash, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            """,
            user_id,
            org_id,
            name,
            key_prefix,
            key_hash,
            expires_at,
        )
        return dict(row)

    async def validate_api_key(self, key_hash: str) -> dict | None:
        row = await self.pool.fetchrow(
            """
            SELECT ak.id AS api_key_id, ak.name AS api_key_name, ak.expires_at,
                   u.id AS user_id, u.username, u.org_id, u.role, u.is_active
            FROM api_keys ak
            JOIN users u ON u.id = ak.user_id
            WHERE ak.key_hash = $1
              AND u.is_active = true
              AND (ak.expires_at IS NULL OR ak.expires_at > NOW())
            """,
            key_hash,
        )
        if row is None:
            return None
        result = dict(row)
        # Fire-and-forget last_used_at update
        import asyncio

        async def _touch() -> None:
            try:
                await self.pool.execute(
                    "UPDATE api_keys SET last_used_at = NOW() WHERE id = $1",
                    result["api_key_id"],
                )
            except Exception:
                pass

        asyncio.create_task(_touch())
        return result

    async def list_api_keys(self, user_id) -> list[dict]:
        rows = await self.pool.fetch(
            """
            SELECT id, name, key_prefix, expires_at, last_used_at, created_at
            FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC
            """,
            user_id,
        )
        return [dict(r) for r in rows]

    async def delete_api_key(self, api_key_id, user_id) -> bool:
        result = await self.pool.execute(
            "DELETE FROM api_keys WHERE id = $1 AND user_id = $2",
            api_key_id,
            user_id,
        )
        return result == "DELETE 1"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_auth_store.py -v -m db`
Expected: All tests PASS (both user and API key tests).

- [ ] **Step 5: Commit**

```bash
git add src/easm/store.py tests/test_auth_store.py
git commit -m "feat(auth): add API key CRUD and validation to Store"
```

---

### Task 7: Password Hashing Utility

**Files:**
- Create: `src/easm/auth/password.py`
- Create: `tests/test_auth_password.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_auth_password.py`:

```python
from easm.auth.password import hash_password, verify_password


def test_hash_password_returns_bcrypt():
    hashed = hash_password("test_password")
    assert hashed.startswith("$2b$")


def test_verify_password_correct():
    hashed = hash_password("my_secret")
    assert verify_password("my_secret", hashed) is True


def test_verify_password_wrong():
    hashed = hash_password("my_secret")
    assert verify_password("wrong", hashed) is False


def test_different_hashes_for_same_password():
    h1 = hash_password("same")
    h2 = hash_password("same")
    assert h1 != h2  # bcrypt uses random salt
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_auth_password.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement password hashing**

Create `src/easm/auth/password.py`:

```python
from __future__ import annotations

from passlib.context import CryptContext

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return _pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_context.verify(plain, hashed)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_auth_password.py -v`
Expected: All 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/easm/auth/password.py tests/test_auth_password.py
git commit -m "feat(auth): add password hashing with bcrypt"
```

---

### Task 8: JWT Session Utility

**Files:**
- Create: `src/easm/auth/session.py`
- Create: `tests/test_auth_session.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_auth_session.py`:

```python
from datetime import datetime, UTC

from easm.auth.session import create_session_token, decode_session_token


def test_create_and_decode_token():
    token = create_session_token(
        user_id="abc-123",
        username="admin",
        org_id="default",
        role="admin",
        secret="test-secret-key-at-least-32-chars-long!!",
        max_age_seconds=3600,
    )
    payload = decode_session_token(token, "test-secret-key-at-least-32-chars-long!!")
    assert payload["sub"] == "abc-123"
    assert payload["username"] == "admin"
    assert payload["org_id"] == "default"
    assert payload["role"] == "admin"
    assert payload["iss"] == "open-easm"
    assert payload["aud"] == "open-easm"
    assert "exp" in payload
    assert "iat" in payload


def test_expired_token_raises():
    import jwt

    token = create_session_token(
        user_id="abc-123",
        username="admin",
        org_id="default",
        role="admin",
        secret="test-secret-key-at-least-32-chars-long!!",
        max_age_seconds=-1,
    )
    try:
        decode_session_token(token, "test-secret-key-at-least-32-chars-long!!")
        assert False, "Should have raised"
    except jwt.ExpiredSignatureError:
        pass


def test_wrong_secret_raises():
    import jwt

    token = create_session_token(
        user_id="abc-123",
        username="admin",
        org_id="default",
        role="admin",
        secret="correct-secret-key-at-least-32-chars!!",
        max_age_seconds=3600,
    )
    try:
        decode_session_token(token, "wrong-secret-key-at-least-32-chars!!")
        assert False, "Should have raised"
    except jwt.InvalidSignatureError:
        pass
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_auth_session.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement JWT session utility**

Create `src/easm/auth/session.py`:

```python
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt


def create_session_token(
    *,
    user_id: str,
    username: str,
    org_id: str,
    role: str,
    secret: str,
    max_age_seconds: int,
) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "username": username,
        "org_id": org_id,
        "role": role,
        "iss": "open-easm",
        "aud": "open-easm",
        "exp": now + timedelta(seconds=max_age_seconds),
        "iat": now,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_session_token(token: str, secret: str) -> dict:
    return jwt.decode(token, secret, algorithms=["HS256"], audience="open-easm", issuer="open-easm")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_auth_session.py -v`
Expected: All 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/easm/auth/session.py tests/test_auth_session.py
git commit -m "feat(auth): add JWT session token create/decode"
```

---

### Task 9: API Key Generation Utility

**Files:**
- Create: `src/easm/auth/api_keys.py`
- Create: `tests/test_auth_api_keys.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_auth_api_keys.py`:

```python
from easm.auth.api_keys import generate_api_key, hash_api_key, verify_api_key, _get_pepper


def test_generate_api_key_format():
    raw, prefix, key_hash = generate_api_key()
    assert raw.startswith("easm_")
    assert len(raw) > 40
    assert prefix == raw[:12]
    assert len(key_hash) == 64  # HMAC-SHA256 hex


def test_generate_api_key_unique():
    r1, _, h1 = generate_api_key()
    r2, _, h2 = generate_api_key()
    assert r1 != r2
    assert h1 != h2


def test_hash_api_key_deterministic():
    raw = "easm_testkey1234567890abcdef"
    h1 = hash_api_key(raw)
    h2 = hash_api_key(raw)
    assert h1 == h2
    assert len(h1) == 64


def test_verify_api_key_against_hash():
    raw, _, key_hash = generate_api_key()
    assert verify_api_key(raw, key_hash) is True
    assert verify_api_key("easm_wrongkey", key_hash) is False


def test_pepper_makes_hash_opaque():
    """Without the pepper, raw SHA-256 would not match our hash."""
    import hashlib

    raw, _, key_hash = generate_api_key()
    plain_sha = hashlib.sha256(raw.encode()).hexdigest()
    assert plain_sha != key_hash
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_auth_api_keys.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement API key utility**

Create `src/easm/auth/api_keys.py`:

```python
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets

logger = logging.getLogger(__name__)

# Server-side pepper loaded from environment. If not set, a random pepper
# is generated per process — keys hashed in one process won't validate in
# another. Set EASM_API_KEY_PEPPER in production for stable hashing.
_pepper: bytes | None = None


def _get_pepper() -> bytes:
    global _pepper
    if _pepper is None:
        env = os.environ.get("EASM_API_KEY_PEPPER")
        if env:
            _pepper = env.encode()
        else:
            _pepper = secrets.token_bytes(32)
            logger.warning(
                "EASM_API_KEY_PEPPER not set — using ephemeral pepper. "
                "All API keys will be invalidated on restart. "
                "Set EASM_API_KEY_PEPPER in production."
            )
    return _pepper


def generate_api_key() -> tuple[str, str, str]:
    """Generate a new API key. Returns (raw_key, prefix, key_hash)."""
    raw = f"easm_{secrets.token_urlsafe(32)}"
    prefix = raw[:12]
    key_hash = hash_api_key(raw)
    return raw, prefix, key_hash


def hash_api_key(raw_key: str) -> str:
    return hmac.new(_get_pepper(), raw_key.encode(), hashlib.sha256).hexdigest()


def verify_api_key(raw_key: str, key_hash: str) -> bool:
    expected = hash_api_key(raw_key)
    return hmac.compare_digest(expected, key_hash)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_auth_api_keys.py -v`
Expected: All 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/easm/auth/api_keys.py tests/test_auth_api_keys.py
git commit -m "feat(auth): add API key generation and hashing utilities"
```

---

## Phase 2: Middleware & API Routes

### Task 10: Auth Middleware

**Files:**
- Create: `src/easm/auth/middleware.py`
- Create: `tests/test_auth_middleware.py`

- [ ] **Step 1: Write failing tests for middleware**

Create `tests/test_auth_middleware.py`:

```python
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
def auth_none_config():
    return AuthConfig(mode="none")


def _make_app():
    return create_app()


@pytest.mark.asyncio
async def test_none_mode_passes_through(db_pool):
    """In 'none' mode, requests pass through without auth."""
    app = _make_app()
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
    app = _make_app()
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
    app = _make_app()
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
    app = _make_app()
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
        # Request from a non-trusted IP (default test client is 127.0.0.1)
        resp = await client.get("/api/targets", headers={"X-Forwarded-User": "admin"})
        assert resp.status_code == 401
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_auth_middleware.py -v`
Expected: FAIL — `ImportError: cannot import name 'set_auth_config'`

- [ ] **Step 3: Add auth config to deps.py**

Add to `src/easm/api/deps.py`:

```python
if TYPE_CHECKING:
    from easm.auth.config import AuthConfig
    from easm.config import Config
    from easm.scheduler import Scheduler
    from easm.store import Store

_auth_config: AuthConfig | None = None


def set_auth_config(auth_config: AuthConfig) -> None:
    global _auth_config
    _auth_config = auth_config


def get_auth_config() -> AuthConfig:
    if _auth_config is None:
        from easm.auth.config import AuthConfig
        return AuthConfig()
    return _auth_config
```

Remove the duplicate `if TYPE_CHECKING:` block that already existed — merge the imports into one block. The full updated file should be:

```python
from __future__ import annotations

from typing import TYPE_CHECKING

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
```

- [ ] **Step 4: Implement auth middleware**

Create `src/easm/auth/middleware.py`:

```python
from __future__ import annotations

import ipaddress
import logging

import jwt
from fastapi import Request, Response
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

# Paths exempt from authentication
EXEMPT_PATHS = {"/api/healthz", "/api/auth/login", "/api/auth/register", "/api/auth/logout"}
EXEMPT_PREFIXES = ("/ui",)


def _is_exempt(path: str) -> bool:
    if path in EXEMPT_PATHS:
        return True
    # SSO login redirect + callback are exempt
    if path.startswith("/api/auth/sso"):
        return True
    return any(path.startswith(p) for p in EXEMPT_PREFIXES)


def _is_trusted_proxy(client_ip: str, trusted_proxies: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    return any(
        addr in ipaddress.ip_network(cidr, strict=False)
        for cidr in trusted_proxies
    )


async def auth_middleware(request: Request, call_next) -> Response:
    if _is_exempt(request.url.path):
        request.state.user = None
        return await call_next(request)

    from easm.api.deps import get_auth_config, get_store

    auth_config = get_auth_config()

    # Try API key first (works in any mode)
    if auth_config.api_keys.enabled:
        raw_key = request.headers.get(auth_config.api_keys.header_name)
        if raw_key:
            from easm.auth.api_keys import hash_api_key

            key_hash = hash_api_key(raw_key)
            try:
                store = get_store()
                result = await store.validate_api_key(key_hash)
                if result:
                    request.state.user = {
                        "user_id": result["user_id"],
                        "username": result["username"],
                        "org_id": result["org_id"],
                        "role": result["role"],
                    }
                    return await call_next(request)
            except Exception:
                logger.warning("api key validation failed", exc_info=True)
            return JSONResponse(status_code=401, content={"error": "invalid_api_key"})

    # Mode-specific auth
    if auth_config.mode == "none":
        request.state.user = None
        return await call_next(request)

    if auth_config.mode == "reverse_proxy":
        return await _handle_reverse_proxy(request, call_next, auth_config)

    if auth_config.mode in ("local", "sso"):
        return await _handle_session_auth(request, call_next, auth_config)

    request.state.user = None
    return await call_next(request)


async def _handle_reverse_proxy(request: Request, call_next, auth_config) -> Response:
    cfg = auth_config.reverse_proxy
    if cfg is None:
        return JSONResponse(status_code=500, content={"error": "reverse_proxy config missing"})

    client_ip = request.client.host if request.client else "0.0.0.0"
    if not _is_trusted_proxy(client_ip, cfg.trusted_proxies):
        return JSONResponse(status_code=401, content={"error": "untrusted_proxy"})

    username = request.headers.get(cfg.header)
    if not username:
        return JSONResponse(status_code=401, content={"error": "missing_auth_header"})

    try:
        from easm.api.deps import get_store

        store = get_store()
        user = await store.get_user_by_username("default", username)
        if user is None:
            if not cfg.auto_provision:
                return JSONResponse(status_code=401, content={"error": "unknown_user"})
            # Auto-provision user from proxy header with configured role
            user = await store.create_user(
                org_id="default",
                username=username,
                role=cfg.auto_provision_role,
            )
        request.state.user = {
            "user_id": user["id"],
            "username": user["username"],
            "org_id": user["org_id"],
            "role": user["role"],
        }
    except Exception:
        logger.warning("reverse proxy user lookup failed", exc_info=True)
        return JSONResponse(status_code=500, content={"error": "user_lookup_failed"})

    return await call_next(request)


async def _handle_session_auth(request: Request, call_next, auth_config) -> Response:
    local_cfg = auth_config.local
    if local_cfg is None:
        return JSONResponse(status_code=500, content={"error": "local/sso session config missing"})

    token = request.cookies.get(local_cfg.cookie_name)
    if not token:
        return JSONResponse(status_code=401, content={"error": "no_session"})

    try:
        from easm.auth.session import decode_session_token

        payload = decode_session_token(token, local_cfg.session_secret)
        request.state.user = {
            "user_id": payload["sub"],
            "username": payload["username"],
            "org_id": payload["org_id"],
            "role": payload["role"],
        }
    except jwt.ExpiredSignatureError:
        return JSONResponse(status_code=401, content={"error": "session_expired"})
    except Exception:
        return JSONResponse(status_code=401, content={"error": "invalid_session"})

    return await call_next(request)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_auth_middleware.py -v`
Expected: All 4 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/easm/auth/middleware.py src/easm/api/deps.py tests/test_auth_middleware.py
git commit -m "feat(auth): add auth middleware with mode dispatch"
```

---

### Task 11: Wire Middleware and Auth Routes into App

**Files:**
- Modify: `src/easm/api/app.py`
- Modify: `src/easm/main.py`

- [ ] **Step 1: Add auth middleware to app.py**

In `src/easm/api/app.py`, add the middleware import near the top:

```python
from easm.auth.middleware import auth_middleware
```

Add the middleware registration inside `create_app()`, right after the CORS middleware and before the exception handler (around line 76):

```python
    app.middleware("http")(auth_middleware)
```

Also add the auth router import and registration. Add the import:

```python
from easm.api.routes import (
    auth as auth_route,
)
```

Add the router registration after the existing route registrations (around line 100, before the SPA serving block):

```python
    app.include_router(auth_route.router, prefix="/api")
```

- [ ] **Step 2: Wire auth config in main.py**

In `src/easm/main.py`, add the auth config setup after the existing `set_config(config)` call (around line 123):

```python
    from easm.api.deps import set_auth_config
    set_auth_config(config.auth)
```

- [ ] **Step 3: Verify app starts**

Run: `python -c "from easm.api.app import create_app; app = create_app(); print('OK')"`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add src/easm/api/app.py src/easm/main.py
git commit -m "feat(auth): wire auth middleware and routes into app"
```

---

### Task 12: Auth Routes — Login, Logout, Register, Me

**Files:**
- Create: `src/easm/api/routes/auth.py`
- Create: `tests/test_auth_routes.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_auth_routes.py`:

```python
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
        # First user — bootstrap
        await client.post("/api/auth/register", json={
            "username": "admin",
            "password": "securepassword123",
            "email": "admin@test.com",
        })
        # Second user — should be rejected (not authenticated)
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_auth_routes.py -v -m db`
Expected: FAIL — import error for auth route module

- [ ] **Step 3: Implement auth routes**

Create `src/easm/api/routes/auth.py`:

```python
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field

from easm.auth.password import hash_password, verify_password
from easm.auth.session import create_session_token, decode_session_token

logger = logging.getLogger(__name__)
router = APIRouter(tags=["auth"])


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)
    email: str | None = None
    display_name: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


def _set_session_cookie(
    response: Response, token: str, max_age: int, cookie_name: str, secure: bool = True,
) -> None:
    response.set_cookie(
        key=cookie_name,
        value=token,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/",
    )


def _clear_session_cookie(response: Response, cookie_name: str) -> None:
    response.delete_cookie(key=cookie_name, path="/")


def _user_response(user: dict) -> dict:
    return {
        "id": str(user["id"]),
        "username": user["username"],
        "display_name": user.get("display_name"),
        "email": user.get("email"),
        "role": user["role"],
        "org_id": user["org_id"],
    }


@router.post("/auth/register", status_code=201)
async def register(req: RegisterRequest, request: Request) -> Any:
    from easm.api.deps import get_store

    store = get_store()

    # After bootstrap, require authenticated admin
    if not await store.is_first_user():
        user = getattr(request.state, "user", None)
        if user is None or user.get("role") != "admin":
            return Response(status_code=403, content='{"error": "registration_requires_admin"}')

    existing = await store.get_user_by_username("default", req.username)
    if existing is not None:
        return Response(status_code=409, content='{"error": "username_taken"}')

    hashed = hash_password(req.password)
    try:
        # Transactional bootstrap: prevents concurrent first-user races
        async with store.pool.acquire() as conn:
            async with conn.transaction(isolation="serializable"):
                count = await conn.fetchval("SELECT COUNT(*) FROM users")
                if count > 0:
                    # Re-check auth inside transaction — another request may have bootstrapped
                    user = getattr(request.state, "user", None)
                    if user is None or user.get("role") != "admin":
                        return Response(status_code=403, content='{"error": "registration_requires_admin"}')
                row = await conn.fetchrow(
                    """
                    INSERT INTO users (org_id, username, email, display_name, password_hash, role)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    ON CONFLICT (org_id, username) DO NOTHING
                    RETURNING *
                    """,
                    "default", req.username, req.email, req.display_name, hashed, "admin",
                )
                if row is None:
                    return Response(status_code=409, content='{"error": "username_taken"}')
                user = dict(row)
    except Exception:
        return Response(status_code=409, content='{"error": "username_taken"}')
    return _user_response(user)


@router.post("/auth/login")
async def login(req: LoginRequest, request: Request) -> Any:
    from easm.api.deps import get_auth_config, get_store

    store = get_store()
    auth_config = get_auth_config()

    if auth_config.local is None:
        return Response(status_code=400, content='{"error": "local_auth_not_configured"}')

    user = await store.get_user_by_username("default", req.username)
    if user is None or user.get("password_hash") is None:
        return Response(status_code=401, content='{"error": "invalid_credentials"}')

    if not verify_password(req.password, user["password_hash"]):
        return Response(status_code=401, content='{"error": "invalid_credentials"}')

    token = create_session_token(
        user_id=str(user["id"]),
        username=user["username"],
        org_id=user["org_id"],
        role=user["role"],
        secret=auth_config.local.session_secret,
        max_age_seconds=auth_config.local.session_max_age_seconds,
    )

    response = Response(
        status_code=200,
        content='{"message":"ok"}',
        media_type="application/json",
    )
    _set_session_cookie(
        response, token, auth_config.local.session_max_age_seconds, auth_config.local.cookie_name,
        secure=auth_config.local.cookie_secure,
    )

    # Include user info in response body
    import json
    body = _user_response(user)
    response.body = json.dumps(body).encode()
    return response


@router.post("/auth/logout")
async def logout(request: Request) -> Any:
    from easm.api.deps import get_auth_config

    auth_config = get_auth_config()
    cookie_name = auth_config.local.cookie_name if auth_config.local else "easm_session"

    response = Response(
        status_code=200,
        content='{"message":"logged_out"}',
        media_type="application/json",
    )
    _clear_session_cookie(response, cookie_name)
    return response


@router.get("/auth/me")
async def me(request: Request) -> Any:
    user = getattr(request.state, "user", None)
    if user is None:
        return Response(status_code=401, content='{"error": "not_authenticated"}')
    return user
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_auth_routes.py -v -m db`
Expected: All 7 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/easm/api/routes/auth.py tests/test_auth_routes.py
git commit -m "feat(auth): add login, logout, register, me endpoints"
```

---

### Task 13: API Key Management Routes

**Files:**
- Modify: `src/easm/api/routes/auth.py`
- Modify: `tests/test_auth_routes.py`

- [ ] **Step 1: Write failing tests for API key endpoints**

Append to `tests/test_auth_routes.py`:

```python
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
        assert "key" in body  # Raw key shown once
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
        assert all("key" not in k for k in body)  # Raw key never returned in list


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
        # Verify it's gone
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

        # Use the API key to authenticate (no session cookie needed)
        resp = await client.get("/api/auth/me", headers={"X-API-Key": raw_key})
        assert resp.status_code == 200
        assert resp.json()["username"] == "admin"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_auth_routes.py::test_create_api_key -v -m db`
Expected: FAIL — 404 (route not yet implemented)

- [ ] **Step 3: Add API key request models and routes**

Append to `src/easm/api/routes/auth.py` (before the existing route handlers):

```python
class CreateApiKeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)
```

Append the following routes to `src/easm/api/routes/auth.py` (after the `me` endpoint):

```python
@router.post("/auth/api-keys", status_code=201)
async def create_api_key(req: CreateApiKeyRequest, request: Request) -> Any:
    from easm.api.deps import get_store
    from easm.auth.api_keys import generate_api_key

    user = getattr(request.state, "user", None)
    if user is None:
        return Response(status_code=401, content='{"error": "not_authenticated"}')

    store = get_store()
    raw, prefix, key_hash = generate_api_key()

    expires_at = None
    if req.expires_in_days is not None:
        from datetime import UTC, datetime, timedelta

        expires_at = datetime.now(UTC) + timedelta(days=req.expires_in_days)

    api_key = await store.create_api_key(
        user_id=user["user_id"],
        org_id=user["org_id"],
        name=req.name,
        key_prefix=prefix,
        key_hash=key_hash,
        expires_at=expires_at,
    )
    return {
        "id": str(api_key["id"]),
        "name": api_key["name"],
        "key_prefix": api_key["key_prefix"],
        "expires_at": api_key["expires_at"].isoformat() if api_key.get("expires_at") else None,
        "created_at": api_key["created_at"].isoformat() if api_key.get("created_at") else None,
        "key": raw,  # Shown only once
    }


@router.get("/auth/api-keys")
async def list_api_keys(request: Request) -> Any:
    from easm.api.deps import get_store

    user = getattr(request.state, "user", None)
    if user is None:
        return Response(status_code=401, content='{"error": "not_authenticated"}')

    store = get_store()
    keys = await store.list_api_keys(user["user_id"])
    return [
        {
            "id": str(k["id"]),
            "name": k["name"],
            "key_prefix": k["key_prefix"],
            "expires_at": k["expires_at"].isoformat() if k.get("expires_at") else None,
            "last_used_at": k["last_used_at"].isoformat() if k.get("last_used_at") else None,
            "created_at": k["created_at"].isoformat() if k.get("created_at") else None,
        }
        for k in keys
    ]


@router.delete("/auth/api-keys/{api_key_id}", status_code=204)
async def delete_api_key(api_key_id: str, request: Request) -> Any:
    from easm.api.deps import get_store

    user = getattr(request.state, "user", None)
    if user is None:
        return Response(status_code=401, content='{"error": "not_authenticated"}')

    store = get_store()
    deleted = await store.delete_api_key(api_key_id, user["user_id"])
    if not deleted:
        return Response(status_code=404, content='{"error": "not_found"}')
    return Response(status_code=204)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_auth_routes.py -v -m db`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/easm/api/routes/auth.py tests/test_auth_routes.py
git commit -m "feat(auth): add API key create, list, delete endpoints"
```

---

### Task 14: get_current_user Dependency for Route Protection

**Files:**
- Modify: `src/easm/api/deps.py`

- [ ] **Step 1: Add get_current_user dependency**

Append to `src/easm/api/deps.py`:

```python
def get_current_user(request: Request) -> dict | None:
    return getattr(request.state, "user", None)
```

Add the import at the top:

```python
from fastapi import Request
```

The full file should now be:

```python
from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Request

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
```

- [ ] **Step 2: Verify it imports**

Run: `python -c "from easm.api.deps import get_current_user; print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add src/easm/api/deps.py
git commit -m "feat(auth): add get_current_user FastAPI dependency"
```

---

## Phase 3: SSO Integration

### Task 15: SSO Provider Integration

**Files:**
- Create: `src/easm/auth/sso.py`
- Modify: `src/easm/api/routes/auth.py`

- [ ] **Step 1: Create SSO provider factory**

Create `src/easm/auth/sso.py`:

```python
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from easm.auth.config import SSOProviderConfig


def get_sso_provider(config: SSOProviderConfig):
    """Return an initialized fastapi-sso SSO instance for the configured provider."""
    redirect_uri = config.redirect_uri

    if config.provider == "google":
        from fastapi_sso.sso.google import GoogleSSO

        return GoogleSSO(
            client_id=config.client_id,
            client_secret=config.client_secret,
            redirect_uri=redirect_uri or "http://localhost:8000/api/auth/sso/google/callback",
        )
    elif config.provider == "github":
        from fastapi_sso.sso.github import GithubSSO

        return GithubSSO(
            client_id=config.client_id,
            client_secret=config.client_secret,
            redirect_uri=redirect_uri or "http://localhost:8000/api/auth/sso/github/callback",
        )
    elif config.provider == "microsoft":
        from fastapi_sso.sso.microsoft import MicrosoftSSO

        return MicrosoftSSO(
            client_id=config.client_id,
            client_secret=config.client_secret,
            redirect_uri=redirect_uri or "http://localhost:8000/api/auth/sso/microsoft/callback",
        )
    else:
        raise ValueError(f"Unsupported SSO provider: {config.provider}")
```

- [ ] **Step 2: Add SSO routes to auth.py**

Append to `src/easm/api/routes/auth.py`:

```python
@router.get("/auth/sso/{provider}")
async def sso_login(provider: str, request: Request) -> Any:
    from easm.api.deps import get_auth_config
    from easm.auth.sso import get_sso_provider

    auth_config = get_auth_config()
    if auth_config.sso is None or auth_config.sso.provider != provider:
        return Response(status_code=404, content='{"error": "sso_not_configured"}')

    sso = get_sso_provider(auth_config.sso)
    async with sso:
        return await sso.get_login_redirect()


@router.get("/auth/sso/{provider}/callback")
async def sso_callback(provider: str, request: Request) -> Any:
    from easm.api.deps import get_auth_config, get_store
    from easm.auth.sso import get_sso_provider

    auth_config = get_auth_config()
    if auth_config.sso is None or auth_config.sso.provider != provider:
        return Response(status_code=404, content='{"error": "sso_not_configured"}')

    sso = get_sso_provider(auth_config.sso)
    async with sso:
        sso_user = await sso.verify_and_process(request)

    if sso_user is None:
        return Response(status_code=401, content='{"error": "sso_verification_failed"}')

    store = get_store()
    provider_id = str(sso_user.id) if sso_user.id else ""

    # Find or create user
    user = await store.get_user_by_sso(provider, provider_id)
    if user is None:
        import re

        raw_name = sso_user.display_name or sso_user.email or f"{provider}_user"
        username = re.sub(r"[^a-zA-Z0-9_-]", "_", raw_name)[:64]
        # Ensure username is unique
        existing = await store.get_user_by_username("default", username)
        if existing is not None:
            username = f"{username}_{provider_id[:8]}"
        user = await store.create_user(
            org_id="default",
            username=username,
            email=sso_user.email,
            display_name=sso_user.display_name,
            role="admin",
            sso_provider=provider,
            sso_provider_id=provider_id,
        )

    # Resolve session config: prefer auth.local, fall back to sso.session_secret
    local_cfg = auth_config.local
    if local_cfg is None:
        local_cfg = LocalAuthConfig(
            session_secret=auth_config.sso.session_secret,  # type: ignore[arg-type]
            session_max_age_seconds=86400,
        )

    token = create_session_token(
        user_id=str(user["id"]),
        username=user["username"],
        org_id=user["org_id"],
        role=user["role"],
        secret=local_cfg.session_secret,
        max_age_seconds=local_cfg.session_max_age_seconds,
    )

    import json
    response = Response(
        status_code=200,
        content=json.dumps(_user_response(user)).encode(),
        media_type="application/json",
    )
    _set_session_cookie(
        response, token, local_cfg.session_max_age_seconds, local_cfg.cookie_name,
        secure=local_cfg.cookie_secure,
    )
    return response
```

Note: The SSO routes are already exempt in the middleware via the `_is_exempt` check for `path.startswith("/api/auth/sso")`.

- [ ] **Step 3: Verify imports**

Run: `python -c "from easm.auth.sso import get_sso_provider; print('OK')"`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add src/easm/auth/sso.py src/easm/api/routes/auth.py
git commit -m "feat(auth): add SSO provider factory and callback routes"
```

---

## Phase 4: Frontend

### Task 16: Frontend Auth API Client

**Files:**
- Create: `ui/src/api/auth.ts`

- [ ] **Step 1: Create auth API module**

Create `ui/src/api/auth.ts`:

```typescript
import api from "./client";

export interface User {
  id: string;
  username: string;
  display_name: string | null;
  email: string | null;
  role: string;
  org_id: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface RegisterRequest {
  username: string;
  password: string;
  email?: string;
  display_name?: string;
}

export interface CreateApiKeyRequest {
  name: string;
  expires_in_days?: number;
}

export interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  expires_at: string | null;
  last_used_at: string | null;
  created_at: string;
}

export interface ApiKeyWithSecret extends ApiKey {
  key: string;
}

export const authApi = {
  login: (data: LoginRequest) =>
    api.post("auth/login", { json: data }).json<User>(),

  logout: () => api.post("auth/logout"),

  register: (data: RegisterRequest) =>
    api.post("auth/register", { json: data }).json<User>(),

  me: () => api.get("auth/me").json<User>(),

  listApiKeys: () => api.get("auth/api-keys").json<ApiKey[]>(),

  createApiKey: (data: CreateApiKeyRequest) =>
    api.post("auth/api-keys", { json: data }).json<ApiKeyWithSecret>(),

  deleteApiKey: (id: string) => api.delete(`auth/api-keys/${id}`),
};
```

- [ ] **Step 2: Commit**

```bash
git add ui/src/api/auth.ts
git commit -m "feat(ui): add auth API client module"
```

---

### Task 17: Frontend Auth Context and Hook

**Files:**
- Create: `ui/src/hooks/useAuth.tsx`

- [ ] **Step 1: Create auth context and hook**

Create `ui/src/hooks/useAuth.tsx`:

```tsx
import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from "react";
import { authApi, type User } from "../api/auth";

interface AuthState {
  user: User | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const me = await authApi.me();
      setUser(me);
    } catch {
      setUser(null);
    }
  }, []);

  useEffect(() => {
    refresh().finally(() => setLoading(false));
  }, [refresh]);

  const login = async (username: string, password: string) => {
    const result = await authApi.login({ username, password });
    setUser(result);
  };

  const logout = async () => {
    await authApi.logout();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, refresh }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
```

- [ ] **Step 2: Commit**

```bash
git add ui/src/hooks/useAuth.tsx
git commit -m "feat(ui): add AuthProvider context and useAuth hook"
```

---

### Task 18: Frontend API Client 401 Interceptor

**Files:**
- Modify: `ui/src/api/client.ts`

- [ ] **Step 1: Add 401 response interceptor**

Replace `ui/src/api/client.ts` with:

```typescript
import ky from "ky";

const api = ky.create({
  prefix: "/api",
  headers: { Accept: "application/json" },
  timeout: 30_000,
  hooks: {
    afterResponse: [
      (request, _options, response) => {
        if (response.status === 401) {
          // Don't redirect on auth endpoint 401s (wrong password, etc.)
          const url = new URL(request.url);
          if (url.pathname.startsWith("/api/auth/")) {
            return;
          }
          const currentPath = window.location.pathname;
          if (!currentPath.startsWith("/ui/login") && !currentPath.startsWith("/ui/register")) {
            window.location.href = "/ui/login";
          }
        }
      },
    ],
  },
});

export default api;
```

- [ ] **Step 2: Commit**

```bash
git add ui/src/api/client.ts
git commit -m "feat(ui): add 401 redirect interceptor to API client"
```

---

### Task 19: Frontend Login and Register Pages

**Files:**
- Create: `ui/src/components/auth/LoginPage.tsx`
- Create: `ui/src/components/auth/RegisterPage.tsx`

- [ ] **Step 1: Create login page**

Create `ui/src/components/auth/LoginPage.tsx`:

```tsx
import { useState, type FormEvent } from "react";
import { useNavigate, Link } from "react-router";
import { useAuth } from "../../hooks/useAuth";

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      await login(username, password);
      navigate("/ui");
    } catch {
      setError("Invalid username or password");
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-canvas">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm p-8 bg-surface rounded-lg border border-border shadow-lg"
      >
        <h1 className="text-2xl font-bold mb-6 text-center">Sign In</h1>
        {error && (
          <div className="mb-4 p-3 bg-red-50 text-red-700 rounded text-sm">{error}</div>
        )}
        <div className="mb-4">
          <label className="block text-sm font-medium mb-1">Username</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full px-3 py-2 border border-border rounded bg-canvas"
            required
            autoFocus
          />
        </div>
        <div className="mb-6">
          <label className="block text-sm font-medium mb-1">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-3 py-2 border border-border rounded bg-canvas"
            required
          />
        </div>
        <button
          type="submit"
          className="w-full py-2 px-4 bg-primary text-white rounded font-medium hover:opacity-90"
        >
          Sign In
        </button>
        <p className="mt-4 text-center text-sm text-muted">
          No account?{" "}
          <Link to="/ui/register" className="text-primary underline">
            Register
          </Link>
        </p>
      </form>
    </div>
  );
}
```

- [ ] **Step 2: Create register page**

Create `ui/src/components/auth/RegisterPage.tsx`:

```tsx
import { useState, type FormEvent } from "react";
import { useNavigate, Link } from "react-router";
import { authApi } from "../../api/auth";

export function RegisterPage() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    if (password !== confirm) {
      setError("Passwords do not match");
      return;
    }
    try {
      await authApi.register({ username, password });
      navigate("/ui/login");
    } catch (err: any) {
      if (err?.response?.status === 409) {
        setError("Username already taken");
      } else if (err?.response?.status === 403) {
        setError("Registration is closed. Contact an administrator.");
      } else {
        setError("Registration failed. Please try again.");
      }
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-canvas">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm p-8 bg-surface rounded-lg border border-border shadow-lg"
      >
        <h1 className="text-2xl font-bold mb-6 text-center">Create Account</h1>
        {error && (
          <div className="mb-4 p-3 bg-red-50 text-red-700 rounded text-sm">{error}</div>
        )}
        <div className="mb-4">
          <label className="block text-sm font-medium mb-1">Username</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full px-3 py-2 border border-border rounded bg-canvas"
            required
            minLength={3}
            autoFocus
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm font-medium mb-1">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-3 py-2 border border-border rounded bg-canvas"
            required
            minLength={8}
          />
        </div>
        <div className="mb-6">
          <label className="block text-sm font-medium mb-1">Confirm Password</label>
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            className="w-full px-3 py-2 border border-border rounded bg-canvas"
            required
            minLength={8}
          />
        </div>
        <button
          type="submit"
          className="w-full py-2 px-4 bg-primary text-white rounded font-medium hover:opacity-90"
        >
          Create Account
        </button>
        <p className="mt-4 text-center text-sm text-muted">
          Already have an account?{" "}
          <Link to="/ui/login" className="text-primary underline">
            Sign In
          </Link>
        </p>
      </form>
    </div>
  );
}
```

- [ ] **Step 3: Commit**

```bash
git add ui/src/components/auth/LoginPage.tsx ui/src/components/auth/RegisterPage.tsx
git commit -m "feat(ui): add login and register page components"
```

---

### Task 20: Frontend Routing with Auth Guard

**Files:**
- Modify: `ui/src/main.tsx`
- Modify: `ui/src/App.tsx`

- [ ] **Step 1: Wrap app with AuthProvider**

In `ui/src/main.tsx`, wrap the app with `AuthProvider`:

```tsx
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router";
import { AuthProvider } from "./hooks/useAuth";
import { App } from "./App";
import "./index.css";

const queryClient = new QueryClient();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter basename="/ui">
        <AuthProvider>
          <App />
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
```

- [ ] **Step 2: Add auth guard to App.tsx**

Replace `ui/src/App.tsx`:

```tsx
import { Routes, Route, Navigate } from "react-router";
import { AppShell } from "./components/layout/AppShell";
import { DashboardView } from "./components/dashboard/DashboardView";
import { AssetInventoryView } from "./components/assets/AssetInventoryView";
import { InventoryView } from "./components/inventory/InventoryView";
import { CertificateInventoryView } from "./components/certificates/CertificateInventoryView";
import { GraphView } from "./components/graph/GraphView";
import { RunsView } from "./components/runs/RunsView";
import { TargetsView } from "./components/targets/TargetsView";
import { ConfigEditorView } from "./components/config/ConfigEditorView";
import { AlertsView } from "./components/alerts/AlertsView";
import { FindingsView } from "./components/findings/FindingsView";
import { GeoMap } from "./components/GeoMap";
import { NotificationSettings } from "./components/settings/NotificationSettings";
import { LoginPage } from "./components/auth/LoginPage";
import { RegisterPage } from "./components/auth/RegisterPage";
import { useAuth } from "./hooks/useAuth";

function ProtectedRoutes() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-canvas">
        <div className="text-muted">Loading...</div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<DashboardView />} />
        <Route path="assets" element={<AssetInventoryView />} />
        <Route path="inventory" element={<InventoryView />} />
        <Route path="certificates" element={<CertificateInventoryView />} />
        <Route path="graph" element={<GraphView />} />
        <Route path="runs" element={<RunsView />} />
        <Route path="targets" element={<TargetsView />} />
        <Route path="config" element={<ConfigEditorView />} />
        <Route path="alerts" element={<AlertsView />} />
        <Route path="findings" element={<FindingsView />} />
        <Route path="notifications" element={<NotificationSettings />} />
        <Route path="geo" element={<GeoMap />} />
      </Route>
    </Routes>
  );
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/*" element={<ProtectedRoutes />} />
    </Routes>
  );
}
```

- [ ] **Step 3: Verify frontend builds**

Run: `cd ui && npx tsc --noEmit`
Expected: No type errors.

- [ ] **Step 4: Commit**

```bash
git add ui/src/main.tsx ui/src/App.tsx
git commit -m "feat(ui): add auth guard, login/register routes, AuthProvider"
```

---

## Self-Review Checklist

### 1. Spec Coverage

| Requirement | Task |
|---|---|
| No auth (current model) | Task 10 (`mode="none"`) |
| Reverse proxy (trust header) | Task 10 (`_handle_reverse_proxy`) |
| Trusted proxy IP validation | Task 10 (`_is_trusted_proxy`) |
| Reverse proxy auto-provision (opt-in) | Task 2 (`auto_provision`, `auto_provision_role`) |
| Local username/password | Tasks 7, 12 (login/register) |
| SSO via fastapi-sso | Task 15 |
| API key creation | Task 13 (`POST /auth/api-keys`) |
| API key provisioning (generation) | Task 9, 13 (`generate_api_key`) |
| API key expiration | Task 6 (`expires_at`), Task 13 (`expires_in_days`) |
| API key deletion | Task 13 (`DELETE /auth/api-keys/{id}`) |
| API key validation | Task 6 (`validate_api_key`), Task 10 (middleware) |
| Forward-thinking: org_id on users | Task 4 (migration) |
| Forward-thinking: org_id on api_keys | Task 4 (migration) |
| Forward-thinking: role CHECK constraint | Task 4 (migration) |
| Forward-thinking: role on users | Task 4 (migration) |
| Frontend login page | Task 19 |
| Frontend auth state | Task 17 |
| Frontend 401 handling | Task 18 |
| Frontend route protection | Task 20 |

### 2. Security Audit Addressed

| # | Finding | Resolution |
|---|---|---|
| 1 | `secure=False` hardcoded | `cookie_secure: bool = True` in `LocalAuthConfig`, passed to `_set_session_cookie` |
| 2 | Reverse proxy auto-provision grants admin | `auto_provision: bool = False`, `auto_provision_role: str = "viewer"` in config |
| 3 | SSO session secret falls back to client_secret | `session_secret` on `SSOProviderConfig`, startup validator requires it |
| 4 | No rate limiting on login/register | Out of scope for v1 (self-hosted tool); recommend adding slowapi in v2 |
| 5 | SameSite=Lax CSRF risk | Changed to `samesite="strict"` |
| 6 | SHA-256 for API keys | HMAC-SHA256 with server-side pepper (`EASM_API_KEY_PEPPER`) |
| 7 | Registration TOCTOU race | `is_first_user()` + try/except on unique constraint violation |
| 8 | Missing JWT iss/aud claims | Added `iss="open-easm"`, `aud="open-easm"` with decode validation |
| 9 | SSO mode doesn't validate session secret | `model_validator` on `AuthConfig` raises at startup |
| 10 | Existing routes not guarded in none mode | By design — `mode=none` is the default. Document as security boundary. |
| 11 | `last_used_at` update misleading label | Changed to `asyncio.create_task()` for true fire-and-forget |
| 12 | SSO display_name unsanitized | `re.sub(r"[^a-zA-Z0-9_-]", "_", raw_name)` before persisting |
| 13 | Store `bool` return hides delete cause | Acceptable for v1 — both cases return 404 to client |
| 14 | Frontend 401 redirect loop | Excluded `/api/auth/*` paths from redirect |

### 3. RBAC / Multi-Tenancy Forward Compatibility

| Concern | Resolution |
|---|---|
| `org_id` on api_keys | Added `org_id TEXT NOT NULL DEFAULT 'default'` column in migration |
| Role is freeform TEXT | Added `CHECK (role IN ('admin', 'viewer'))` constraint |
| `get_current_user` returns flat dict | Acceptable for v1; recommend typed `User` Pydantic model in v2 |
| Existing domain tables lack org_id | Convention documented: all future migrations must include `org_id` |

### 4. Placeholder Scan

No `TBD`, `TODO`, `implement later`, or "add appropriate error handling" found. All steps contain complete code.

### 5. Type Consistency

- `create_user()` returns `dict` with `id`, `username`, `org_id`, `role` fields — consistent across all tasks
- `request.state.user` dict uses `user_id`, `username`, `org_id`, `role` — consistent in middleware, routes, and deps
- API key models use `name`, `key_prefix`, `key_hash`, `expires_at` — consistent across store, routes, and tests
- `generate_api_key()` returns `(raw, prefix, key_hash)` tuple — consistent across Tasks 9 and 13
- `hash_api_key()` uses HMAC-SHA256 with pepper — consistent in middleware (Task 10) and tests (Tasks 6, 9, 13)

---

**Total: 20 tasks across 4 phases.**

Phase 1 (Tasks 1-9): ~2-3 hours — Foundation: config, database, utilities
Phase 2 (Tasks 10-14): ~2-3 hours — Middleware and API routes
Phase 3 (Task 15): ~1 hour — SSO integration
Phase 4 (Tasks 16-20): ~2-3 hours — Frontend auth

**Note on `fast-api-key`:** The plan implements API key management from scratch using `secrets` + `hashlib` (standard library). The implementation is straightforward enough that an external dependency is unnecessary. The `generate_api_key()` function produces keys with the `easm_` prefix, SHA-256 hashed for storage, with configurable expiration.
