"""User, API key, and bootstrap-admin persistence.

Tables: ``users``, ``api_keys``. API keys are HMAC-SHA256 hashed with a
server-side pepper before reaching this store; only the hash is stored.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import asyncpg

from easm.stores import BaseStore

logger = logging.getLogger(__name__)


class AuthStore(BaseStore):
    """User and API key persistence."""

    async def user_count(self) -> int:
        return await self._pool.fetchval("SELECT COUNT(*) FROM users")

    async def is_first_user(self) -> bool:
        """Atomically check if no users exist. Use inside a transaction for bootstrap."""
        return await self._pool.fetchval("SELECT COUNT(*) = 0 FROM users")

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
    ) -> dict[str, Any]:
        row = await self._pool.fetchrow(
            """
            INSERT INTO users (org_id, username, email, display_name,
                               password_hash, role, sso_provider, sso_provider_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            """,
            org_id, username, email, display_name,
            password_hash, role, sso_provider, sso_provider_id,
        )
        assert row is not None
        return dict(row)

    async def get_user_by_username(self, org_id: str, username: str) -> dict[str, Any] | None:
        row = await self._pool.fetchrow(
            "SELECT * FROM users WHERE org_id = $1 AND username = $2 AND is_active = true",
            org_id, username,
        )
        return dict(row) if row else None

    async def get_user_by_id(self, user_id: Any) -> dict[str, Any] | None:
        row = await self._pool.fetchrow(
            "SELECT * FROM users WHERE id = $1 AND is_active = true",
            user_id,
        )
        return dict(row) if row else None

    async def get_user_by_sso(
        self, provider: str, provider_id: str,
    ) -> dict[str, Any] | None:
        row = await self._pool.fetchrow(
            "SELECT * FROM users WHERE sso_provider = $1 AND sso_provider_id = $2 "
            "AND is_active = true",
            provider, provider_id,
        )
        return dict(row) if row else None

    async def update_user_last_seen(self, user_id: Any) -> None:
        await self._pool.execute(
            "UPDATE users SET updated_at = NOW() WHERE id = $1",
            user_id,
        )

    async def list_users(self, org_id: str = "default") -> list[dict[str, Any]]:
        rows = await self._pool.fetch(
            "SELECT id, org_id, username, email, display_name, role, "
            "created_at, updated_at FROM users WHERE org_id = $1 ORDER BY created_at",
            org_id,
        )
        return [dict(r) for r in rows]

    async def delete_user(self, user_id: Any) -> bool:
        result = await self._pool.execute(
            "DELETE FROM users WHERE id = $1",
            user_id,
        )
        return result != "DELETE 0"

    async def update_user(
        self,
        user_id: str,
        *,
        email: str | None = None,
        display_name: str | None = None,
        password_hash: str | None = None,
    ) -> bool:
        sets: list[str] = []
        args: list[Any] = []
        idx = 1
        if email is not None:
            sets.append(f"email = ${idx}")
            args.append(email)
            idx += 1
        if display_name is not None:
            sets.append(f"display_name = ${idx}")
            args.append(display_name)
            idx += 1
        if password_hash is not None:
            sets.append(f"password_hash = ${idx}")
            args.append(password_hash)
            idx += 1
        if not sets:
            return False
        args.append(user_id)
        result = await self._pool.execute(
            f"UPDATE users SET {', '.join(sets)} WHERE id = ${idx}",
            *args,
        )
        return result != "UPDATE 0"

    # ── API keys ──────────────────────────────────────────────────────

    async def create_api_key(
        self,
        *,
        user_id: Any,
        org_id: str = "default",
        name: str,
        key_prefix: str,
        key_hash: str,
        expires_at: Any = None,
    ) -> dict[str, Any]:
        row = await self._pool.fetchrow(
            """
            INSERT INTO api_keys (user_id, org_id, name, key_prefix, key_hash, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            """,
            user_id, org_id, name, key_prefix, key_hash, expires_at,
        )
        assert row is not None
        return dict(row)

    async def validate_api_key(self, key_hash: str) -> dict[str, Any] | None:
        row = await self._pool.fetchrow(
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
        async def _touch() -> None:
            try:
                await self._pool.execute(
                    "UPDATE api_keys SET last_used_at = NOW() WHERE id = $1",
                    result["api_key_id"],
                )
            except (asyncpg.PostgresError, KeyError) as e:
                logger.debug(
                    "api key last_used_at update skipped",
                    extra={"api_key_id": str(result.get("api_key_id")), "error": str(e)},
                )

        asyncio.create_task(_touch())
        return result

    async def list_api_keys(self, user_id: Any) -> list[dict[str, Any]]:
        rows = await self._pool.fetch(
            """
            SELECT id, name, key_prefix, expires_at, last_used_at, created_at
            FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC
            """,
            user_id,
        )
        return [dict(r) for r in rows]

    async def delete_api_key(self, api_key_id: Any, user_id: Any) -> bool:
        result = await self._pool.execute(
            "DELETE FROM api_keys WHERE id = $1 AND user_id = $2",
            api_key_id, user_id,
        )
        return result == "DELETE 1"
