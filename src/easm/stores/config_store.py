"""Config snapshot persistence (``config_snapshots`` table).

Stores content-addressed (``config_hash`` → ``raw_config``) snapshots of
the YAML config file. Used by the config history endpoint and by audit
trails when config is reloaded.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

import asyncpg

from easm.stores import BaseStore


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _row_to_config_snapshot_dict(row: asyncpg.Record) -> dict[str, Any]:
    def _fmt(dt: datetime | None) -> str | None:
        return dt.isoformat() if dt else None

    raw = row["raw_config"]
    if isinstance(raw, str):
        raw = json.loads(raw)
    return {
        "config_hash": row["config_hash"],
        "raw_config": raw,
        "created_at": _fmt(row["created_at"]),
    }


class ConfigStore(BaseStore):
    """Content-addressed config snapshot persistence."""

    async def save_config_snapshot(self, raw_config: dict[str, Any]) -> None:
        raw_json = _canonical_json(raw_config)
        config_hash = hashlib.sha256(raw_json.encode()).hexdigest()
        await self._pool.execute(
            """
            INSERT INTO config_snapshots (config_hash, raw_config)
            VALUES ($1, $2::jsonb)
            ON CONFLICT (config_hash) DO NOTHING
            """,
            config_hash,
            json.dumps(raw_config),
        )

    async def list_config_history(self, limit: int = 50) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 500))
        rows = await self._pool.fetch(
            """
            SELECT config_hash, raw_config, created_at
            FROM config_snapshots
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
        )
        return [_row_to_config_snapshot_dict(row) for row in rows]

    async def get_config_snapshot(self, config_hash: str) -> dict[str, Any] | None:
        row = await self._pool.fetchrow(
            "SELECT config_hash, raw_config, created_at "
            "FROM config_snapshots WHERE config_hash = $1",
            config_hash,
        )
        if row is None:
            return None
        return _row_to_config_snapshot_dict(row)
