"""Backward-compatible store facade.

Originally a 1700+ LOC monolith, this module now delegates to per-domain
stores in :mod:`easm.stores`. The :class:`Store` class preserves the
legacy method surface so existing call sites continue to work without
modification.

Module-level helpers (``_compute_event_hash``, ``_canonical_json``) are
preserved because a handful of callers (legacy pivot worker, runner
adapters, scheduler tasks) import them directly.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

import asyncpg

from easm.stores.asset_store import AssetStore
from easm.stores.auth_store import AuthStore
from easm.stores.certificate_store import CertificateStore
from easm.stores.config_store import ConfigStore
from easm.stores.entity_store import EntityStore
from easm.stores.finding_store import FindingStore
from easm.stores.run_store import RunStore
from easm.stores.triage_store import TriageStore

if TYPE_CHECKING:
    from easm.correlation.rule import Finding

logger = logging.getLogger(__name__)


# ── Module-level helpers (kept for legacy callers) ───────────────────


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _compute_event_hash(org_id: str, target_id: str, source: str, raw: Any) -> str:
    payload = f"{org_id}:{target_id}:{source}:{_canonical_json(raw)}"
    return hashlib.sha256(payload.encode()).hexdigest()


class Store:
    """Facade over the domain stores.

    Each domain (``runs``, ``entities``, ``findings``, ``assets``,
    ``certificates``, ``auth``, ``config``, ``triage``) is implemented by
    a dedicated ``BaseStore`` subclass. ``Store`` instantiates each one
    and exposes both the sub-store attribute (``store.entities.upsert_entity``)
    and a flat delegator method (``store.upsert_entity``) for backward
    compatibility.

    Raw-event methods (``insert_raw_event``, ``list_events``, ``get_event``,
    ``count_events``) are owned here because they form a small audit-log
    surface that does not belong to any single domain store.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        self.pool = pool
        # Domain stores — new code should target these directly.
        self.runs = RunStore(pool)
        self.entities = EntityStore(pool)
        self.findings = FindingStore(pool)
        self.assets = AssetStore(pool)
        self.certificates = CertificateStore(pool)
        self.auth = AuthStore(pool)
        self.config = ConfigStore(pool)
        self.triage = TriageStore(pool)

    # ── Raw events (audit log) — owned here, not delegated ───────────

    async def insert_raw_event(
        self, org_id: str, target_id: str, source: str, raw: Any, run_id: uuid.UUID,
    ) -> uuid.UUID | None:
        """Insert a raw event. Returns the raw_event UUID on success, or ``None`` on dedup."""
        event_hash = _compute_event_hash(org_id, target_id, source, raw)
        raw_json = json.dumps(raw)
        row = await self.pool.fetchrow(
            """
            INSERT INTO raw_events (org_id, target_id, source, raw, event_hash, run_id)
            VALUES ($1, $2, $3, $4::jsonb, $5, $6)
            ON CONFLICT (event_hash) DO NOTHING
            RETURNING id
            """,
            org_id, target_id, source, raw_json, event_hash, run_id,
        )
        if row is None:
            return None
        return row["id"]

    async def list_events(
        self,
        target_id: str | None = None,
        source: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        limit = max(1, min(limit, 500))
        conditions: list[str] = []
        params: list[Any] = []
        idx = 0

        if cursor:
            idx += 1
            conditions.append(f"id < ${idx}::uuid")
            params.append(cursor)
        if target_id:
            idx += 1
            conditions.append(f"target_id = ${idx}")
            params.append(target_id)
        if source:
            idx += 1
            conditions.append(f"source = ${idx}")
            params.append(source)
        if start:
            idx += 1
            conditions.append(f"collected_at >= ${idx}")
            params.append(start)
        if end:
            idx += 1
            conditions.append(f"collected_at <= ${idx}")
            params.append(end)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        idx += 1
        query = f"""
            SELECT id, org_id, target_id, source, collected_at, raw, event_hash, run_id
            FROM raw_events
            {where}
            ORDER BY id DESC
            LIMIT ${idx}
        """
        params.append(limit + 1)

        rows = await self.pool.fetch(query, *params)
        has_more = len(rows) > limit
        results = rows[:limit]

        events = [
            {
                "id": str(r["id"]),
                "org_id": r["org_id"],
                "target_id": r["target_id"],
                "source": r["source"],
                "collected_at": r["collected_at"].isoformat(),
                "raw": json.loads(r["raw"]) if isinstance(r["raw"], str) else r["raw"],
                "event_hash": r["event_hash"],
                "run_id": str(r["run_id"]),
            }
            for r in results
        ]

        next_cursor = str(results[-1]["id"]) if has_more and results else None
        return events, next_cursor

    async def get_event(self, event_id: uuid.UUID) -> dict[str, Any] | None:
        row = await self.pool.fetchrow(
            "SELECT id, org_id, target_id, source, collected_at, raw, event_hash, run_id "
            "FROM raw_events WHERE id = $1",
            event_id,
        )
        if row is None:
            return None
        return {
            "id": str(row["id"]),
            "org_id": row["org_id"],
            "target_id": row["target_id"],
            "source": row["source"],
            "collected_at": row["collected_at"].isoformat(),
            "raw": json.loads(row["raw"]) if isinstance(row["raw"], str) else row["raw"],
            "event_hash": row["event_hash"],
            "run_id": str(row["run_id"]),
        }

    async def count_events(
        self,
        target_id: str | None = None,
        source: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> int:
        conditions: list[str] = []
        params: list[Any] = []
        idx = 0
        if target_id:
            idx += 1
            conditions.append(f"target_id = ${idx}")
            params.append(target_id)
        if source:
            idx += 1
            conditions.append(f"source = ${idx}")
            params.append(source)
        if start:
            idx += 1
            conditions.append(f"collected_at >= ${idx}")
            params.append(start)
        if end:
            idx += 1
            conditions.append(f"collected_at <= ${idx}")
            params.append(end)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        return await self.pool.fetchval(
            f"SELECT COUNT(*) FROM raw_events {where}", *params,
        ) or 0

    # ── Run delegation ───────────────────────────────────────────────

    async def create_run(self, *args: Any, **kwargs: Any) -> uuid.UUID:
        return await self.runs.create_run(*args, **kwargs)

    async def mark_run_started(self, *args: Any, **kwargs: Any) -> None:
        await self.runs.mark_run_started(*args, **kwargs)

    async def mark_run_finished(self, *args: Any, **kwargs: Any) -> None:
        await self.runs.mark_run_finished(*args, **kwargs)

    async def count_active_runs(self, *args: Any, **kwargs: Any) -> int:
        return await self.runs.count_active_runs(*args, **kwargs)

    async def list_runs(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        return await self.runs.list_runs(*args, **kwargs)

    async def get_run(self, *args: Any, **kwargs: Any) -> dict[str, Any] | None:
        return await self.runs.get_run(*args, **kwargs)

    async def count_runs(self, *args: Any, **kwargs: Any) -> int:
        return await self.runs.count_runs(*args, **kwargs)

    # ── Entity delegation ────────────────────────────────────────────

    async def upsert_entity(self, *args: Any, **kwargs: Any) -> tuple[uuid.UUID, bool]:
        return await self.entities.upsert_entity(*args, **kwargs)

    async def update_entity_asset_profile(self, *args: Any, **kwargs: Any) -> None:
        await self.entities.update_entity_asset_profile(*args, **kwargs)

    async def apply_asset_profile_for_entity(self, *args: Any, **kwargs: Any) -> None:
        # The legacy signature does not include the optional ``finding_lookup``
        # parameter. Delegating positionally preserves backward compatibility.
        await self.entities.apply_asset_profile_for_entity(*args, **kwargs)

    async def _findings_for_entity(
        self, target_id: str, entity_id: uuid.UUID,
    ) -> list[dict[str, Any]]:
        return await self.entities._findings_for_entity(target_id, entity_id)

    async def upsert_relationship(self, *args: Any, **kwargs: Any) -> None:
        await self.entities.upsert_relationship(*args, **kwargs)

    async def upsert_relationship_by_value(self, *args: Any, **kwargs: Any) -> None:
        await self.entities.upsert_relationship_by_value(*args, **kwargs)

    async def record_asset_change_event(self, *args: Any, **kwargs: Any) -> uuid.UUID:
        return await self.entities.record_asset_change_event(*args, **kwargs)

    async def list_asset_change_events(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        return await self.entities.list_asset_change_events(*args, **kwargs)

    async def get_active_scan_targets(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        return await self.entities.get_active_scan_targets(*args, **kwargs)

    async def get_entity_lineage(self, *args: Any, **kwargs: Any) -> dict[str, Any] | None:
        return await self.entities.get_entity_lineage(*args, **kwargs)

    async def count_entities(self, *args: Any, **kwargs: Any) -> int:
        return await self.entities.count_entities(*args, **kwargs)

    async def migrate_ip_associations(self, *args: Any, **kwargs: Any) -> dict[str, int]:
        return await self.entities.migrate_ip_associations(*args, **kwargs)

    # ── Finding delegation ───────────────────────────────────────────

    async def list_finding_rules(self) -> list[str]:
        return await self.findings.list_finding_rules()

    async def count_findings(self, *args: Any, **kwargs: Any) -> int:
        return await self.findings.count_findings(*args, **kwargs)

    async def create_finding(self, finding: Finding) -> uuid.UUID:
        return await self.findings.create_finding(finding)

    async def list_findings(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        return await self.findings.list_findings(*args, **kwargs)

    async def get_finding(self, *args: Any, **kwargs: Any) -> dict[str, Any] | None:
        return await self.findings.get_finding(*args, **kwargs)

    async def update_finding_status(self, *args: Any, **kwargs: Any) -> None:
        await self.findings.update_finding_status(*args, **kwargs)

    async def acknowledge_finding(self, *args: Any, **kwargs: Any) -> None:
        await self.findings.acknowledge_finding(*args, **kwargs)

    # ── Asset delegation ─────────────────────────────────────────────

    async def list_asset_inventory(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return await self.assets.list_asset_inventory(*args, **kwargs)

    async def export_assets_ndjson(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        return await self.assets.export_assets_ndjson(*args, **kwargs)

    # ── Certificate delegation ───────────────────────────────────────

    async def list_certificate_inventory(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return await self.certificates.list_certificate_inventory(*args, **kwargs)

    async def summarize_certificate_inventory(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return await self.certificates.summarize_certificate_inventory(*args, **kwargs)

    # ── Config delegation ────────────────────────────────────────────

    async def save_config_snapshot(self, *args: Any, **kwargs: Any) -> None:
        await self.config.save_config_snapshot(*args, **kwargs)

    async def list_config_history(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        return await self.config.list_config_history(*args, **kwargs)

    async def get_config_snapshot(self, *args: Any, **kwargs: Any) -> dict[str, Any] | None:
        return await self.config.get_config_snapshot(*args, **kwargs)

    # ── Triage delegation ────────────────────────────────────────────

    async def get_triage_inbox(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        return await self.triage.get_triage_inbox(*args, **kwargs)

    async def set_entity_triage_state(self, *args: Any, **kwargs: Any) -> bool:
        return await self.triage.set_entity_triage_state(*args, **kwargs)

    # ── Auth delegation ──────────────────────────────────────────────

    async def user_count(self) -> int:
        return await self.auth.user_count()

    async def is_first_user(self) -> bool:
        return await self.auth.is_first_user()

    async def create_user(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return await self.auth.create_user(*args, **kwargs)

    async def get_user_by_username(self, *args: Any, **kwargs: Any) -> dict[str, Any] | None:
        return await self.auth.get_user_by_username(*args, **kwargs)

    async def get_user_by_id(self, *args: Any, **kwargs: Any) -> dict[str, Any] | None:
        return await self.auth.get_user_by_id(*args, **kwargs)

    async def get_user_by_sso(self, *args: Any, **kwargs: Any) -> dict[str, Any] | None:
        return await self.auth.get_user_by_sso(*args, **kwargs)

    async def update_user_last_seen(self, *args: Any, **kwargs: Any) -> None:
        await self.auth.update_user_last_seen(*args, **kwargs)

    async def list_users(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        return await self.auth.list_users(*args, **kwargs)

    async def delete_user(self, *args: Any, **kwargs: Any) -> bool:
        return await self.auth.delete_user(*args, **kwargs)

    async def update_user(self, *args: Any, **kwargs: Any) -> bool:
        return await self.auth.update_user(*args, **kwargs)

    async def create_api_key(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return await self.auth.create_api_key(*args, **kwargs)

    async def validate_api_key(self, *args: Any, **kwargs: Any) -> dict[str, Any] | None:
        return await self.auth.validate_api_key(*args, **kwargs)

    async def list_api_keys(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        return await self.auth.list_api_keys(*args, **kwargs)

    async def delete_api_key(self, *args: Any, **kwargs: Any) -> bool:
        return await self.auth.delete_api_key(*args, **kwargs)


__all__ = ["Store", "_canonical_json", "_compute_event_hash"]
