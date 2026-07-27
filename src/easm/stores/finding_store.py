"""Finding persistence (``findings`` table)."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

import asyncpg

from easm.stores import BaseStore

if TYPE_CHECKING:
    from easm.correlation.rule import Finding


def _compute_fingerprint(rule_id: str, target_id: str, entity_ids: list[str]) -> str:
    """Deterministic sha256 fingerprint for a finding.

    Two findings with the same ``rule_id``, ``target_id`` and set of
    affected entities are treated as the same finding across pivot cycles.
    Entity ids are normalised to canonical lowercase UUID form before
    sorting so that ordering and case differences do not fragment the
    fingerprint.
    """
    canonical_entities = sorted(str(uuid.UUID(eid)) for eid in entity_ids)
    payload = f"{rule_id}:{target_id}:{canonical_entities}"
    return hashlib.sha256(payload.encode()).hexdigest()


def _row_to_finding_dict(row: asyncpg.Record) -> dict[str, Any]:
    def _fmt(dt: datetime | None) -> str | None:
        return dt.isoformat() if dt else None

    def _parse(val: Any) -> Any:
        if isinstance(val, dict):
            return val
        if isinstance(val, str):
            try:
                return json.loads(val)
            except (json.JSONDecodeError, TypeError):
                return {}
        return {}

    return {
        "id": str(row["id"]),
        "org_id": row["org_id"],
        "target_id": row["target_id"],
        "rule_id": row["rule_id"],
        "risk": row["risk"],
        "headline": row["headline"],
        "description": row["description"],
        "entity_ids": [str(eid) for eid in row["entity_ids"]] if row["entity_ids"] else [],
        "evidence": _parse(row["evidence"]),
        "status": row["status"],
        "confidence_score": row.get("confidence_score"),
        "confidence_level": row.get("confidence_level"),
        "first_seen_at": _fmt(row["first_seen_at"]),
        "last_seen_at": _fmt(row["last_seen_at"]),
        "created_at": _fmt(row["created_at"]),
    }


class FindingStore(BaseStore):
    """Persistence for correlation findings."""

    async def list_finding_rules(self) -> list[str]:
        rows = await self._pool.fetch(
            "SELECT DISTINCT rule_id FROM findings ORDER BY rule_id"
        )
        return [r["rule_id"] for r in rows]

    async def count_findings(
        self,
        target_id: str | None = None,
        risk: str | None = None,
        status: str | None = None,
        rule_id: str | None = None,
    ) -> int:
        conditions: list[str] = []
        params: list[Any] = []
        idx = 0
        if target_id:
            idx += 1
            conditions.append(f"target_id = ${idx}")
            params.append(target_id)
        if risk:
            idx += 1
            conditions.append(f"risk = ${idx}")
            params.append(risk)
        if status:
            idx += 1
            conditions.append(f"status = ${idx}")
            params.append(status)
        if rule_id:
            idx += 1
            conditions.append(f"rule_id = ${idx}")
            params.append(rule_id)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        return await self._pool.fetchval(
            f"SELECT COUNT(*) FROM findings {where}", *params,
        ) or 0

    async def create_finding(self, finding: Finding) -> uuid.UUID:
        """Idempotent insert: refreshes ``last_seen_at`` on fingerprint conflict.

        Returns the row id in both the insert and update paths, so callers
        cannot assume an INSERT occurred.
        """
        fingerprint = _compute_fingerprint(
            finding.rule_id, finding.target_id, finding.entity_ids,
        )
        row = await self._pool.fetchrow(
            """
            INSERT INTO findings (org_id, target_id, rule_id, risk, headline, description,
                                  entity_ids, evidence, status,
                                  confidence_score, confidence_level, fingerprint)
            VALUES ($1, $2, $3, $4, $5, $6, $7::uuid[], $8::jsonb, $9, $10, $11, $12)
            ON CONFLICT (fingerprint) DO UPDATE SET last_seen_at = NOW()
            RETURNING id
            """,
            finding.org_id,
            finding.target_id,
            finding.rule_id,
            finding.risk.value if hasattr(finding.risk, "value") else finding.risk,
            finding.headline,
            finding.description,
            [uuid.UUID(eid) for eid in finding.entity_ids],
            json.dumps(finding.evidence, default=str),
            finding.status,
            finding.confidence_score,
            finding.confidence_level,
            fingerprint,
        )
        assert row is not None
        return row["id"]

    async def list_findings(
        self,
        org_id: str = "default",
        target_id: str | None = None,
        risk: str | None = None,
        status: str | None = None,
        rule_id: str | None = None,
        q: str | None = None,
        confidence_min: float | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        conditions: list[str] = ["org_id = $1"]
        params: list[Any] = [org_id]
        idx = 1

        if target_id:
            idx += 1
            conditions.append(f"target_id = ${idx}")
            params.append(target_id)
        if risk:
            idx += 1
            conditions.append(f"risk = ${idx}")
            params.append(risk)
        if status:
            idx += 1
            conditions.append(f"status = ${idx}")
            params.append(status)
        if rule_id:
            idx += 1
            conditions.append(f"rule_id = ${idx}")
            params.append(rule_id)
        if confidence_min is not None:
            idx += 1
            conditions.append(f"confidence_score >= ${idx}")
            params.append(confidence_min)
        if q:
            idx += 1
            conditions.append(f"(headline ILIKE ${idx} OR rule_id ILIKE ${idx})")
            params.append(f"%{q}%")

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        idx += 1
        idx += 1
        query = f"""
            SELECT id, org_id, target_id, rule_id, risk, headline, description,
                   entity_ids, evidence, status,
                   confidence_score, confidence_level,
                   first_seen_at, last_seen_at, created_at
            FROM findings
            {where}
            ORDER BY risk DESC, created_at DESC
            LIMIT ${idx - 1} OFFSET ${idx}
        """
        params.extend([limit, offset])
        rows = await self._pool.fetch(query, *params)
        return [_row_to_finding_dict(r) for r in rows]

    async def get_finding(self, finding_id: uuid.UUID) -> dict[str, Any] | None:
        row = await self._pool.fetchrow(
            """SELECT id, org_id, target_id, rule_id, risk, headline, description,
                      entity_ids, evidence, status,
                      confidence_score, confidence_level,
                      first_seen_at, last_seen_at, created_at
               FROM findings WHERE id = $1""",
            finding_id,
        )
        if row is None:
            return None
        return _row_to_finding_dict(row)

    async def update_finding_status(self, finding_id: uuid.UUID, status: str) -> None:
        await self._pool.execute(
            "UPDATE findings SET status = $1, last_seen_at = NOW() WHERE id = $2",
            status, finding_id,
        )

    async def acknowledge_finding(self, finding_id: uuid.UUID) -> None:
        await self.update_finding_status(finding_id, "acknowledged")
