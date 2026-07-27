"""Triage queue persistence.

Entities with ``attributes.triage_state = 'discovered'`` form the analyst
inbox. ``set_entity_triage_state`` transitions them through the four
allowed states (``discovered``, ``adopted``, ``dismissed``, ``active``).
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from easm.stores import BaseStore


class TriageStore(BaseStore):
    """Read-side triage inbox + triage state transitions."""

    async def get_triage_inbox(
        self,
        org_id: str,
        target_id: str | None = None,
        entity_type: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        where_clauses = ["e.org_id = $1", "e.attributes->>'triage_state' = 'discovered'"]
        params: list[Any] = [org_id]
        idx = 2
        if target_id:
            where_clauses.append(f"e.target_id = ${idx}")
            params.append(target_id)
            idx += 1
        if entity_type:
            where_clauses.append(f"e.entity_type = ${idx}")
            params.append(entity_type)
            idx += 1
        params.append(limit)
        params.append(offset)
        rows = await self._pool.fetch(
            f"""SELECT e.*, count(*) OVER() as total_count
                FROM entities e
                WHERE {' AND '.join(where_clauses)}
                ORDER BY e.first_seen_at DESC
                LIMIT ${idx} OFFSET ${idx + 1}""",
            *params,
        )
        return [dict(r) for r in rows]

    async def set_entity_triage_state(
        self,
        org_id: str,
        entity_id: uuid.UUID,
        triage_state: str,
    ) -> bool:
        valid_states = {"discovered", "adopted", "dismissed", "active"}
        if triage_state not in valid_states:
            return False
        result = await self._pool.execute(
            """UPDATE entities
               SET attributes = jsonb_set(attributes, '{triage_state}', $1::jsonb)
               WHERE org_id = $2 AND id = $3""",
            json.dumps(triage_state), org_id, entity_id,
        )
        return result.endswith("1")
