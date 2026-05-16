from __future__ import annotations

import tldextract

from easm.models import ScopeResult
from easm.pivot_store import enqueue_pivot_job


class PivotResolver:
    def __init__(self, pool):
        self.pool = pool

    async def check_and_enqueue(
        self, target, entity_type, entity_value, entity_id,
        parent_entity_id=None, depth=1, discovery_session_id=None,
    ):
        pivot_config = target.pivot
        if not pivot_config or not pivot_config.enabled:
            return
        if depth > pivot_config.max_depth:
            return

        from easm.pivot.scope import ScopeEvaluator
        scope = ScopeEvaluator().evaluate(target, entity_type, entity_value)
        if scope == ScopeResult.OUT_OF_SCOPE and pivot_config.scope_mode == "strict":
            return

        for pivot_rule in pivot_config.allowed_pivots:
            if pivot_rule.from_ != entity_type:
                continue

            if pivot_rule.coverage and pivot_rule.coverage.apex_covers_subdomains:
                if entity_type == "domain":
                    apex = tldextract.extract(entity_value).registered_domain
                    if apex != entity_value:
                        covered = await self._check_apex_coverage(
                            target.org_id, apex, pivot_rule.via, pivot_rule.cooldown_hours,
                        )
                        if covered:
                            await self._insert_skipped(
                                target.org_id, target.id, entity_type, entity_value,
                                pivot_rule.via, f"covered_by_apex:{apex}",
                            )
                            continue

            if pivot_rule.cooldown_hours > 0:
                recent = await self._check_cooldown(
                    target.org_id, entity_type, entity_value, pivot_rule.via,
                    pivot_rule.cooldown_hours,
                )
                if recent:
                    continue

            await enqueue_pivot_job(
                self.pool,
                org_id=target.org_id,
                target_id=target.id,
                entity_type=entity_type,
                entity_value=entity_value,
                entity_id=entity_id,
                pivot_type=pivot_rule.via,
                depth=depth,
                parent_entity_id=parent_entity_id,
                discovery_session_id=discovery_session_id,
            )

    async def _check_apex_coverage(self, org_id, apex, pivot_type, cooldown_hours):
        row = await self.pool.fetchval("""
            SELECT 1 FROM pivot_queue
            WHERE org_id=$1 AND entity_value=$2 AND pivot_type=$3
              AND status='completed'
              AND completed_at > NOW() - ($4 || ' hours')::INTERVAL
            LIMIT 1
        """, org_id, apex, pivot_type, str(cooldown_hours))

    async def _check_cooldown(self, org_id, entity_type, entity_value, pivot_type, cooldown_hours):
        row = await self.pool.fetchval("""
            SELECT 1 FROM pivot_queue
            WHERE org_id=$1 AND entity_type=$2 AND entity_value=$3 AND pivot_type=$4
              AND status IN ('completed', 'running')
              AND enqueued_at > NOW() - ($5 || ' hours')::INTERVAL
            LIMIT 1
        """, org_id, entity_type, entity_value, pivot_type, str(cooldown_hours))

    async def _insert_skipped(self, org_id, target_id, entity_type, entity_value, pivot_type, reason):
        await self.pool.execute("""
            INSERT INTO pivot_queue (org_id, target_id, entity_type, entity_value, pivot_type, status, skip_reason)
            VALUES ($1, $2, $3, $4, $5, 'skipped_covered', $6)
        """, org_id, target_id, entity_type, entity_value, pivot_type, reason)
