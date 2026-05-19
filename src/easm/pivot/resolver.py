from __future__ import annotations

import logging

import tldextract

from easm.models import ScopeResult
from easm.store import Store

logger = logging.getLogger(__name__)


class PivotResolver:
    def __init__(self, pool):
        self.pool = pool
        self.store = Store(pool)

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

        # Skip pivots for non-org-owned entities (saas-hosted, third-party-integrated)
        classification = await self._get_classification(entity_id)
        if classification and classification != "org-owned":
            return

        max_queue_depth = getattr(pivot_config, 'max_queue_depth', 10000)
        count = await self.pool.fetchval(
            "SELECT COUNT(*) FROM pivot_queue WHERE status = 'pending'"
        )
        if count is not None and count >= max_queue_depth:
            logger.warning(
                "pivot queue at capacity, skipping enqueue",
                extra={
                    "queue_depth": count,
                    "max": max_queue_depth,
                    "target_id": target.id,
                    "entity_type": entity_type,
                    "entity_value": entity_value,
                },
            )
            return

        for pivot_rule in pivot_config.allowed_pivots:
            if pivot_rule.from_ != entity_type:
                continue

            if pivot_rule.coverage and pivot_rule.coverage.apex_covers_subdomains:
                if entity_type in ("domain", "hostname"):
                    apex = tldextract.extract(entity_value).registered_domain
                    if apex != entity_value:
                        covered = await self._check_apex_coverage(
                            target.org_id, apex, pivot_rule.via, pivot_rule.cooldown_hours,
                        )
                        if covered:
                            await self._insert_skipped(
                                target.org_id, target.id, entity_type, entity_value,
                                entity_id, pivot_rule.via, f"covered_by_apex:{apex}",
                            )
                            continue

            if pivot_rule.cooldown_hours > 0:
                recent = await self._check_cooldown(
                    target.org_id, entity_type, entity_value, pivot_rule.via,
                    pivot_rule.cooldown_hours,
                )
                if recent:
                    continue

            await self.store.enqueue_pivot_job(
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

            # Auto-enqueue CPE→CVE enrichment after tech-detection pivots
            if pivot_rule.via in ("shodan_enrich",) and depth + 1 <= pivot_config.max_depth:
                await self.store.enqueue_pivot_job(
                    org_id=target.org_id,
                    target_id=target.id,
                    entity_type=entity_type,
                    entity_value=entity_value,
                    entity_id=entity_id,
                    pivot_type="cpe_vuln_enrich",
                    depth=depth + 1,
                    parent_entity_id=entity_id,
                    discovery_session_id=discovery_session_id,
                )

    async def _get_classification(self, entity_id) -> str | None:
        row = await self.pool.fetchval(
            "SELECT attributes->>'asset_classification' FROM entities WHERE id = $1",
            entity_id,
        )
        return row

    async def _check_apex_coverage(self, org_id, apex, pivot_type, cooldown_hours):
        row = await self.pool.fetchval("""
            SELECT 1 FROM pivot_queue
            WHERE org_id=$1 AND entity_value=$2 AND pivot_type=$3
              AND status='completed'
              AND completed_at > NOW() - ($4 || ' hours')::INTERVAL
            LIMIT 1
        """, org_id, apex, pivot_type, str(cooldown_hours))
        return row

    async def _check_cooldown(self, org_id, entity_type, entity_value, pivot_type, cooldown_hours):
        row = await self.pool.fetchval("""
            SELECT 1 FROM pivot_queue
            WHERE org_id=$1 AND entity_type=$2 AND entity_value=$3 AND pivot_type=$4
              AND status IN ('completed', 'running')
              AND enqueued_at > NOW() - ($5 || ' hours')::INTERVAL
            LIMIT 1
        """, org_id, entity_type, entity_value, pivot_type, str(cooldown_hours))
        return row

    async def _insert_skipped(self, org_id, target_id, entity_type, entity_value, entity_id, pivot_type, reason):
        await self.pool.execute("""
            INSERT INTO pivot_queue (org_id, target_id, entity_type, entity_value, entity_id, pivot_type, status, skip_reason)
            VALUES ($1, $2, $3, $4, $5, $6, 'skipped_covered', $7)
        """, org_id, target_id, entity_type, entity_value, entity_id, pivot_type, reason)
