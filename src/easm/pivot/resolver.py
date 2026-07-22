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
            "SELECT COUNT(*) FROM procrastinate_jobs "
            "WHERE task_name = 'easm.tasks.pivot.execute_pivot' AND status = 'todo'"
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

            if pivot_rule.skip_on_source:
                entity_row = await self.pool.fetchrow(
                    "SELECT attributes FROM entities WHERE id = $1",
                    entity_id,
                )
                if entity_row:
                    attrs = entity_row["attributes"]
                    if isinstance(attrs, str):
                        import json
                        attrs = json.loads(attrs)
                    if attrs and attrs.get("source") in pivot_rule.skip_on_source:
                        logger.debug(
                            "skipping pivot due to skip_on_source",
                            extra={
                                "entity_type": entity_type,
                                "entity_value": entity_value,
                                "pivot_type": pivot_rule.via,
                                "source": attrs.get("source"),
                            },
                        )
                        continue

            if pivot_rule.coverage and pivot_rule.coverage.apex_covers_subdomains:
                if entity_type in ("domain", "hostname"):
                    apex = tldextract.extract(entity_value).registered_domain
                    if apex != entity_value:
                        covered = await self._check_apex_coverage(
                            target.org_id, apex, pivot_rule.via, pivot_rule.cooldown_hours,
                        )
                        if covered:
                            logger.debug(
                                "skipping pivot due to apex coverage",
                                extra={
                                    "entity_type": entity_type,
                                    "entity_value": entity_value,
                                    "pivot_type": pivot_rule.via,
                                    "apex": apex,
                                },
                            )
                            continue

            if pivot_rule.cooldown_hours > 0:
                recent = await self._check_cooldown(
                    target.org_id, entity_type, entity_value, pivot_rule.via,
                    pivot_rule.cooldown_hours,
                )
                if recent:
                    continue

            from easm.tasks.pivot import execute_pivot

            # Priority: fast/cheap pivots should not be blocked by slow ones
            _priority = {
                "dns_resolve": 100,
                "reverse_dns": 80,
                "takeover_detect": 70,
                "subdomain_takeover": 70,
                "domain_extract": 60,
                "geoip_enrich": 50,
                "dns_mail_records": 40,
                "ip_to_asn": 40,
            }.get(pivot_rule.via, 10)

            await execute_pivot.configure(
                queue="pivot",
                priority=_priority,
            ).defer_async(
                org_id=target.org_id,
                target_id=target.id,
                entity_type=entity_type,
                entity_value=entity_value,
                entity_id=str(entity_id),
                pivot_type=pivot_rule.via,
                depth=depth,
                parent_entity_id=str(parent_entity_id) if parent_entity_id else None,
                discovery_session_id=str(discovery_session_id) if discovery_session_id else None,
            )

            # Auto-enqueue CPE→CVE enrichment after tech-detection pivots
            if pivot_rule.via in ("shodan_enrich",) and depth + 1 <= pivot_config.max_depth:
                await execute_pivot.configure(
                    queue="pivot",
                ).defer_async(
                    org_id=target.org_id,
                    target_id=target.id,
                    entity_type=entity_type,
                    entity_value=entity_value,
                    entity_id=str(entity_id),
                    pivot_type="cpe_vuln_enrich",
                    depth=depth + 1,
                    parent_entity_id=str(entity_id),
                    discovery_session_id=(
                        str(discovery_session_id) if discovery_session_id else None
                    ),
                )

    async def _get_classification(self, entity_id) -> str | None:
        row = await self.pool.fetchval(
            "SELECT attributes->>'asset_classification' FROM entities WHERE id = $1",
            entity_id,
        )
        return row

    async def _check_apex_coverage(self, org_id, apex, pivot_type, cooldown_hours):
        row = await self.pool.fetchval("""
            SELECT 1 FROM procrastinate_jobs j
            WHERE j.task_name = 'easm.tasks.pivot.execute_pivot'
              AND j.status IN ('succeeded', 'doing', 'todo')
              AND j.args->>'org_id' = $1
              AND j.args->>'entity_value' = $2
              AND j.args->>'pivot_type' = $3
            LIMIT 1
        """, org_id, apex, pivot_type)
        return row

    async def _check_cooldown(self, org_id, entity_type, entity_value, pivot_type, cooldown_hours):
        row = await self.pool.fetchval("""
            SELECT 1 FROM procrastinate_events ev
            JOIN procrastinate_jobs j ON ev.job_id = j.id
            WHERE j.task_name = 'easm.tasks.pivot.execute_pivot'
              AND j.status = 'succeeded'
              AND j.args->>'org_id' = $1
              AND j.args->>'entity_type' = $2
              AND j.args->>'entity_value' = $3
              AND j.args->>'pivot_type' = $4
              AND ev.type = 'succeeded'
              AND ev.at > NOW() - ($5 || ' hours')::INTERVAL
            LIMIT 1
        """, org_id, entity_type, entity_value, pivot_type, str(cooldown_hours))
        return row

