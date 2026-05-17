from __future__ import annotations

import json
from typing import Any

import asyncpg

from easm.correlation.rule import (
    AnalysisMethod,
    CollectCondition,
    CollectMethod,
    CorrelationRule,
    Finding,
)


class CorrelationEngine:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self.pool = pool

    async def evaluate(self, rule: CorrelationRule, org_id: str, target_id: str) -> list[Finding]:
        matched = await self._collect(rule, org_id, target_id)
        if not matched:
            return []
        groups = self._aggregate(matched, rule)
        findings: list[Finding] = []
        for key, entities in groups.items():
            if not self._analyze(entities, rule):
                continue
            first = entities[0]
            placeholder_data = dict(first) | (first.get("attributes") or {})
            try:
                headline = rule.headline.format(**placeholder_data)
            except KeyError:
                headline = rule.headline
            findings.append(
                Finding(
                    org_id=org_id,
                    target_id=target_id,
                    rule_id=rule.id,
                    risk=rule.meta.risk,
                    headline=headline,
                    entity_ids=[e["id"] for e in entities],
                    evidence={"matched_entities": entities},
                )
            )
        return findings

    async def evaluate_rules(
        self, rules: list[CorrelationRule], org_id: str, target_id: str
    ) -> list[Finding]:
        all_findings: list[Finding] = []
        for rule in rules:
            try:
                rule_findings = await self.evaluate(rule, org_id, target_id)
                all_findings.extend(rule_findings)
            except Exception:
                continue
        return all_findings

    async def _collect(
        self, rule: CorrelationRule, org_id: str, target_id: str
    ) -> list[dict[str, Any]]:
        conditions: list[str] = ["org_id = $1", "target_id = $2"]
        params: list[Any] = [org_id, target_id]
        idx = 2

        for cond in rule.collect:
            if cond.method == CollectMethod.EXACT:
                idx += 1
                field_sql = self._field_to_sql(cond.field)
                conditions.append(f"{field_sql} = ${idx}")
                params.append(cond.value)
            elif cond.method == CollectMethod.REGEX:
                field_sql = self._field_to_sql(cond.field)
                sub_conditions = []
                for pattern in cond.patterns or []:
                    idx += 1
                    sub_conditions.append(f"{field_sql} ~ ${idx}::text")
                    params.append(pattern)
                conditions.append(f"({' OR '.join(sub_conditions)})")

        query = f"""
            SELECT id, org_id, target_id, entity_type, entity_value, attributes
            FROM entities
            WHERE {' AND '.join(conditions)}
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query, *params)

        return [
            {
                "id": str(r["id"]),
                "org_id": r["org_id"],
                "target_id": r["target_id"],
                "entity_type": r["entity_type"],
                "entity_value": r["entity_value"],
                "attributes": json.loads(r["attributes"]) if isinstance(r["attributes"], str) else (dict(r["attributes"]) if r["attributes"] else {}),
            }
            for r in rows
        ]

    def _aggregate(
        self, matched: list[dict[str, Any]], rule: CorrelationRule
    ) -> dict[str, list[dict[str, Any]]]:
        groups: dict[str, list[dict[str, Any]]] = {}
        for entity in matched:
            key = self._resolve_field(entity, rule.aggregation.field)
            if key not in groups:
                groups[key] = []
            groups[key].append(entity)
        return groups

    def _analyze(self, entities: list[dict[str, Any]], rule: CorrelationRule) -> bool:
        if not rule.analysis:
            return True
        for step in rule.analysis:
            if step.method == AnalysisMethod.THRESHOLD:
                if step.minimum is not None and len(entities) < step.minimum:
                    return False
                if step.maximum is not None and len(entities) > step.maximum:
                    return False
        return True

    def _field_to_sql(self, field: str) -> str:
        if field == "entity_type":
            return "entity_type"
        if field == "entity_value":
            return "entity_value"
        if field.startswith("attributes."):
            attr_key = field[len("attributes."):]
            return f"attributes->>'{attr_key}'"
        return field

    def _resolve_field(self, entity: dict[str, Any], field: str) -> str:
        if field == "entity_value":
            return entity.get("entity_value", "")
        if field == "entity_type":
            return entity.get("entity_type", "")
        if field.startswith("attributes."):
            attr_key = field[len("attributes."):]
            attrs = entity.get("attributes", {})
            val = attrs.get(attr_key)
            return str(val) if val is not None else ""
        return str(entity.get(field, ""))
