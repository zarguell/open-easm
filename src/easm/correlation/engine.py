from __future__ import annotations

import json
from typing import Any

import asyncpg

from easm.assets.lifecycle import compute_lifecycle_state
from easm.correlation.rule import (
    AnalysisMethod,
    CollectMethod,
    CorrelationRule,
    Finding,
)


def _compute_finding_confidence(matched_entities: list[dict]) -> tuple[float, str]:
    """Compute aggregate confidence from matched entities.

    Uses the average confidence score of all matched entities.
    Falls back to (0.0, "unknown") if no entity has confidence data.
    """
    scores = []
    for entity in matched_entities:
        attrs = entity.get("attributes", {})
        profile = attrs.get("asset_profile", {}) if isinstance(attrs, dict) else {}
        conf = profile.get("confidence", {}) if isinstance(profile, dict) else {}
        score = conf.get("score")
        if score is not None:
            scores.append(float(score))

    if not scores:
        return (0.0, "unknown")

    avg = sum(scores) / len(scores)
    if avg >= 80:
        level = "high"
    elif avg >= 50:
        level = "medium"
    else:
        level = "low"
    return (round(avg, 1), level)


class CorrelationEngine:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self.pool = pool

    async def evaluate(self, rule: CorrelationRule, org_id: str, target_id: str) -> list[Finding]:
        matched = await self._collect(rule, org_id, target_id)
        if not matched:
            return []
        groups = self._aggregate(matched, rule)
        findings: list[Finding] = []
        for _key, entities in groups.items():
            if not self._analyze(entities, rule):
                continue
            first = entities[0]
            entity_lifecycle = compute_lifecycle_state(first.get("first_seen_at"))
            novelty_factor = {"new": 1.5, "recent": 1.2, "stable": 1.0}.get(entity_lifecycle, 1.0)
            placeholder_data = dict(first) | (first.get("attributes") or {})
            try:
                headline = rule.headline.format(**placeholder_data)
            except KeyError:
                headline = rule.headline
            conf_score, conf_level = _compute_finding_confidence(entities)
            findings.append(
                Finding(
                    org_id=org_id,
                    target_id=target_id,
                    rule_id=rule.id,
                    risk=rule.meta.risk,
                    headline=headline,
                    entity_ids=[e["id"] for e in entities],
                    evidence={
                        "matched_entities": entities,
                        "novelty_factor": novelty_factor,
                        "lifecycle_state": entity_lifecycle,
                    },
                    confidence_score=conf_score,
                    confidence_level=conf_level,
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
            elif cond.method == CollectMethod.NOT_REGEX:
                field_sql = self._field_to_sql(cond.field)
                sub_conditions = []
                for pattern in cond.patterns or []:
                    idx += 1
                    sub_conditions.append(f"{field_sql} !~ ${idx}::text")
                    params.append(pattern)
                conditions.append(f"({' AND '.join(sub_conditions)})")
            elif cond.method == CollectMethod.REGEX:
                field_sql = self._field_to_sql(cond.field)
                sub_conditions = []
                for pattern in cond.patterns or []:
                    idx += 1
                    sub_conditions.append(f"{field_sql} ~ ${idx}::text")
                    params.append(pattern)
                conditions.append(f"({' OR '.join(sub_conditions)})")

        query = f"""
            SELECT id, org_id, target_id, entity_type, entity_value, attributes,
                   first_seen_at
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
                "attributes": (
                    json.loads(r["attributes"])
                    if isinstance(r["attributes"], str)
                    else (dict(r["attributes"]) if r["attributes"] else {})
                ),
                "first_seen_at": r["first_seen_at"],
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
