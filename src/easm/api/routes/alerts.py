from __future__ import annotations

from fastapi import APIRouter, Depends

from easm.api.deps import get_config, get_store
from easm.api.schemas import AlertFeedEntry, AlertRuleSchema

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("/rules", response_model=list[AlertRuleSchema])
async def list_alert_rules(config=Depends(get_config)):
    return [
        AlertRuleSchema(
            name=r.name,
            description=r.description,
            enabled=r.enabled,
            condition=r.condition,
            severity=r.severity,
        )
        for r in config.alerts.rules
    ]


@router.get("/feed", response_model=list[AlertFeedEntry])
async def alert_feed(store=Depends(get_store)):
    rows = await store.pool.fetch(
        "SELECT id, rule_id, risk, title, description, entity_ids, created_at, status "
        "FROM findings ORDER BY created_at DESC LIMIT 50"
    )
    return [
        AlertFeedEntry(
            id=str(r["id"]),
            rule_name=r["rule_id"] or "unknown",
            severity=r["risk"] or "low",
            title=r["title"] or "",
            detail=r["description"] or "",
            created_at=r["created_at"].isoformat(),
            acknowledged=r["status"] == "acknowledged",
        )
        for r in rows
    ]


@router.patch("/feed/{finding_id}")
async def acknowledge_finding(finding_id: str, store=Depends(get_store)):
    await store.pool.execute(
        "UPDATE findings SET status = 'acknowledged' WHERE id = $1",
        finding_id,
    )
    return {"status": "ok"}
