from __future__ import annotations

from fastapi import APIRouter, Depends

from easm.api.deps import get_config, get_store
from easm.api.schemas import AlertFeedEntry, AlertRuleSchema
from easm.store import Store

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
async def alert_feed(store: Store = Depends(get_store)):
    results = await store.list_findings(limit=50, offset=0)
    return [
        AlertFeedEntry(
            id=r["id"], rule_name=r["rule_id"] or "unknown",
            severity=r["risk"] or "low", title=r["headline"] or "",
            detail=r["description"] or "", created_at=r["created_at"],
            acknowledged=r["status"] == "acknowledged",
        )
        for r in results
    ]


@router.patch("/feed/{finding_id}")
async def acknowledge_finding(finding_id: str, store: Store = Depends(get_store)):
    import uuid as _uuid
    fid = _uuid.UUID(finding_id)
    await store.acknowledge_finding(fid)
    return {"status": "ok"}
