from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query

from easm.api.deps import get_store
from easm.api.schemas import EventDetail, EventSummary

router = APIRouter(prefix="/events", tags=["events"])


@router.get("/count")
async def count_events(
    target_id: str | None = None,
    source: str | None = None,
    start: str | None = None,
    end: str | None = None,
):
    store = get_store()
    start_dt = datetime.fromisoformat(start) if start else None
    end_dt = datetime.fromisoformat(end) if end else None
    count = await store.count_events(
        target_id=target_id, source=source, start=start_dt, end=end_dt,
    )
    return {"count": count}


@router.get("", response_model=list[EventSummary])
async def list_events(
    target_id: str | None = None,
    source: str | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    cursor: str | None = None,
) -> list[EventSummary]:
    store = get_store()
    start_dt = datetime.fromisoformat(start) if start else None
    end_dt = datetime.fromisoformat(end) if end else None
    events, _ = await store.list_events(
        target_id=target_id, source=source, start=start_dt, end=end_dt, limit=limit, cursor=cursor,
    )
    return [EventSummary(**e) for e in events]


@router.get("/{event_id}", response_model=EventDetail)
async def get_event(event_id: str) -> EventDetail:
    store = get_store()
    try:
        uid = uuid.UUID(event_id)
    except ValueError:
        raise HTTPException(
            status_code=400, detail={"error": "invalid_id", "detail": "Invalid event ID format"}
        ) from None
    event = await store.get_event(uid)
    if event is None:
        raise HTTPException(
            status_code=404, detail={"error": "not_found", "detail": "Event not found"}
        )
    return EventDetail(**event)
