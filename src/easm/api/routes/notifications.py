from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from easm.notifications.dispatcher import get_dispatcher
from easm.notifications.types import NotificationPayload

router = APIRouter(prefix="/notifications", tags=["notifications"])
logger = logging.getLogger(__name__)


class TestNotificationRequest(BaseModel):
    channel_name: str


@router.post("/test")
async def test_notification(req: TestNotificationRequest) -> dict:
    """Send a test notification to the specified channel."""
    dispatcher = get_dispatcher()
    if not dispatcher:
        raise HTTPException(status_code=503, detail="Notification dispatcher not configured")

    payload = NotificationPayload(
        finding_id="test-00000000",
        rule_id="test_rule",
        headline="Test Notification from Open EASM",
        risk="info",
        severity="info",
        target_id="test-target",
        entity_ids=["test-entity-001"],
        evidence={"test": True},
    )

    channel_found = False
    for ch in dispatcher._config.channels:
        if ch.name == req.channel_name:
            channel_found = True
            if not ch.enabled:
                raise HTTPException(
                    status_code=400,
                    detail=f"Channel '{req.channel_name}' is disabled",
                )
            handler = dispatcher._get_handler(ch)
            if not handler:
                raise HTTPException(
                    status_code=400,
                    detail=f"No handler for channel type '{ch.type}'",
                )
            try:
                await handler(ch, payload)
                return {"status": "sent", "channel": req.channel_name}
            except Exception as e:
                logger.exception("test notification failed", extra={"channel": req.channel_name})
                raise HTTPException(status_code=500, detail=f"Failed to send: {e}") from e

    if not channel_found:
        raise HTTPException(status_code=404, detail=f"Channel '{req.channel_name}' not found")
    return {"status": "error", "channel": req.channel_name}


@router.get("/channels")
async def list_channels() -> dict:
    """List configured notification channels."""
    dispatcher = get_dispatcher()
    if not dispatcher:
        return {"channels": []}
    channels = []
    for ch in dispatcher._config.channels:
        channels.append({
            "name": ch.name,
            "type": ch.type.value,
            "enabled": ch.enabled,
            "min_severity": ch.min_severity,
        })
    return {"channels": channels}
