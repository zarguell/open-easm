from __future__ import annotations
import hashlib
import hmac
import json
import logging

import httpx

from easm.config import NotificationChannel, WebhookChannelConfig
from easm.notifications.types import NotificationPayload

logger = logging.getLogger(__name__)


async def handle_webhook(channel: NotificationChannel, payload: NotificationPayload) -> None:
    """Send finding notification to a generic webhook endpoint."""
    cfg = channel.webhook
    if not cfg or not cfg.url:
        return

    body = {
        "finding_id": payload.finding_id,
        "rule_id": payload.rule_id,
        "headline": payload.headline,
        "risk": payload.risk,
        "severity": payload.severity,
        "target_id": payload.target_id,
        "entity_ids": payload.entity_ids,
        "evidence": payload.evidence,
        "dashboard_url": payload.dashboard_url,
        "timestamp": payload.timestamp,
        "channel_name": channel.name,
    }

    headers: dict[str, str] = {"Content-Type": "application/json"}

    # HMAC signature if secret configured
    if cfg.secret:
        raw = json.dumps(body, sort_keys=True, default=str).encode()
        sig = hmac.new(cfg.secret.encode(), raw, hashlib.sha256).hexdigest()
        headers["X-EASM-Signature"] = f"sha256={sig}"

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.request(cfg.method, cfg.url, json=body, headers=headers)
        resp.raise_for_status()
        logger.info("webhook notification sent", extra={"channel": channel.name, "status": resp.status_code})
