from __future__ import annotations
import logging

import httpx

from easm.config import NotificationChannel
from easm.notifications.types import NotificationPayload

logger = logging.getLogger(__name__)

_RISK_COLORS = {
    "critical": "#FF0000",
    "high": "#FF6600",
    "medium": "#FFCC00",
    "low": "#36A64F",
    "info": "#808080",
}


async def handle_slack(channel: NotificationChannel, payload: NotificationPayload) -> None:
    """Send finding notification to Slack via webhook."""
    cfg = channel.slack
    if not cfg or not cfg.url:
        return

    color = _RISK_COLORS.get(payload.risk, "#808080")
    risk_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}.get(payload.risk, "⚪")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{risk_emoji} EASM Alert: {payload.headline}"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Risk:* {payload.risk.upper()}"},
                {"type": "mrkdwn", "text": f"*Rule:* `{payload.rule_id}`"},
                {"type": "mrkdwn", "text": f"*Target:* `{payload.target_id}`"},
                {"type": "mrkdwn", "text": f"*Time:* {payload.timestamp}"},
            ],
        },
    ]

    if payload.entity_ids:
        entity_text = ", ".join(f"`{eid[:8]}...`" for eid in payload.entity_ids[:5])
        if len(payload.entity_ids) > 5:
            entity_text += f" (+{len(payload.entity_ids) - 5} more)"
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Entities:* {entity_text}"},
        })

    if payload.dashboard_url:
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View in Dashboard"},
                    "url": payload.dashboard_url,
                }
            ],
        })

    message = {
        "attachments": [{"color": color, "blocks": blocks}],
    }

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(cfg.url, json=message)
        resp.raise_for_status()
        logger.info("slack notification sent", extra={"channel": channel.name})
