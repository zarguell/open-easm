from __future__ import annotations

import asyncio
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

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


def _build_email_html(payload: NotificationPayload) -> str:
    color = _RISK_COLORS.get(payload.risk, "#808080")
    entities_html = ""
    if payload.entity_ids:
        entities_html = "<h3>Related Entities</h3><ul>"
        for eid in payload.entity_ids[:10]:
            entities_html += f"<li><code>{eid}</code></li>"
        if len(payload.entity_ids) > 10:
            entities_html += f"<li><em>...and {len(payload.entity_ids) - 10} more</em></li>"
        entities_html += "</ul>"

    dashboard_link = ""
    if payload.dashboard_url:
        dashboard_link = f'<a href="{payload.dashboard_url}" style="display:inline-block;padding:10px 20px;background:#00e5ff;color:#000;text-decoration:none;border-radius:4px;margin-top:16px;">View in Dashboard</a>'

    return f"""
    <html><body style="font-family:sans-serif;background:#0a0a0a;color:#e0e0e0;padding:20px;">
    <div style="max-width:600px;margin:0 auto;background:#111;border:1px solid #333;border-radius:8px;padding:24px;">
        <div style="border-left:4px solid {color};padding-left:16px;">
            <h2 style="margin:0;color:#fff;">EASM Security Alert</h2>
            <p style="color:{color};font-size:18px;margin:8px 0;">{payload.headline}</p>
        </div>
        <table style="width:100%;margin:16px 0;border-collapse:collapse;">
            <tr><td style="padding:8px;border-bottom:1px solid #222;color:#888;">Risk Level</td><td style="padding:8px;border-bottom:1px solid #222;color:{color};font-weight:bold;">{payload.risk.upper()}</td></tr>
            <tr><td style="padding:8px;border-bottom:1px solid #222;color:#888;">Rule</td><td style="padding:8px;border-bottom:1px solid #222;"><code>{payload.rule_id}</code></td></tr>
            <tr><td style="padding:8px;border-bottom:1px solid #222;color:#888;">Target</td><td style="padding:8px;border-bottom:1px solid #222;"><code>{payload.target_id}</code></td></tr>
            <tr><td style="padding:8px;border-bottom:1px solid #222;color:#888;">Time</td><td style="padding:8px;border-bottom:1px solid #222;">{payload.timestamp}</td></tr>
        </table>
        {entities_html}
        {dashboard_link}
    </div>
    </body></html>
    """


def _send_smtp_sync(cfg: Any, msg: MIMEMultipart) -> None:
    """Blocking SMTP send — run in executor."""
    if cfg.use_tls:
        with smtplib.SMTP(cfg.host, cfg.port) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            if cfg.username and cfg.password:
                server.login(cfg.username, cfg.password)
            server.send_message(msg)
    else:
        with smtplib.SMTP(cfg.host, cfg.port) as server:
            if cfg.username and cfg.password:
                server.login(cfg.username, cfg.password)
            server.send_message(msg)


async def handle_smtp(channel: NotificationChannel, payload: NotificationPayload) -> None:
    cfg = channel.smtp
    if not cfg or not cfg.host:
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[EASM {payload.risk.upper()}] {payload.headline}"
    msg["From"] = cfg.from_address
    msg["To"] = ", ".join(cfg.to_addresses)

    text_body = (
        f"EASM Security Alert\n\n"
        f"Headline: {payload.headline}\n"
        f"Risk: {payload.risk.upper()}\n"
        f"Rule: {payload.rule_id}\n"
        f"Target: {payload.target_id}\n"
        f"Time: {payload.timestamp}\n"
    )
    if payload.entity_ids:
        text_body += f"\nEntities: {', '.join(payload.entity_ids[:10])}\n"
    if payload.dashboard_url:
        text_body += f"\nView: {payload.dashboard_url}\n"

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(_build_email_html(payload), "html"))

    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _send_smtp_sync, cfg, msg)
    logger.info("smtp notification sent", extra={"channel": channel.name, "recipients": cfg.to_addresses})
