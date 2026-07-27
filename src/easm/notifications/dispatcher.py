from __future__ import annotations

import logging
from typing import Any

from easm.config import NotificationChannel, NotificationConfig
from easm.notifications.types import NotificationPayload

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class NotificationDispatcher:
    def __init__(self, config: NotificationConfig, base_url: str = "http://localhost:8000"):
        self._config = config
        self._base_url = base_url
        self._rate_counts: dict[str, int] = {}

    async def dispatch(self, payload: NotificationPayload) -> None:
        risk_level = _SEVERITY_ORDER.get(payload.risk, 0)
        for channel in self._config.channels:
            if not channel.enabled:
                continue
            min_level = _SEVERITY_ORDER.get(channel.min_severity, 0)
            if risk_level < min_level:
                continue
            if self._is_rate_limited(channel.name):
                logger.warning("notification rate limited", extra={"channel": channel.name})
                continue
            payload.dashboard_url = f"{self._base_url}/ui/findings"
            try:
                handler = self._get_handler(channel)
                if handler:
                    await handler(channel, payload)
                    self._rate_counts[channel.name] = self._rate_counts.get(channel.name, 0) + 1
            except (ValueError, KeyError, TypeError, OSError) as e:
                logger.exception(
                    "notification dispatch failed",
                    extra={"channel": channel.name, "error": str(e)},
                )

    def _is_rate_limited(self, channel_name: str) -> bool:
        return self._rate_counts.get(channel_name, 0) >= self._config.rate_limit_per_hour

    def _get_handler(self, channel: NotificationChannel) -> Any:
        from easm.config import NotificationChannelType
        if channel.type == NotificationChannelType.WEBHOOK:
            from easm.notifications.webhook_handler import handle_webhook
            return handle_webhook
        if channel.type == NotificationChannelType.SLACK:
            from easm.notifications.slack_handler import handle_slack
            return handle_slack
        if channel.type == NotificationChannelType.SMTP:
            from easm.notifications.smtp_handler import handle_smtp
            return handle_smtp
        # PagerDuty and other handlers can be added later
        return None

    def reset_hourly_counts(self) -> None:
        self._rate_counts.clear()


_dispatcher: NotificationDispatcher | None = None


def configure_notifications(config: NotificationConfig, base_url: str = "http://localhost:8000") -> None:
    global _dispatcher
    _dispatcher = NotificationDispatcher(config, base_url)


def get_dispatcher() -> NotificationDispatcher | None:
    return _dispatcher
