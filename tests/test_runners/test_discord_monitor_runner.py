from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from easm.config import TargetConfig


@pytest.mark.asyncio
async def test_discord_runner_returns_tuple_of_ints():
    from easm.runners.discord_monitor_runner import DiscordMonitorRunner

    store = MagicMock()
    store.insert_raw_event = AsyncMock(return_value=True)
    store.pool = AsyncMock()

    runner = DiscordMonitorRunner(store)
    target = TargetConfig(
        id="test-target",
        name="Test",
        type="organization",
        match_rules={"domains": ["example.com"], "keywords": ["acme"]},
        runners={"discord_monitor": {"enabled": True, "schedule": "*/15 * * * *", "args": {"timeout_seconds": 30}}},
    )
    inserted, deduped, errors = await runner.run_once(target, "scheduled", uuid.uuid7())
    assert isinstance(inserted, int)
    assert isinstance(deduped, int)
    assert isinstance(errors, int)


@pytest.mark.asyncio
async def test_discord_runner_source_name():
    from easm.runners.discord_monitor_runner import DiscordMonitorRunner

    assert DiscordMonitorRunner.source_name == "discord_monitor"


@pytest.mark.asyncio
async def test_discord_runner_class_attributes():
    from easm.runners.discord_monitor_runner import DiscordMonitorRunner

    assert DiscordMonitorRunner.supports_schedule is True
    assert DiscordMonitorRunner.supports_manual_trigger is True
    assert DiscordMonitorRunner.is_continuous is False
