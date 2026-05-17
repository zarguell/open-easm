from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from easm.runners.wappalyzer_runner import WappalyzerRunner


@pytest.mark.asyncio
async def test_wappalyzer_runner_class_attributes():
    assert WappalyzerRunner.source_name == "wappalyzer"
    assert WappalyzerRunner.supports_schedule is True
    assert WappalyzerRunner.supports_manual_trigger is True
    assert WappalyzerRunner.is_continuous is False


@pytest.mark.asyncio
async def test_wappalyzer_runner_run_once_returns_tuple():
    mock_store = MagicMock()
    mock_store.insert_raw_event = AsyncMock(return_value=True)

    mock_target = MagicMock()
    mock_target.id = "test-target"
    mock_target.org_id = "default"
    mock_target.match_rules.domains = ["example.com"]
    mock_target.runners = {
        "wappalyzer": {"enabled": True, "args": {"timeout_seconds": 120}}
    }

    runner = WappalyzerRunner(store=mock_store)
    runner._exec_subprocess = AsyncMock(
        return_value=(True, '[{"name":"nginx","version":"1.24.0"}]', "")
    )

    inserted, deduped, errors = await runner.run_once(
        mock_target, "manual", uuid.uuid4()
    )
    assert isinstance(inserted, int)
    assert isinstance(deduped, int)
    assert isinstance(errors, int)


@pytest.mark.asyncio
async def test_wappalyzer_runner_handles_failure():
    mock_store = MagicMock()
    mock_store.insert_raw_event = AsyncMock(return_value=True)

    mock_target = MagicMock()
    mock_target.id = "test-target"
    mock_target.org_id = "default"
    mock_target.match_rules.domains = ["example.com"]
    mock_target.runners = {}

    runner = WappalyzerRunner(store=mock_store)
    runner._exec_subprocess = AsyncMock(return_value=(False, "", "error"))

    inserted, deduped, errors = await runner.run_once(
        mock_target, "manual", uuid.uuid4()
    )
    assert errors > 0
