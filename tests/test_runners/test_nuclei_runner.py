from __future__ import annotations

import json
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from easm.runners.nuclei_runner import NucleiRunner


@pytest.mark.asyncio
async def test_nuclei_runner_class_attributes():
    assert NucleiRunner.source_name == "nuclei"
    assert NucleiRunner.supports_schedule is True
    assert NucleiRunner.supports_manual_trigger is True
    assert NucleiRunner.is_continuous is False


@pytest.mark.asyncio
async def test_nuclei_runner_run_once_returns_tuple():
    mock_store = MagicMock()
    mock_store.insert_raw_event = AsyncMock(return_value=True)

    mock_target = MagicMock()
    mock_target.id = "test-target"
    mock_target.org_id = "default"
    mock_target.match_rules.domains = ["example.com"]
    mock_target.runners = {}

    nuclei_output = json.dumps({
        "template-id": "CVE-2023-1234",
        "info": {"name": "Test Vuln", "severity": "high"},
        "matched-at": "https://example.com/admin",
    })

    runner = NucleiRunner(store=mock_store)
    runner._exec_subprocess = AsyncMock(return_value=(True, nuclei_output, ""))

    inserted, deduped, errors = await runner.run_once(
        mock_target, "manual", uuid.uuid4()
    )
    assert isinstance(inserted, int)
    assert isinstance(deduped, int)
    assert isinstance(errors, int)
    assert inserted > 0


@pytest.mark.asyncio
async def test_nuclei_runner_handles_failure():
    mock_store = MagicMock()
    mock_target = MagicMock()
    mock_target.id = "test-target"
    mock_target.org_id = "default"
    mock_target.match_rules.domains = ["example.com"]
    mock_target.runners = {}

    runner = NucleiRunner(store=mock_store)
    runner._exec_subprocess = AsyncMock(return_value=(False, "", "nuclei not found"))

    inserted, deduped, errors = await runner.run_once(
        mock_target, "manual", uuid.uuid4()
    )
    assert errors > 0
