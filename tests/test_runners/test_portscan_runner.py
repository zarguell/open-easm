from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from easm.runners.portscan_runner import PortScanRunner


@pytest.mark.asyncio
async def test_portscan_runner_class_attributes():
    assert PortScanRunner.source_name == "portscan"
    assert PortScanRunner.supports_schedule is True
    assert PortScanRunner.supports_manual_trigger is True
    assert PortScanRunner.is_continuous is False


@pytest.mark.asyncio
async def test_portscan_runner_run_once_returns_tuple():
    mock_store = MagicMock()
    mock_store.insert_raw_event = AsyncMock(return_value=True)

    mock_target = MagicMock()
    mock_target.id = "test-target"
    mock_target.org_id = "default"
    mock_target.match_rules.domains = ["example.com"]
    mock_target.runners = {}

    nmap_output = (
        "# Nmap 7.94 scan initiated\n"
        "Host: 93.184.216.34 (1)\tPorts: 80/open/tcp//http//\tIgnored State: closed (99)\n"
        "Host: 93.184.216.34 (1)\tPorts: 443/open/tcp//https//\tIgnored State: closed (99)\n"
        "# Nmap done\n"
    )

    runner = PortScanRunner(store=mock_store)
    runner._exec_subprocess = AsyncMock(return_value=(True, nmap_output, ""))

    inserted, deduped, errors = await runner.run_once(
        mock_target, "manual", uuid.uuid4()
    )
    assert isinstance(inserted, int)
    assert isinstance(deduped, int)
    assert isinstance(errors, int)


@pytest.mark.asyncio
async def test_portscan_runner_handles_failure():
    mock_store = MagicMock()
    mock_target = MagicMock()
    mock_target.id = "test-target"
    mock_target.org_id = "default"
    mock_target.match_rules.domains = ["example.com"]
    mock_target.runners = {}

    runner = PortScanRunner(store=mock_store)
    runner._exec_subprocess = AsyncMock(return_value=(False, "", "nmap not found"))

    inserted, deduped, errors = await runner.run_once(
        mock_target, "manual", uuid.uuid4()
    )
    assert errors > 0
