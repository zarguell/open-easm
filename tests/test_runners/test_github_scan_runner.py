from __future__ import annotations

import uuid
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import httpx
import pytest

from easm.config import TargetConfig


@pytest.mark.asyncio
async def test_github_scan_class_attributes():
    from easm.runners.github_scan_runner import GithubScanRunner

    assert GithubScanRunner.source_name == "github_scan"
    assert GithubScanRunner.supports_schedule is True
    assert GithubScanRunner.supports_manual_trigger is True
    assert GithubScanRunner.is_continuous is False


@pytest.fixture
def target():
    return TargetConfig(
        id="test-target",
        name="Test",
        type="organization",
        match_rules={"domains": ["example.com"], "keywords": ["acme"]},
        runners={
            "github_scan": {
                "enabled": True,
                "schedule": "0 */4 * * *",
                "search_queries": ["credential_patterns", "domain_matches"],
            }
        },
    )


@pytest.fixture
def mock_store():
    store = MagicMock()
    store.pool = AsyncMock()
    store.insert_raw_event = AsyncMock(return_value=True)
    store.create_run = AsyncMock(return_value=uuid.uuid7())
    store.mark_run_started = AsyncMock()
    store.mark_run_finished = AsyncMock()
    store.get_run = AsyncMock(return_value={"discovery_session_id": str(uuid.uuid7())})
    return store


@pytest.mark.asyncio
async def test_github_scan_run_once_with_gitleaks(target, mock_store):
    from easm.runners.github_scan_runner import GithubScanRunner

    runner = GithubScanRunner(mock_store)
    runner._exec_subprocess = AsyncMock(return_value=(
        True,
        '[{"Repo":"example/repo","Line":42,"Commit":"abc123","File":"config.env","Secret":"fake","Match":"password=secret"}]',
        "",
    ))

    run_id = uuid.uuid7()
    inserted, deduped, errors = await runner.run_once(target, "scheduled", run_id)

    assert inserted >= 1
    runner._exec_subprocess.assert_called_once()
    args, kwargs = runner._exec_subprocess.call_args
    assert args[0][0] == "gitleaks"


@pytest.mark.asyncio
async def test_github_scan_run_once_gitleaks_not_found(target, mock_store):
    from easm.runners.github_scan_runner import GithubScanRunner

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json = lambda: {"items": []}
    mock_client.get = AsyncMock(return_value=mock_resp)

    runner = GithubScanRunner(mock_store, http_client=mock_client)
    runner._exec_subprocess = AsyncMock(return_value=(False, "", "binary not found: gitleaks"))

    run_id = uuid.uuid7()
    inserted, deduped, errors = await runner.run_once(target, "scheduled", run_id)

    assert inserted == 0
    assert errors == 0


@pytest.mark.asyncio
async def test_github_scan_run_once_github_search_api(target, mock_store):
    from easm.runners.github_scan_runner import GithubScanRunner

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json = lambda: {
        "items": [
            {
                "repository": {"full_name": "example/repo"},
                "path": "src/config.py",
                "html_url": "https://github.com/example/repo/src/config.py",
                "text_matches": [{"fragment": "acme password=secret"}],
            }
        ]
    }
    mock_client.get = AsyncMock(return_value=mock_resp)

    runner = GithubScanRunner(mock_store, http_client=mock_client)
    runner._exec_subprocess = AsyncMock(return_value=(False, "", "binary not found: gitleaks"))
    run_id = uuid.uuid7()
    inserted, deduped, errors = await runner.run_once(target, "scheduled", run_id)

    assert inserted >= 1
    assert errors == 0


@pytest.mark.asyncio
async def test_github_scan_runner_closes_http_client(target, mock_store):
    from easm.runners.github_scan_runner import GithubScanRunner

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    runner = GithubScanRunner(mock_store, http_client=mock_client)
    await runner.close()
    mock_client.aclose.assert_awaited_once()
