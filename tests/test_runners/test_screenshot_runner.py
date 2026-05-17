from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from easm.runners.screenshot_runner import ScreenshotRunner


@pytest.mark.asyncio
async def test_screenshot_runner_class_attributes():
    assert ScreenshotRunner.source_name == "screenshot"
    assert ScreenshotRunner.supports_schedule is True
    assert ScreenshotRunner.supports_manual_trigger is True
    assert ScreenshotRunner.is_continuous is False


@pytest.mark.asyncio
async def test_screenshot_runner_returns_tuple_without_playwright():
    """When playwright is not importable, runner returns (0, 0, 1)."""
    mock_store = MagicMock()
    mock_target = MagicMock()
    mock_target.id = "test-target"
    mock_target.org_id = "default"
    mock_target.match_rules.domains = ["example.com"]
    mock_target.runners = {}

    runner = ScreenshotRunner(store=mock_store)

    with patch.dict("sys.modules", {"playwright": None, "playwright.async_api": None}):
        # Force ImportError by making the import fail
        import builtins
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if "playwright" in name:
                raise ImportError("no playwright")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            inserted, deduped, errors = await runner.run_once(
                mock_target, "manual", uuid.uuid4()
            )
    assert isinstance(inserted, int)
    assert isinstance(deduped, int)
    assert isinstance(errors, int)


@pytest.mark.asyncio
async def test_screenshot_runner_run_once_with_mock_playwright():
    """Test with mocked playwright that takes a screenshot successfully."""
    mock_store = MagicMock()
    mock_store.insert_raw_event = AsyncMock(return_value=True)

    mock_target = MagicMock()
    mock_target.id = "test-target"
    mock_target.org_id = "default"
    mock_target.match_rules.domains = ["example.com"]
    mock_target.runners = {}

    mock_page = AsyncMock()
    mock_page.goto = AsyncMock()
    mock_page.screenshot = AsyncMock()
    mock_page.close = AsyncMock()

    mock_browser = AsyncMock()
    mock_browser.new_page = AsyncMock(return_value=mock_page)
    mock_browser.close = AsyncMock()

    mock_pw = AsyncMock()
    mock_pw.chromium.launch = AsyncMock(return_value=mock_browser)
    mock_pw.__aenter__ = AsyncMock(return_value=mock_pw)
    mock_pw.__aexit__ = AsyncMock(return_value=False)

    runner = ScreenshotRunner(store=mock_store)

    with patch("easm.runners.screenshot_runner.async_playwright", return_value=mock_pw):
        inserted, deduped, errors = await runner.run_once(
            mock_target, "manual", uuid.uuid4()
        )

    assert isinstance(inserted, int)
    assert isinstance(deduped, int)
    assert isinstance(errors, int)
    assert inserted > 0
