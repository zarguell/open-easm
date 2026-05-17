from __future__ import annotations

import logging
import uuid
from pathlib import Path

from easm.config import TargetConfig
from easm.runners.base import BaseRunner

logger = logging.getLogger(__name__)

SCREENSHOT_DIR = Path("data/screenshots")


class ScreenshotRunner(BaseRunner):
    source_name = "screenshot"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        cfg = self.get_runner_config(target)
        timeout = cfg.get("args", {}).get("timeout_seconds", 30)
        inserted = deduped = errors = 0

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.error("playwright not installed")
            return 0, 0, 1

        SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

        async with async_playwright() as p:
            browser = await p.chromium.launch()
            for domain in target.match_rules.domains:
                for scheme in ("https://", "http://"):
                    url = f"{scheme}{domain}"
                    try:
                        page = await browser.new_page()
                        await page.goto(
                            url, timeout=timeout * 1000,
                            wait_until="domcontentloaded",
                        )
                        filepath = SCREENSHOT_DIR / f"{domain}.png"
                        await page.screenshot(path=str(filepath), full_page=False)
                        await page.close()
                        raw = {
                            "hostname": domain, "url": url,
                            "screenshot_path": str(filepath),
                        }
                        result = await self.store.insert_raw_event(
                            target.org_id, target.id, self.source_name, raw, run_id,
                        )
                        if result:
                            inserted += 1
                        else:
                            deduped += 1
                    except Exception as e:
                        errors += 1
                        logger.debug("screenshot failed for %s: %s", url, e)
            await browser.close()
        return inserted, deduped, errors
