from __future__ import annotations

import logging
import uuid

import httpx

from easm.config import TargetConfig
from easm.keyword_engine import KeywordEngine
from easm.runners.base import ApiRunner

logger = logging.getLogger(__name__)

GITHUB_GISTS_PUBLIC_URL = "https://api.github.com/gists/public"


class GistMonitorRunner(ApiRunner):
    source_name = "gist_monitor"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        cfg = self.get_runner_config(target)
        args = cfg.get("args", {})
        timeout = args.get("timeout_seconds", 60)
        github_token = args.get("github_token", "")

        http = self._http_client or httpx.AsyncClient(timeout=float(timeout))
        inserted = deduped = errors = 0

        kw_engine = KeywordEngine(target)

        try:
            headers = {}
            if github_token:
                headers["Authorization"] = f"token {github_token}"

            try:
                resp = await http.get(
                    f"{GITHUB_GISTS_PUBLIC_URL}?per_page=100",
                    headers=headers,
                )
                if resp.status_code != 200:
                    logger.warning("GitHub gists API returned %d", resp.status_code)
                    return 0, 0, 0
                gists = resp.json()
            except Exception as e:
                logger.warning("GitHub gists fetch failed: %s", e)
                return 0, 0, 1

            for gist in gists:
                try:
                    gist_id = gist.get("id", "")
                    gist_url = gist.get("html_url", "")

                    combined_text = ""
                    files = gist.get("files", {})
                    for fname, fdata in files.items():
                        content = fdata.get("content", "")
                        if content:
                            combined_text += content + "\n"

                    if not combined_text:
                        continue

                    matches = kw_engine.match(combined_text)
                    if not matches:
                        continue

                    max_severity = "low"
                    for m in matches:
                        if m.severity == "high":
                            max_severity = "high"
                        elif m.severity == "medium" and max_severity != "high":
                            max_severity = "medium"

                    raw = {
                        "gist_id": gist_id,
                        "gist_url": gist_url,
                        "filename": ",".join(files.keys()),
                        "matches": [
                            {
                                "keyword": m.keyword,
                                "match_type": m.match_type,
                                "severity": m.severity,
                            }
                            for m in matches
                        ],
                        "severity": max_severity,
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
                    logger.warning("gist processing error: %s", e)
        finally:
            if not self._http_client:
                await http.aclose()

        return inserted, deduped, errors
