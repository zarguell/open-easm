from __future__ import annotations

import json
import logging
import uuid

from easm.config import TargetConfig
from easm.runners.base import BaseRunner

logger = logging.getLogger(__name__)


class WappalyzerRunner(BaseRunner):
    source_name = "wappalyzer"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        cfg = self.get_runner_config(target)
        timeout = cfg.get("args", {}).get("timeout_seconds", 120)
        inserted = deduped = errors = 0

        for domain in target.match_rules.domains:
            for scheme in ("https://", "http://"):
                url = f"{scheme}{domain}"
                cmd = ["wappalyzer", url]
                ok, stdout, stderr = await self._exec_subprocess(cmd, timeout=timeout)
                if not ok:
                    errors += 1
                    logger.warning(
                        "wappalyzer failed",
                        extra={"url": url, "stderr": stderr[:200] if stderr else ""},
                    )
                    continue
                try:
                    techs = json.loads(stdout)
                    raw = {"hostname": domain, "url": url, "technologies": techs}
                    result = await self.store.insert_raw_event(
                        target.org_id, target.id, self.source_name, raw, run_id
                    )
                    if result:
                        inserted += 1
                    else:
                        deduped += 1
                except json.JSONDecodeError:
                    errors += 1
        return inserted, deduped, errors
