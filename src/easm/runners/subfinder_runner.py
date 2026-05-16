from __future__ import annotations

import json
import logging
import uuid

from easm.config import TargetConfig
from easm.runners.base import BaseRunner

logger = logging.getLogger(__name__)


class SubfinderRunner(BaseRunner):
    source_name = "subfinder"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        cfg = self.get_runner_config(target)
        args_cfg = cfg.get("args", {})
        timeout = args_cfg.get("timeout_seconds", 300)
        recursive = args_cfg.get("recursive", False)
        inserted = deduped = errors = 0

        for domain in target.match_rules.domains:
            cmd = ["subfinder", "-d", domain, "-json", "-silent", "-nW", "-all"]
            if recursive:
                cmd.append("-recursive")

            ok, stdout, stderr = await self._exec_subprocess(cmd, timeout=timeout)
            if not ok:
                errors += 1
                logger.warning(
                    "subfinder error",
                    extra={
                        "domain": domain,
                        "target_id": target.id,
                        "stderr": stderr[:200] if stderr else "",
                    },
                )
                continue

            for line in stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                    result = await self.store.insert_raw_event(
                        target.org_id, target.id, self.source_name, parsed, run_id,
                    )
                    if result:
                        inserted += 1
                    else:
                        deduped += 1
                except json.JSONDecodeError:
                    errors += 1

        return inserted, deduped, errors
