from __future__ import annotations

import json
import logging
import uuid

from easm.config import TargetConfig
from easm.runners.base import BaseRunner

logger = logging.getLogger(__name__)


class AsnmapRunner(BaseRunner):
    source_name = "asnmap"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        cfg = self.get_runner_config(target)
        timeout = cfg.get("args", {}).get("timeout_seconds", 300)
        inserted = deduped = errors = 0

        for asn in target.match_rules.asns:
            cmd = ["asnmap", "-a", asn, "-json"]

            ok, stdout, stderr = await self._exec_subprocess(cmd, timeout=timeout)
            if not ok:
                errors += 1
                logger.warning(
                    "asnmap error",
                    extra={
                        "asn": asn,
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
                        target.id, self.source_name, parsed, run_id,
                    )
                    if result:
                        inserted += 1
                    else:
                        deduped += 1
                except json.JSONDecodeError:
                    errors += 1

        return inserted, deduped, errors
