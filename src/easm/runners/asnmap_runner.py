from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any

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
        cfg: dict[str, Any] = {}
        runner_raw = target.runners.get("asnmap", {})
        if isinstance(runner_raw, dict):
            cfg = runner_raw
        elif hasattr(runner_raw, "model_dump"):
            cfg = runner_raw.model_dump()

        args_cfg = cfg.get("args", {})
        timeout = args_cfg.get("timeout_seconds", 300)
        expand_org_names = args_cfg.get("expand_org_names", False)

        inserted = 0
        deduped = 0
        errors = 0

        for asn in target.match_rules.asns:
            cmd = ["asnmap", "-a", asn, "-json"]
            if expand_org_names:
                cmd.append("-org")

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                except TimeoutError:
                    proc.kill()
                    await proc.wait()
                    errors += 1
                    logger.warning("asnmap timeout", extra={"asn": asn, "target_id": target.id})
                    continue

                if proc.returncode != 0:
                    errors += 1
                    stderr_str = stderr.decode(errors="replace")[:500] if stderr else ""
                    logger.warning(
                        "asnmap non-zero exit",
                        extra={
                            "asn": asn,
                            "target_id": target.id,
                            "returncode": proc.returncode,
                            "stderr": stderr_str,
                        },
                    )
                    continue

                try:
                    parsed = json.loads(stdout.decode().strip())
                    ok = await self.store.insert_raw_event(
                        target.id, self.source_name, parsed, run_id
                    )
                    if ok:
                        inserted += 1
                    else:
                        deduped += 1
                except json.JSONDecodeError:
                    errors += 1

            except FileNotFoundError:
                errors += 1
                logger.error("asnmap binary not found in PATH")
                break
            except Exception as e:
                errors += 1
                logger.error(
                    "asnmap error",
                    extra={"asn": asn, "target_id": target.id, "error": str(e)},
                )

        return inserted, deduped, errors
