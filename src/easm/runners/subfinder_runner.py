from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any

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
        cfg: dict[str, Any] = {}
        runner_raw = target.runners.get("subfinder", {})
        if isinstance(runner_raw, dict):
            cfg = runner_raw
        elif hasattr(runner_raw, "model_dump"):
            cfg = runner_raw.model_dump()

        args_cfg = cfg.get("args", {})
        timeout = args_cfg.get("timeout_seconds", 300)
        passive_only = args_cfg.get("passive_only", True)
        recursive = args_cfg.get("recursive", False)

        inserted = 0
        deduped = 0
        errors = 0

        for domain in target.match_rules.domains:
            cmd = ["subfinder", "-d", domain, "-json", "-silent"]
            if passive_only:
                cmd.extend(["-s", "crtsh,alienvault,urlscan"])  # subset of fast passive sources
            if recursive:
                cmd.append("-recursive")

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(), timeout=timeout
                    )
                except TimeoutError:
                    proc.kill()
                    await proc.wait()
                    errors += 1
                    logger.warning(
                        "subfinder timeout",
                        extra={"domain": domain, "target_id": target.id},
                    )
                    continue

                if proc.returncode != 0:
                    errors += 1
                    stderr_str = stderr.decode(errors="replace")[:500] if stderr else ""
                    logger.warning(
                        "subfinder non-zero exit",
                        extra={
                            "domain": domain,
                            "target_id": target.id,
                            "returncode": proc.returncode,
                            "stderr": stderr_str,
                        },
                    )
                    continue

                for line in stdout.decode().strip().split("\n"):
                    if not line:
                        continue
                    try:
                        parsed = json.loads(line)
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
                logger.error("subfinder binary not found in PATH")
                break
            except Exception as e:
                errors += 1
                logger.error(
                    "subfinder error",
                    extra={"domain": domain, "target_id": target.id, "error": str(e)},
                )

        return inserted, deduped, errors
