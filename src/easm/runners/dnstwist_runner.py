import asyncio
import json
import logging
import uuid

from easm.config import TargetConfig
from easm.runners.base import BaseRunner

logger = logging.getLogger(__name__)


class DnstwistRunner(BaseRunner):
    source_name = "dnstwist"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        from easm.store import _compute_event_hash
        inserted = deduped = errors = 0

        for domain in target.match_rules.domains:
            cmd = ["dnstwist", "--format=json", domain]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            except FileNotFoundError:
                errors += 1
                logger.warning("dnstwist binary not found")
                continue
            except asyncio.TimeoutError:
                errors += 1
                logger.warning("dnstwist timeout", extra={"domain": domain})
                continue

            for line in stdout.decode().strip().split("\n"):
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                    raw = {
                        "domain": parsed.get("domain", ""),
                        "original_domain": domain,
                        "type": parsed.get("fuzzer", ""),
                        "dns": parsed.get("dns", {}),
                        "registered": parsed.get("registered", False),
                    }
                    event_hash = _compute_event_hash(target.org_id, target.id, self.source_name, raw)
                    result = await self.store.pool.execute(
                        """INSERT INTO raw_events (org_id, target_id, source, raw, event_hash, run_id)
                           VALUES ($1, $2, $3, $4::jsonb, $5, $6)
                           ON CONFLICT (event_hash) DO NOTHING""",
                        target.org_id, target.id, self.source_name,
                        json.dumps(raw), event_hash, run_id,
                    )
                    if result == "INSERT 0 0":
                        deduped += 1
                    else:
                        inserted += 1
                except json.JSONDecodeError:
                    errors += 1

        return inserted, deduped, errors
