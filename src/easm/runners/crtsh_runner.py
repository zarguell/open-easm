import json
import logging
import uuid

import httpx

from easm.config import TargetConfig
from easm.runners.base import ApiRunner

logger = logging.getLogger(__name__)


class CrtShRunner(ApiRunner):
    source_name = "crtsh"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False
    is_api_runner = True

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        from easm.store import _compute_event_hash
        http = self._http_client or httpx.AsyncClient(timeout=30.0)
        inserted = deduped = errors = 0
        try:
            for domain in target.match_rules.domains:
                try:
                    resp = await http.get(f"https://crt.sh/?q=%.{domain}&output=json")
                    resp.raise_for_status()
                    certs = resp.json()
                    for cert in certs:
                        raw = {
                            "name_value": cert.get("name_value", ""),
                            "issuer_name_id": cert.get("issuer_name_id", ""),
                            "not_before": cert.get("not_before", ""),
                            "not_after": cert.get("not_after", ""),
                            "serial_number": cert.get("serial_number", ""),
                            "fingerprint": cert.get("fingerprint", ""),
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
                except Exception as e:
                    errors += 1
                    logger.warning("crtsh error", extra={"domain": domain, "target_id": target.id, "error": str(e)})
                    continue
        finally:
            if not self._http_client:
                await http.aclose()
        return inserted, deduped, errors
