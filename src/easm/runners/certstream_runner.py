from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any

import websockets

from easm.config import TargetConfig
from easm.runners.base import BaseRunner

logger = logging.getLogger(__name__)

CERTSTREAM_URL = "wss://certstream.calidog.io"


class CertStreamRunner(BaseRunner):
    source_name = "certstream"
    supports_schedule = False
    supports_manual_trigger = False
    is_continuous = True

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        cfg: dict[str, Any] = {}
        runner_raw = target.runners.get("certstream", {})
        if isinstance(runner_raw, dict):
            cfg = runner_raw
        elif hasattr(runner_raw, "model_dump"):
            cfg = runner_raw.model_dump()

        filters = cfg.get("filters", {})
        match_mode = filters.get("match_mode", "suffix")
        include_cn = filters.get("include_common_name", True)
        include_san = filters.get("include_san_dns_names", True)

        inserted = 0
        deduped = 0
        errors = 0
        backoff = 1.0

        while True:
            try:
                async with websockets.connect(CERTSTREAM_URL, ping_interval=None, open_timeout=15) as ws:
                    backoff = 1.0
                    logger.info("certstream connected", extra={"target_id": target.id})

                    async for raw_msg in ws:
                        try:
                            msg = json.loads(raw_msg)
                        except json.JSONDecodeError:
                            continue

                        if msg.get("message_type") != "certificate_update":
                            continue

                        data = msg.get("data", {})
                        if self._matches_target(data, target, match_mode, include_cn, include_san):
                            ok = await self.store.insert_raw_event(
                                target.id, self.source_name, {"cert_data": data}, run_id
                            )
                            if ok:
                                inserted += 1
                            else:
                                deduped += 1

            except (websockets.ConnectionClosed, OSError, TimeoutError) as e:
                logger.warning(
                    "certstream disconnected, reconnecting",
                    extra={"target_id": target.id, "backoff_s": backoff, "error": str(e)},
                )
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60.0)
            except Exception as e:
                logger.exception(
                    "certstream unexpected error",
                    extra={"target_id": target.id, "error": str(e)},
                )
                errors += 1
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60.0)

    def _matches_target(
        self, data: dict[str, Any], target: TargetConfig,
        match_mode: str, include_cn: bool, include_san: bool,
    ) -> bool:
        data_leaf = data.get("leaf_cert", {}) if "leaf_cert" in data else (
            data.get("chain", [None]) or [None]
        )[0]
        if not isinstance(data_leaf, dict):
            return False

        subject = data_leaf.get("subject", {})
        cn = subject.get("CN", "")

        san_dns: list[str] = []
        alt_names: list[str] = []
        ext = data_leaf.get("extensions")
        if isinstance(ext, dict):
            raw_san = ext.get("subjectAltName", "")
            alt_names = raw_san.split(", ") if raw_san else []
        for alt in alt_names:
            if alt.startswith("DNS:"):
                san_dns.append(alt[4:])

        domains_to_check: list[str] = []
        if include_cn and cn:
            domains_to_check.append(cn)
        if include_san:
            domains_to_check.extend(san_dns)

        return any(
            self._domain_matches(domain, target, match_mode)
            for domain in domains_to_check
        )

    def _domain_matches(self, domain: str, target: TargetConfig, match_mode: str) -> bool:
        domain_lower = domain.lower()
        for cfg_domain in target.match_rules.domains:
            cfg_lower = cfg_domain.lower()
            if match_mode == "suffix":
                if domain_lower == cfg_lower or domain_lower.endswith(f".{cfg_lower}"):
                    return True
            elif match_mode == "exact" and domain_lower == cfg_lower:
                return True
        return False
