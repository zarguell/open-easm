from __future__ import annotations

import logging
import re
import uuid

import asyncpg

from easm.config import TargetConfig
from easm.network_guard import resolve_and_validate
from easm.runners.base import BaseRunner

logger = logging.getLogger(__name__)

DEFAULT_PORTS = "22,80,443,8080,8443,3389,3306,5432,6379,27017"


class PortScanRunner(BaseRunner):
    source_name = "portscan"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    async def _get_scan_targets(self, target: TargetConfig) -> list[str]:
        """Get targets to scan: configured domains + discovered hostnames."""
        targets = list(target.match_rules.domains)

        if self.store and hasattr(self.store, "pool") and self.store.pool:
            try:
                rows = await self.store.pool.fetch(
                    "SELECT entity_value FROM entities "
                    "WHERE target_id = $1 AND entity_type = 'hostname' "
                    "ORDER BY last_seen_at DESC",
                    target.id,
                )
                existing = set(target.match_rules.domains)
                for row in rows:
                    hostname = row["entity_value"]
                    if hostname not in existing:
                        targets.append(hostname)
            except (asyncpg.PostgresError, KeyError) as e:
                logger.debug(
                    "failed to query hostnames for portscan",
                    exc_info=True, extra={"target_id": target.id, "error": str(e)},
                )

        return targets

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        cfg = self.get_runner_config(target)
        timeout = cfg.get("args", {}).get("timeout_seconds", 600)
        ports = cfg.get("args", {}).get("ports", DEFAULT_PORTS)
        profile = cfg.get("args", {}).get("profile", "quick")
        port_arg = ports if profile == "custom" else DEFAULT_PORTS
        inserted = deduped = errors = 0

        scan_targets = await self._get_scan_targets(target)
        self._log(f"[portscan] scanning {len(scan_targets)} target(s)")

        for hostname in scan_targets:
            guard = resolve_and_validate(hostname)
            if not guard.safe:
                self._log(
                    f"[portscan] skipping {hostname}: {guard.reason}"
                )
                logger.warning(
                    "portscan blocked by network guard",
                    extra={"hostname": hostname, "reason": guard.reason},
                )
                continue

            cmd = [
                "nmap", "-Pn", "-sV", "-p", port_arg,
                "--open", "-oG", "-", hostname,
            ]
            self._log(f"[portscan] running: {' '.join(cmd)}")
            ok, stdout, stderr = await self._exec_subprocess(cmd, timeout=timeout)
            if not ok:
                errors += 1
                self._log(
                    f"[portscan] failed for {hostname}: "
                    f"{stderr[:200] if stderr else ''}"
                )
                logger.warning(
                    "nmap failed",
                    extra={
                        "hostname": hostname,
                        "stderr": stderr[:200] if stderr else "",
                    },
                )
                continue

            for line in stdout.split("\n"):
                if not line.startswith("Host:") or "Ports:" not in line:
                    continue
                parts = line.split("\t")
                host = parts[0].replace("Host: ", "").strip()
                if " (" in host:
                    host = host.split(" (")[0].strip()
                ports_str = (
                    parts[1].replace("Ports: ", "").strip()
                    if len(parts) > 1 else ""
                )
                open_ports = []
                for p in ports_str.split(", "):
                    if not p:
                        continue
                    m = re.match(r"(\d+)/open/(\w+)///(.*?)/", p)
                    if not m:
                        m = re.match(r"(\d+)/open/(\w+)///(.*)", p)
                    if m:
                        open_ports.append({
                            "port": int(m.group(1)),
                            "protocol": m.group(2),
                            "service": m.group(3).strip(),
                        })
                if open_ports:
                    raw = {"hostname": hostname, "ip": host, "ports": open_ports}
                    result = await self.store.insert_raw_event(
                        target.org_id, target.id, self.source_name, raw, run_id,
                    )
                    if result:
                        inserted += 1
                    else:
                        deduped += 1
        return inserted, deduped, errors
