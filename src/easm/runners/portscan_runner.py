from __future__ import annotations

import logging
import re
import uuid

from easm.config import TargetConfig
from easm.runners.base import BaseRunner

logger = logging.getLogger(__name__)

DEFAULT_PORTS = "22,80,443,8080,8443,3389,3306,5432,6379,27017"


class PortScanRunner(BaseRunner):
    source_name = "portscan"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        cfg = self.get_runner_config(target)
        timeout = cfg.get("args", {}).get("timeout_seconds", 600)
        ports = cfg.get("args", {}).get("ports", DEFAULT_PORTS)
        profile = cfg.get("args", {}).get("profile", "quick")
        port_arg = ports if profile == "custom" else DEFAULT_PORTS
        inserted = deduped = errors = 0

        for domain in target.match_rules.domains:
            cmd = ["nmap", "-sV", "-p", port_arg, "--open", "-oG", "-", domain]
            ok, stdout, stderr = await self._exec_subprocess(cmd, timeout=timeout)
            if not ok:
                errors += 1
                logger.warning(
                    "nmap failed",
                    extra={"domain": domain, "stderr": stderr[:200] if stderr else ""},
                )
                continue

            for line in stdout.split("\n"):
                if not line.startswith("Host:") or "Ports:" not in line:
                    continue
                # Parse grepable nmap output
                parts = line.split("\t")
                host = parts[0].replace("Host: ", "").strip()
                # Remove (status) suffix like " (1)"
                if " (" in host:
                    host = host.split(" (")[0].strip()
                ports_str = parts[1].replace("Ports: ", "").strip() if len(parts) > 1 else ""
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
                    raw = {"hostname": domain, "ip": host, "ports": open_ports}
                    result = await self.store.insert_raw_event(
                        target.org_id, target.id, self.source_name, raw, run_id,
                    )
                    if result:
                        inserted += 1
                    else:
                        deduped += 1
        return inserted, deduped, errors
