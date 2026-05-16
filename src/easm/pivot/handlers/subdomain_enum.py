import asyncio
import json
from easm.pivot.handlers.base import PivotHandler


class SubdomainEnumHandler(PivotHandler):
    pivot_type = "subdomain_enum"
    source_name = "subfinder"

    async def execute(self, job: dict, pool) -> list[dict]:
        domain = job["entity_value"]
        results = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "subfinder", "-d", domain, "-json", "-silent", "-nW", "-all",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            for line in stdout.decode().strip().split("\n"):
                if line:
                    try:
                        parsed = json.loads(line)
                        results.append(parsed)
                    except json.JSONDecodeError:
                        pass
        except FileNotFoundError:
            pass
        except Exception:
            pass
        return results
