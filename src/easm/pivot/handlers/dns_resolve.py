import dns.resolver
from easm.pivot.handlers.base import PivotHandler


class DnsResolveHandler(PivotHandler):
    pivot_type = "dns_resolve"
    source_name = "dns"

    async def execute(self, job: dict, pool) -> list[dict]:
        hostname = job["entity_value"]
        results = []
        try:
            answers = dns.resolver.resolve(hostname, "A")
            for rdata in answers:
                results.append({"hostname": hostname, "ip": str(rdata), "record_type": "A"})
        except dns.resolver.NXDOMAIN:
            pass
        except Exception:
            pass
        return results
