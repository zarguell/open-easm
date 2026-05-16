import dns.reversename
import dns.resolver
from easm.pivot.handlers.base import PivotHandler


class ReverseDnsHandler(PivotHandler):
    pivot_type = "reverse_dns"
    source_name = "reverse_dns"

    async def execute(self, job: dict, pool) -> list[dict]:
        ip_range = job["entity_value"]
        results = []
        try:
            import ipaddress
            network = ipaddress.ip_network(ip_range, strict=False)
            for ip in list(network.hosts())[:16]:
                try:
                    rev = dns.reversename.from_address(str(ip))
                    answers = dns.resolver.resolve(rev, "PTR")
                    for rdata in answers:
                        results.append({"ip": str(ip), "hostname": str(rdata.target)[:-1]})
                except Exception:
                    pass
        except ValueError:
            pass
        return results
