from easm.geoip import GeoIpLookup
from easm.pivot.handlers.base import PivotHandler


class GeoIpEnrichHandler(PivotHandler):
    pivot_type = "geoip_enrich"
    source_name = "geoip"

    def __init__(self, geoip_lookup: GeoIpLookup | None = None):
        self._lookup = geoip_lookup or GeoIpLookup()

    async def execute(self, job: dict, pool) -> list[dict]:
        ip = job["entity_value"]
        result = self._lookup.lookup(ip)
        if result is None:
            return [{"ip": ip, "message": "no geo-IP data available"}]
        return [{"ip": ip, "geo": result.to_dict()}]
