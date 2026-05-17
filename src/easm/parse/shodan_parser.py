from easm.entity_store import normalize_entity_value
from easm.parse.base import BaseParser, EntityCandidate, ParseResult


class ShodanParser(BaseParser):
    source_name = "shodan"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        ip = raw.get("ip", "").strip()
        if not ip:
            return ParseResult(entities=[], relationships=[], unparseable=True,
                              parse_error="missing ip")
        normalized = normalize_entity_value("ip", ip)
        shodan = raw.get("shodan", raw)
        return ParseResult(entities=[EntityCandidate(
            entity_type="ip", value=normalized,
            attributes={
                "source": "shodan",
                "ports": shodan.get("ports", []),
                "hostnames": shodan.get("hostnames", []),
                "domains": shodan.get("domains", []),
                "vulnerabilities": [v for v in shodan.get("vulns", []) if isinstance(v, str)],
                "org": shodan.get("org", ""),
                "isp": shodan.get("isp", ""),
                "asn": shodan.get("asn", ""),
                "country": shodan.get("country_name", ""),
                "city": shodan.get("city", ""),
                "os": shodan.get("os", ""),
                "services": shodan.get("data", []),
            },
        )], relationships=[])
