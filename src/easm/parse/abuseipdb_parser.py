from easm.entity_store import normalize_entity_value
from easm.parse.base import BaseParser, EntityCandidate, ParseResult


class AbuseIpDbParser(BaseParser):
    source_name = "abuseipdb"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        ip = raw.get("ip", "").strip()
        abuseipdb = raw.get("abuseipdb")
        if not ip or not abuseipdb:
            return ParseResult(
                entities=[], relationships=[], unparseable=True,
                parse_error="missing ip or abuseipdb data",
            )

        normalized_ip = normalize_entity_value("ip", ip)
        return ParseResult(
            entities=[
                EntityCandidate(
                    entity_type="ip",
                    value=normalized_ip,
                    attributes={
                        "source": "abuseipdb",
                        "threat_intel": {
                            "abuseipdb": {
                                "abuseConfidenceScore": abuseipdb.get("abuseConfidenceScore"),
                                "totalReports": abuseipdb.get("totalReports"),
                                "lastReportedAt": abuseipdb.get("lastReportedAt"),
                                "usageType": abuseipdb.get("usageType", ""),
                                "hostnames": abuseipdb.get("hostnames", []),
                                "domain": abuseipdb.get("domain", ""),
                                "countryCode": abuseipdb.get("countryCode", ""),
                                "isp": abuseipdb.get("isp", ""),
                            }
                        },
                    },
                ),
            ],
            relationships=[],
        )
