from easm.entity_store import normalize_entity_value
from easm.parse.base import BaseParser, EntityCandidate, ParseResult


class PortScanParser(BaseParser):
    source_name = "portscan"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        hostname = raw.get("hostname", "").strip()
        ip = raw.get("ip", "").strip()
        ports = raw.get("ports", [])
        if not hostname:
            return ParseResult(
                entities=[], relationships=[], unparseable=True,
                parse_error="missing hostname",
            )
        if not ports:
            return ParseResult(
                entities=[], relationships=[], unparseable=True,
                parse_error="no open ports",
            )
        entities = []
        normalized_hostname = normalize_entity_value("hostname", hostname)
        entities.append(EntityCandidate(
            entity_type="hostname", value=normalized_hostname,
            attributes={"source": "portscan", "open_ports": ports},
        ))
        if ip:
            normalized_ip = normalize_entity_value("ip", ip)
            entities.append(EntityCandidate(
                entity_type="ip", value=normalized_ip,
                attributes={"source": "portscan", "open_ports": ports},
            ))
        return ParseResult(entities=entities, relationships=[])
