import uuid
from easm.parse.base import BaseParser, ParseResult, EntityCandidate, RelationshipCandidate
from easm.entity_store import normalize_entity_value


class CrtShParser(BaseParser):
    source_name = "crtsh"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        all_names = set()
        name_value = raw.get("name_value", "")
        if name_value:
            for line in name_value.split("\n"):
                dns = line.strip()
                if dns:
                    all_names.add(dns)
        if not all_names:
            return ParseResult(entities=[], relationships=[], unparseable=True, parse_error="no name_value entries")
        entities = []
        relationships = []
        cert_value = raw.get("fingerprint", raw.get("serial_number", str(uuid.uuid4())))
        entities.append(EntityCandidate(
            entity_type="certificate",
            value=cert_value,
            attributes={
                "issuer_name_id": raw.get("issuer_name_id", ""),
                "not_before": raw.get("not_before", ""),
                "not_after": raw.get("not_after", ""),
                "source": "crtsh",
            },
        ))
        for name in all_names:
            normalized_name = normalize_entity_value("domain", name)
            entities.append(EntityCandidate(entity_type="domain", value=normalized_name, attributes={"source": "crtsh"}))
            relationships.append(RelationshipCandidate(
                source_type="certificate", source_value=cert_value,
                target_type="domain", target_value=normalized_name,
                relationship_type="issued_for",
                relationship_source="runner_direct",
                runner="crtsh",
            ))
            relationships.append(RelationshipCandidate(
                source_type="domain", source_value=normalized_name,
                target_type="certificate", target_value=cert_value,
                relationship_type="reverse_of",
                relationship_source="correlation",
            ))
        return ParseResult(entities=entities, relationships=relationships)
