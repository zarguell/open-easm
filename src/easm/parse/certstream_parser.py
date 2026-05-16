import uuid
from easm.parse.base import BaseParser, ParseResult, EntityCandidate, RelationshipCandidate
from easm.entity_store import normalize_entity_value


class CertStreamParser(BaseParser):
    source_name = "certstream"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        cert_data = raw.get("cert_data", {})
        all_names = set()
        cn = cert_data.get("subject", {}).get("CN", "")
        if cn:
            all_names.add(cn)
        san_ext = cert_data.get("extensions", {}).get("subjectAltName", {})
        for name_type, names in san_ext.items():
            if name_type in ("dnsNames", "DNS"):
                all_names.update(names)
        if not all_names:
            return ParseResult(entities=[], relationships=[], unparseable=True, parse_error="no CN or SANs")
        entities = []
        relationships = []
        cert_value = raw.get("fingerprint", raw.get("serial_number", str(uuid.uuid4())))
        entities.append(EntityCandidate(
            entity_type="certificate",
            value=cert_value,
            attributes={
                "subject": cert_data.get("subject", {}),
                "issuer": cert_data.get("issuer", {}),
                "not_before": cert_data.get("not_before"),
                "not_after": cert_data.get("not_after"),
                "source": "certstream",
            },
        ))
        for name in all_names:
            normalized_name = normalize_entity_value("domain", name)
            entities.append(EntityCandidate(entity_type="domain", value=normalized_name, attributes={"source": "certstream"}))
            relationships.append(RelationshipCandidate(
                source_type="certificate", source_value=cert_value,
                target_type="domain", target_value=normalized_name,
                relationship_type="issued_for",
                relationship_source="runner_direct",
                runner="certstream",
            ))
            relationships.append(RelationshipCandidate(
                source_type="domain", source_value=normalized_name,
                target_type="certificate", target_value=cert_value,
                relationship_type="reverse_of",
                relationship_source="correlation",
            ))
        return ParseResult(entities=entities, relationships=relationships)
