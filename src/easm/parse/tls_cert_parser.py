from easm.parse.base import BaseParser, ParseResult, EntityCandidate, RelationshipCandidate
from easm.entity_store import normalize_entity_value


class TlsCertParser(BaseParser):
    source_name = "tls_cert"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        hostname = raw.get("hostname", "").strip()
        cert_data = raw.get("cert")
        if not hostname or not cert_data:
            return ParseResult(entities=[], relationships=[], unparseable=True,
                               parse_error="missing hostname or cert data")

        cert_value = cert_data.get("fingerprint_sha256", cert_data.get("serial_number", ""))
        if not cert_value:
            return ParseResult(entities=[], relationships=[], unparseable=True,
                               parse_error="no cert fingerprint or serial")

        normalized_hostname = normalize_entity_value("hostname", hostname)
        san_names = cert_data.get("san_dns_names", [])

        entities: list[EntityCandidate] = []
        relationships: list[RelationshipCandidate] = []

        cert_attrs: dict = {
            "source": "tls_cert",
            "subject_cn": cert_data.get("subject_cn", ""),
            "issuer_cn": cert_data.get("issuer_cn", ""),
            "issuer_org": cert_data.get("issuer_org", ""),
            "serial_number": cert_data.get("serial_number", ""),
            "not_before": cert_data.get("not_before", ""),
            "not_after": cert_data.get("not_after", ""),
            "fingerprint_sha256": cert_data.get("fingerprint_sha256", ""),
            "san_dns_names": san_names,
            "grabbed_from": normalized_hostname,
        }
        entities.append(EntityCandidate(
            entity_type="certificate",
            value=cert_value,
            attributes=cert_attrs,
        ))

        relationships.append(RelationshipCandidate(
            source_type="hostname",
            source_value=normalized_hostname,
            target_type="certificate",
            target_value=cert_value,
            relationship_type="issued_for",
            relationship_source="pivot",
            runner="tls_cert",
        ))

        for san in san_names:
            normalized_san = normalize_entity_value("domain", san)
            entities.append(EntityCandidate(
                entity_type="domain",
                value=normalized_san,
                attributes={"source": "tls_cert"},
            ))
            relationships.append(RelationshipCandidate(
                source_type="certificate",
                source_value=cert_value,
                target_type="domain",
                target_value=normalized_san,
                relationship_type="san_contains",
                relationship_source="pivot",
                runner="tls_cert",
            ))
            relationships.append(RelationshipCandidate(
                source_type="domain",
                source_value=normalized_san,
                target_type="certificate",
                target_value=cert_value,
                relationship_type="reverse_of",
                relationship_source="correlation",
            ))

        return ParseResult(entities=entities, relationships=relationships)
