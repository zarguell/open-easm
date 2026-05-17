from __future__ import annotations

from easm.parse.base import BaseParser, EntityCandidate, ParseResult


class BreachMonitorParser(BaseParser):
    source_name = "breach_monitor"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        source = raw.get("source", "")

        if not source:
            return ParseResult(
                entities=[], relationships=[],
                unparseable=True, parse_error="no source",
            )

        entities: list[EntityCandidate] = []

        if source == "hibp":
            breach_name = raw.get("breach_name", "")
            email = raw.get("email", "")
            if not breach_name or not email:
                return ParseResult(
                    entities=[], relationships=[],
                    unparseable=True,
                    parse_error="missing breach name or email",
                )

            finding_id = f"hibp-{email}-{breach_name}"
            entities.append(EntityCandidate(
                entity_type="finding",
                value=finding_id,
                attributes={
                    "source": "hibp",
                    "breach_name": breach_name,
                    "breach_date": raw.get("breach_date", ""),
                    "compromised_email": email,
                    "data_classes": raw.get("data_classes", []),
                    "domain": raw.get("domain", ""),
                    "description": raw.get("description", ""),
                    "severity": "high",
                    "source_type": "breach_monitor",
                },
            ))

        elif source == "dehashed":
            email = raw.get("email", "")
            if not email:
                return ParseResult(
                    entities=[], relationships=[],
                    unparseable=True,
                    parse_error="dehashed entry without email",
                )

            finding_id = f"dehashed-{email}-{raw.get('database_name', 'unknown')}"
            entities.append(EntityCandidate(
                entity_type="finding",
                value=finding_id,
                attributes={
                    "source": "dehashed",
                    "compromised_email": email,
                    "password": raw.get("password", ""),
                    "hashed_password": raw.get("hashed_password", ""),
                    "username": raw.get("username", ""),
                    "database_name": raw.get("database_name", ""),
                    "ip_address": raw.get("ip_address", ""),
                    "name": raw.get("name", ""),
                    "severity": "critical",
                    "source_type": "breach_monitor",
                },
            ))

        else:
            return ParseResult(
                entities=[], relationships=[],
                unparseable=True,
                parse_error=f"unknown source: {source}",
            )

        return ParseResult(entities=entities, relationships=[])
