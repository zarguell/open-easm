from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any
import uuid


@dataclass
class EntityCandidate:
    entity_type: str
    value: str
    attributes: dict[str, Any]


@dataclass
class RelationshipCandidate:
    source_type: str
    source_value: str
    target_type: str
    target_value: str
    relationship_type: str
    relationship_source: str
    evidence_raw_event_id: uuid.UUID | None = None
    runner: str | None = None


@dataclass
class ParseResult:
    entities: list[EntityCandidate]
    relationships: list[RelationshipCandidate]
    unparseable: bool = False
    parse_error: str | None = None


class BaseParser(ABC):
    source_name: str
    current_version: int = 1

    @property
    def parsed_by(self) -> str:
        return f"{self.source_name}:{self.current_version}"

    @abstractmethod
    async def parse(self, raw_event: dict[str, Any]) -> ParseResult:
        pass

