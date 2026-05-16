from __future__ import annotations

import enum


class TriggerType(str, enum.Enum):
    SCHEDULED = "scheduled"
    MANUAL = "manual"
    STREAM = "stream"


class RunStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class EntityType(str, enum.Enum):
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    IP = "ip"
    IP_RANGE = "ip_range"
    CERTIFICATE = "certificate"
    ASN = "asn"
    ORG = "org"


class RelationshipType(str, enum.Enum):
    OWNS = "owns"
    RESOLVES_TO = "resolves_to"
    ISSUED_FOR = "issued_for"
    SAN_CONTAINS = "san_contains"
    LOOKALIKE_OF = "lookalike_of"
    REVERSE_OF = "reverse_of"


class RelationshipSource(str, enum.Enum):
    RUNNER_DIRECT = "runner_direct"
    CORRELATION = "correlation"
    PIVOT = "pivot"


class ScopeResult(str, enum.Enum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    UNKNOWN = "unknown"
