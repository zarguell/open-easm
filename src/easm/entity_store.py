from __future__ import annotations

import hashlib

from easm.models import EntityType


def normalize_entity_value(entity_type: str, value: str) -> str:
    if entity_type == EntityType.DOMAIN.value:
        return value.lower().rstrip(".").strip()
    if entity_type == EntityType.HOSTNAME.value:
        return value.lower().rstrip(".").strip()
    if entity_type == EntityType.IP.value:
        return value.strip()
    if entity_type == EntityType.IP_RANGE.value:
        return value.strip()
    if entity_type == EntityType.CERTIFICATE.value:
        return hashlib.sha256(value.encode()).hexdigest()
    if entity_type == EntityType.ASN.value:
        val = value.upper().strip()
        if not val.startswith("AS"):
            val = f"AS{val}"
        return val
    if entity_type == EntityType.ORG.value:
        return value.strip()
    return value.strip()


def deep_merge_attributes(existing: dict, incoming: dict) -> dict:
    result = dict(existing)
    for key, value in incoming.items():
        if key in result and isinstance(result[key], list) and isinstance(value, list):
            result[key] = result[key] + value
        else:
            result[key] = value
    return result
