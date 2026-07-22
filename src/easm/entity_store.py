from __future__ import annotations

import hashlib
import ipaddress

from easm.models import EntityType


def normalize_entity_value(entity_type: str, value: str) -> str:
    """Canonicalize an entity value by type.

    Ensures that semantically equivalent values produce the same string so
    that minor formatting differences (leading zeros in IPv4 octets, port
    suffixes, ASN prefix variants, wildcard/quote wrappers, trailing dots,
    mixed case) do not create duplicate entities.
    """
    value = value.strip()
    if not value:
        return value

    if entity_type == EntityType.IP.value:
        # Strip optional port suffix (IPv4 only — IPv6 has multiple colons).
        if value.count(":") == 1 and value.rsplit(":", 1)[1].isdigit():
            value = value.split(":", 1)[0]
        # Strip leading zeros from IPv4 octets before delegating to ipaddress,
        # which rejects octets like "005" on Python >= 3.9.5.
        parts = value.split(".")
        if len(parts) == 4:
            try:
                octets = [int(p) for p in parts]
            except ValueError:
                octets = None
            if octets is not None and all(0 <= o <= 255 for o in octets):
                value = ".".join(str(o) for o in octets)
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return value

    if entity_type == EntityType.ASN.value:
        value = value.upper()
        if value.startswith("ASN"):
            value = f"AS{value[3:]}"
        if not value.startswith("AS"):
            value = f"AS{value}"
        return value

    if entity_type in (EntityType.HOSTNAME.value, EntityType.DOMAIN.value):
        value = value.removeprefix("*.").strip("\"'")
        return value.lower().rstrip(".")

    if entity_type == EntityType.IP_RANGE.value:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            return value

    if entity_type == EntityType.CERTIFICATE.value:
        return hashlib.sha256(value.encode()).hexdigest()

    if entity_type == EntityType.ORG.value:
        return value

    return value


def deep_merge_attributes(existing: dict, incoming: dict) -> dict:
    result = dict(existing)
    for key, value in incoming.items():
        if key in result and isinstance(result[key], list) and isinstance(value, list):
            result[key] = result[key] + value
        else:
            result[key] = value
    return result
