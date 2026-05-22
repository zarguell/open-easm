from __future__ import annotations

from datetime import date, datetime, time, timezone
from typing import Any


CT_SOURCES = {"crtsh", "certstream"}
SUPPORTED_SOURCES = CT_SOURCES | {"tls_cert"}


def parse_cert_datetime(value: date | datetime | str | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime.combine(value, time.min)
    elif isinstance(value, str):
        normalized = value.strip()
        if not normalized:
            return None
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    else:
        raise TypeError(f"unsupported certificate datetime value: {type(value)!r}")

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def build_certificate_profile(
    *, source: str, raw: dict[str, Any], observed_at: datetime | None = None
) -> dict[str, Any]:
    if source not in SUPPORTED_SOURCES:
        raise ValueError(f"unsupported certificate source: {source}")

    observed = parse_cert_datetime(observed_at) or datetime.now(timezone.utc)
    cert = raw.get("cert") if isinstance(raw.get("cert"), dict) else raw
    not_before = parse_cert_datetime(cert.get("not_before") or raw.get("not_before"))
    not_after = parse_cert_datetime(cert.get("not_after") or raw.get("not_after"))
    san_dns_names = _extract_san_dns_names(source=source, raw=raw, cert=cert)
    deployment = _build_deployment(source=source, raw=raw, observed_at=observed)

    profile = {
        "fingerprint_sha256": _lower_or_none(
            cert.get("fingerprint_sha256")
            or raw.get("fingerprint_sha256")
            or cert.get("fingerprint")
            or raw.get("fingerprint")
        ),
        "serial_number": cert.get("serial_number") or raw.get("serial_number"),
        "subject": {
            "common_name": cert.get("subject_cn") or raw.get("subject_cn"),
            "organization": cert.get("subject_org") or raw.get("subject_org"),
        },
        "issuer": {
            "common_name": cert.get("issuer_cn") or raw.get("issuer_cn"),
            "organization": cert.get("issuer_org") or raw.get("issuer_org"),
            "name_id": str(raw.get("issuer_name_id"))
            if raw.get("issuer_name_id") is not None
            else None,
        },
        "san_dns_names": san_dns_names,
        "not_before": not_before.isoformat() if not_before else None,
        "not_after": not_after.isoformat() if not_after else None,
        "validity_days": _validity_days(not_before, not_after),
        "public_key": _build_public_key(cert),
        "signature": _build_signature(cert),
        "x509": _build_x509(cert),
        "sources": [source],
        "ct": {
            "seen": source in CT_SOURCES,
            "sources": [source] if source in CT_SOURCES else [],
            "last_seen": observed.isoformat() if source in CT_SOURCES else None,
        },
        "deployment": deployment,
        "observed_endpoints": _observed_endpoints(source=source, raw=raw),
    }
    return profile


def merge_certificate_profiles(
    existing: dict[str, Any], incoming: dict[str, Any]
) -> dict[str, Any]:
    merged = {**existing}

    for key in (
        "fingerprint_sha256",
        "serial_number",
        "not_before",
        "not_after",
        "validity_days",
        "public_key",
        "signature",
        "x509",
    ):
        merged[key] = _prefer_present(incoming.get(key), existing.get(key))

    merged["subject"] = _merge_dict(existing.get("subject"), incoming.get("subject"))
    merged["issuer"] = _merge_dict(existing.get("issuer"), incoming.get("issuer"))
    merged["san_dns_names"] = _dedupe_sorted(
        [*existing.get("san_dns_names", []), *incoming.get("san_dns_names", [])]
    )
    merged["sources"] = _dedupe_sorted(
        [*existing.get("sources", []), *incoming.get("sources", [])]
    )
    merged["observed_endpoints"] = _dedupe_dicts(
        [
            *existing.get("observed_endpoints", []),
            *incoming.get("observed_endpoints", []),
        ]
    )
    merged["ct"] = _merge_ct(existing.get("ct", {}), incoming.get("ct", {}))
    merged["deployment"] = _merge_deployment(
        existing.get("deployment", {}), incoming.get("deployment", {})
    )
    return merged


def _extract_san_dns_names(
    *, source: str, raw: dict[str, Any], cert: dict[str, Any]
) -> list[str]:
    names: list[str] = []
    if source in CT_SOURCES and raw.get("name_value"):
        names.extend(str(raw["name_value"]).splitlines())
    value = cert.get("san_dns_names") or raw.get("san_dns_names") or []
    if isinstance(value, str):
        names.extend(value.splitlines())
    else:
        names.extend(value)
    return _dedupe_sorted(_normalize_dns_name(name) for name in names)


def _build_deployment(
    *, source: str, raw: dict[str, Any], observed_at: datetime
) -> dict[str, Any]:
    if source == "tls_cert":
        endpoints = _observed_endpoints(source=source, raw=raw)
        return {
            "state": "deployed",
            "last_seen": observed_at.isoformat(),
            "last_observed_at": observed_at.isoformat(),
            "endpoints": endpoints,
            "observed_endpoints": endpoints,
        }
    return {
        "state": "ct_only",
        "last_seen": None,
        "last_observed_at": None,
        "endpoints": [],
        "observed_endpoints": [],
    }


def _observed_endpoints(*, source: str, raw: dict[str, Any]) -> list[dict[str, Any]]:
    if source != "tls_cert" or not raw.get("hostname"):
        return []
    endpoint: dict[str, Any] = {
        "hostname": _normalize_dns_name(raw["hostname"]),
        "source": source,
    }
    if raw.get("port") is not None:
        endpoint["port"] = raw["port"]
    return [endpoint]


def _build_public_key(cert: dict[str, Any]) -> dict[str, Any]:
    if isinstance(cert.get("public_key"), dict) and cert["public_key"]:
        return cert["public_key"]
    return {
        "algorithm": cert.get("public_key_algorithm") or "",
        "size_bits": cert.get("public_key_size_bits"),
        "curve": cert.get("public_key_curve") or "",
    }


def _build_signature(cert: dict[str, Any]) -> dict[str, Any]:
    if isinstance(cert.get("signature"), dict) and cert["signature"]:
        return cert["signature"]
    return {
        "algorithm": cert.get("signature_algorithm") or "",
        "hash_algorithm": cert.get("signature_hash_algorithm") or "",
    }


def _build_x509(cert: dict[str, Any]) -> dict[str, Any]:
    if isinstance(cert.get("x509"), dict) and cert["x509"]:
        return cert["x509"]
    return {
        "is_ca": bool(cert.get("is_ca", False)),
        "key_usage": cert.get("key_usage") or [],
        "extended_key_usage": cert.get("extended_key_usage") or [],
    }


def _merge_ct(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    return {
        **existing,
        **incoming,
        "seen": bool(existing.get("seen") or incoming.get("seen")),
        "sources": _dedupe_sorted(
            [*existing.get("sources", []), *incoming.get("sources", [])]
        ),
        "last_seen": _prefer_present(incoming.get("last_seen"), existing.get("last_seen")),
    }


def _merge_deployment(
    existing: dict[str, Any], incoming: dict[str, Any]
) -> dict[str, Any]:
    if incoming.get("state") == "deployed" or existing.get("state") != "deployed":
        preferred = {**existing, **incoming}
    else:
        preferred = {**incoming, **existing}
    preferred["endpoints"] = _dedupe_dicts(
        [*existing.get("endpoints", []), *incoming.get("endpoints", [])]
    )
    preferred["observed_endpoints"] = _dedupe_dicts(
        [
            *existing.get("observed_endpoints", existing.get("endpoints", [])),
            *incoming.get("observed_endpoints", incoming.get("endpoints", [])),
        ]
    )
    preferred["last_observed_at"] = _prefer_present(
        incoming.get("last_observed_at"),
        existing.get("last_observed_at"),
    )
    return preferred


def _merge_dict(
    existing: dict[str, Any] | None, incoming: dict[str, Any] | None
) -> dict[str, Any]:
    existing = existing or {}
    incoming = incoming or {}
    keys = existing.keys() | incoming.keys()
    return {
        key: _prefer_present(incoming.get(key), existing.get(key))
        for key in sorted(keys)
    }


def _validity_days(not_before: datetime | None, not_after: datetime | None) -> int | None:
    if not_before is None or not_after is None:
        return None
    return (not_after - not_before).days


def _normalize_dns_name(value: Any) -> str:
    return str(value).strip().lower().rstrip(".")


def _lower_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return str(value).strip().lower()


def _dedupe_sorted(values: Any) -> list[Any]:
    return sorted({value for value in values if value})


def _dedupe_dicts(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    deduped = []
    for value in values:
        marker = tuple(sorted(value.items()))
        if marker in seen:
            continue
        seen.add(marker)
        deduped.append(value)
    return deduped


def _prefer_present(incoming: Any, existing: Any) -> Any:
    if incoming not in (None, "", [], {}):
        return incoming
    return existing
