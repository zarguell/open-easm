from __future__ import annotations
from typing import Any

_PROVIDER_PATTERNS: list[tuple[str, str, str]] = [
    ("google_workspace", ".google.com", "include:_spf.google.com"),
    ("google_workspace", ".googlemail.com", "include:_spf.google.com"),
    ("microsoft_365", ".mail.protection.outlook.com", "include:spf.protection.outlook.com"),
    ("microsoft_365", ".outlook.com", "include:spf.protection.outlook.com"),
    ("proofpoint", ".pphosted.com", "include:pphosted.com"),
    ("mimecast", ".mimecast.com", "include:mimecast.com"),
    ("mimecast", ".mimecast.org", "include:mimecast.org"),
    ("zoho", ".zoho.com", "include:zoho.com"),
    ("fastmail", ".fastmail.com", "include:fastmail.com"),
    ("sendgrid", ".sendgrid.net", "include:sendgrid.net"),
    ("mailgun", ".mailgun.org", "include:mailgun.org"),
    ("postmark", ".postmarkapp.com", "include:postmarkapp.com"),
    ("amazon_ses", ".amazonses.com", "include:amazonses.com"),
    ("yahoo", ".yahoodns.net", "include:yahoo.com"),
]


def classify_mail_provider(
    mx_records: list[dict[str, Any]],
    spf_record: str,
) -> dict[str, str]:
    mx_exchanges = [
        r.get("exchange", "").lower().rstrip(".")
        for r in mx_records
        if r.get("exchange")
    ]
    mx_match: str | None = None
    for exchange in mx_exchanges:
        for provider_id, mx_suffix, _spf_include in _PROVIDER_PATTERNS:
            if exchange.endswith(mx_suffix):
                mx_match = provider_id
                break
        if mx_match:
            break
    spf_match: str | None = None
    if spf_record:
        spf_lower = spf_record.lower()
        for provider_id, _mx_suffix, spf_include in _PROVIDER_PATTERNS:
            if spf_include.lower() in spf_lower:
                spf_match = provider_id
                break
    if mx_match and spf_match and mx_match == spf_match:
        return {"provider": mx_match, "confidence": "high"}
    if mx_match:
        return {"provider": mx_match, "confidence": "high"}
    if spf_match:
        return {"provider": spf_match, "confidence": "medium"}
    return {"provider": "unknown", "confidence": "low"}
