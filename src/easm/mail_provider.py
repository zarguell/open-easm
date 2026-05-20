from __future__ import annotations
from typing import Any

_PROVIDER_PATTERNS: list[tuple[str, str, str]] = [
    ("google_workspace", ".google.com", "include:_spf.google.com"),
    ("google_workspace", ".googlemail.com", "include:_spf.google.com"),
    ("microsoft_365", ".mail.protection.outlook.com", "include:spf.protection.outlook.com"),
    ("microsoft_365", ".outlook.com", "include:spf.protection.outlook.com"),
    ("microsoft_eop", ".eo.outlook.com", "include:spf.protection.outlook.com"),
    ("proofpoint", ".pphosted.com", "include:pphosted.com"),
    ("mimecast", ".mimecast.com", "include:mimecast.com"),
    ("mimecast", ".mimecast.org", "include:mimecast.org"),
    ("zoho", ".zoho.com", "include:zoho.com"),
    ("zoho", ".zoho.eu", "include:zoho.eu"),
    ("fastmail", ".fastmail.com", "include:fastmail.com"),
    ("fastmail", ".messagingengine.com", "include:spf.messagingengine.com"),
    ("sendgrid", ".sendgrid.net", "include:sendgrid.net"),
    ("mailgun", ".mailgun.org", "include:mailgun.org"),
    ("postmark", ".postmarkapp.com", "include:postmarkapp.com"),
    ("postmark", ".mtasv.net", "include:spf.mtasv.net"),
    ("amazon_ses", ".amazonses.com", "include:amazonses.com"),
    ("yahoo", ".yahoodns.net", "include:yahoo.com"),
    ("icloud", ".icloud.com", "include:icloud.com"),
    ("icloud", ".me.com", "include:icloud.com"),
    ("cloudflare_email_routing", ".mx.cloudflare.net", "include:_spf.mx.cloudflare.net"),
    ("proton_mail", ".protonmail.ch", "include:_spf.protonmail.ch"),
    ("tuta", ".tutanota.de", ""),
    ("tuta", ".tutanota.com", ""),
    ("tuta", ".tutanota.org", ""),
    ("purelymail", ".purelymail.com", "include:_spf.purelymail.com"),
    ("mailchimp", ".mcsv.net", "include:servers.mcsv.net"),
    ("mandrill", ".mandrillapp.com", "include:spf.mandrillapp.com"),
    ("salesforce", ".salesforce.com", "include:_spf.salesforce.com"),
    ("hubspot", ".hubspotemail.net", "include:_spf.hubspot.com"),
    ("zendesk", ".zendesk.com", "include:mail.zendesk.com"),
    ("rackspace", ".emailsrvr.com", "include:emailsrvr.com"),
    ("godaddy", ".secureserver.net", "include:secureserver.net"),
    ("mailjet", ".mailjet.com", "include:spf.mailjet.com"),
    ("mailerlite", ".mlsend.com", "include:_spf.mlsend.com"),
    ("sparkpost", ".sparkpostmail.com", "include:sparkpostmail.com"),
    ("brevo", ".sendinblue.com", "include:sendinblue.com"),
    ("klaviyo", ".klaviyomail.com", "include:spf.klaviyo.com"),
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
