"""Executive pillar definitions and domain profile classification."""

from __future__ import annotations


PILLARS = [
    {
        "id": "dns",
        "label": "DNS",
        "patterns": ["dns", "caa", "a/aaaa", "resolution", "nameserver", "ns record"],
        "description": "Quality of public DNS records and zone consistency.",
        "recommendation": "Correct weak or inconsistent DNS records, including CAA, NS, and non-public resolutions.",
    },
    {
        "id": "mail",
        "label": "Mail",
        "patterns": ["mail", "dmarc", "spf", "mx", "dkim", "email"],
        "description": "Domain protection against spoofing, phishing, and mail routing errors.",
        "recommendation": "Strengthen SPF, DKIM, and DMARC, then progressively aim for a strict DMARC policy.",
    },
    {
        "id": "web",
        "label": "Web",
        "patterns": ["web", "headers", "http", "header", "hsts", "x-frame", "content-security"],
        "description": "Security of public web services, redirects, and HTTP security headers.",
        "recommendation": "Fix missing HTTP headers, enforce HTTPS, and reduce uncontrolled web surfaces.",
    },
    {
        "id": "tls",
        "label": "TLS/SSL",
        "patterns": ["tls", "ssl", "certificate", "https", "cert", "expired"],
        "description": "Certificate quality, expiration, TLS versions, and HTTPS configuration.",
        "recommendation": "Monitor expirations, keep TLS modern, and fix certificate anomalies.",
    },
    {
        "id": "surface",
        "label": "Exposed Surface",
        "patterns": ["ip inventory", "subdomain", "surface", "public ip", "open port", "service"],
        "description": "Inventory of IPs, subdomains, and assets exposed on the internet.",
        "recommendation": "Justify each exposure, remove unnecessary assets, and correct published private IPs.",
    },
    {
        "id": "cti",
        "label": "CTI / Reputation",
        "patterns": ["cti", "reputation", "dnsbl", "blacklist", "abuse"],
        "description": "Reputation signals and potential presence in blocklists.",
        "recommendation": "Address listed IPs, verify abuse reports, and document false positives.",
    },
    {
        "id": "cve",
        "label": "CVEs",
        "patterns": ["cve", "vulnerability", "exploit", "kev"],
        "description": "Potential CVEs deduced from exposed technologies.",
        "recommendation": "Confirm actual versions internally and prioritize remediation on public-facing assets.",
    },
]

# Domain profile weights: how much each pillar matters per service profile.
# Derived from typical attack surface priorities for EASM platforms:
#   - Surface exposure (IPs, subdomains, open ports) is always the largest
#     concern since our platform continuously discovers new assets.
#   - TLS/Certificate posture is high because our certstream runner catches
#     misconfigurations in near-real-time.
#   - CVE correlation gets weight proportional to the services present.
#   - CTI/reputation is lower priority since we do lightweight DNSBL checks.
PROFILE_WEIGHTS: dict[str, dict[str, int]] = {
    "web_and_mail": {
        "dns": 10, "mail": 15, "web": 15, "tls": 15, "surface": 20, "cti": 10, "cve": 15,
    },
    "web": {
        "dns": 10, "mail": 0, "web": 20, "tls": 20, "surface": 25, "cti": 10, "cve": 15,
    },
    "mail": {
        "dns": 15, "mail": 25, "web": 0, "tls": 5, "surface": 20, "cti": 20, "cve": 15,
    },
    "dns": {
        "dns": 30, "mail": 0, "web": 0, "tls": 0, "surface": 35, "cti": 35, "cve": 0,
    },
    "undetermined": {
        "dns": 15, "mail": 10, "web": 10, "tls": 10, "surface": 25, "cti": 15, "cve": 15,
    },
}


def classify_domain(
    has_mail: bool = False,
    has_web: bool = False,
) -> str:
    """Classify a domain's profile based on which services are present.

    Returns one of: web_and_mail, web, mail, dns, undetermined.
    """
    if has_web and has_mail:
        return "web_and_mail"
    if has_web:
        return "web"
    if has_mail:
        return "mail"
    return "undetermined"
