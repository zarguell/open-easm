"""Infer a human-readable location for a correlation finding.

Maps findings to the specific DNS record, hostname, port, or service they
relate to, using the linked entity data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class FindingLocation:
    hostname: str = ""
    record: str | None = None
    control: str = ""
    path: str | None = None
    display: str = ""

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "record": self.record,
            "control": self.control,
            "path": self.path,
            "display": self.display,
        }


# Maps correlation rule IDs to pillar categories and DNS record hints.
_RULE_HINTS: dict[str, dict[str, str]] = {
    "stale_certificate": {"control": "TLS/Certificates", "record_prefix": "certificate"},
    "known_exploited_vulnerability": {"control": "CVE", "record_prefix": "cve"},
    "high_risk_port_exposed": {"control": "Surface", "record_prefix": "port"},
    "subdomain_takeover_risk": {"control": "DNS", "record_prefix": "cname"},
    "cloud_bucket_open": {"control": "Cloud", "record_prefix": "bucket"},
    "dev_or_test_system": {"control": "DNS", "record_prefix": "hostname"},
    "outlier_country": {"control": "GeoIP", "record_prefix": "ip"},
    "email_in_breach": {"control": "Identity", "record_prefix": "email"},
    "saas_hosted_infrastructure": {"control": "DNS", "record_prefix": "cname"},
}


def infer_finding_location(
    rule_id: str,
    headline: str,
    matched_entities: list[dict],
) -> FindingLocation:
    """Infer a location for a finding based on rule ID and linked entities."""
    hostname = _extract_hostname(headline, matched_entities)
    hint = _RULE_HINTS.get(rule_id, {})

    # Determine control / category
    control = hint.get("control", _infer_control_from_headline(headline))

    # Determine DNS record reference
    record = _infer_record(rule_id, headline, hostname, matched_entities)

    # Build path (e.g. "host -> header X-Frame-Options")
    path = _infer_path(rule_id, headline, hostname, matched_entities)

    display = path or record or hostname

    return FindingLocation(
        hostname=hostname,
        record=record,
        control=control,
        path=path,
        display=display,
    )


def _extract_hostname(headline: str, entities: list[dict]) -> str:
    """Try to extract a hostname from headline text or entity values."""
    # Try to find a hostname-like pattern in the headline
    for pattern in [
        r"on\s+([a-z0-9._-]+\.[a-z]{2,})",
        r"for\s+([a-z0-9._-]+\.[a-z]{2,})",
        r"([a-z0-9._-]+\.[a-z]{2,})",
    ]:
        m = re.search(pattern, headline, re.IGNORECASE)
        if m:
            candidate = m.group(1)
            if "." in candidate and len(candidate) > 3:
                return candidate.lower()

    # Fall back to entity values (hostnames and domains first)
    for entity in entities:
        etype = entity.get("entity_type", "")
        if etype in ("hostname", "domain"):
            return entity.get("entity_value", "")

    # Then IPs
    for entity in entities:
        if entity.get("entity_type") == "ip":
            return entity.get("entity_value", "")

    return ""


def _infer_control_from_headline(headline: str) -> str:
    h = headline.lower()
    if any(kw in h for kw in ("certificate", "tls", "ssl", "https")):
        return "TLS/SSL"
    if any(kw in h for kw in ("dns", "cname", "ns", "caa")):
        return "DNS"
    if any(kw in h for kw in ("dmarc", "spf", "mx", "mail")):
        return "Mail"
    if any(kw in h for kw in ("header", "http", "web")):
        return "Web"
    if any(kw in h for kw in ("cve", "vuln")):
        return "CVE"
    if any(kw in h for kw in ("port", "service", "open")):
        return "Surface"
    if any(kw in h for kw in ("breach", "email", "credential")):
        return "Identity"
    return "General"


def _infer_record(
    rule_id: str, headline: str, hostname: str, entities: list[dict]
) -> str | None:
    if not hostname:
        return None

    h = headline.lower()

    if "dmarc" in h:
        return f"_dmarc.{hostname} TXT"
    if "spf" in h:
        return f"{hostname} TXT SPF"
    if "mx" in h or "mail" in h:
        return f"{hostname} MX"
    if "caa" in h:
        return f"{hostname} CAA"
    if "cname" in h or "takeover" in h:
        return f"{hostname} CNAME"
    if "ns" in h:
        return f"{hostname} NS"

    # Port/service findings
    if rule_id == "high_risk_port_exposed":
        for entity in entities:
            attrs = entity.get("attributes", {})
            ports = attrs.get("open_ports", [])
            if ports:
                port_list = ", ".join(str(p.get("port", "")) for p in ports[:4])
                return f"{hostname}:{port_list}/tcp"

    # CVE findings
    if rule_id == "known_exploited_vulnerability":
        cve_match = re.search(r"(CVE-\d{4}-\d+)", headline, re.IGNORECASE)
        if cve_match:
            return f"{hostname} -> {cve_match.group(1)}"

    return None


def _infer_path(
    rule_id: str, headline: str, hostname: str, entities: list[dict]
) -> str | None:
    if not hostname:
        return None

    h = headline.lower()

    if "header" in h and ":" in headline:
        header = headline.split(":")[-1].strip()
        if header:
            return f"{hostname} -> header {header}"

    if "stale" in h or "expired" in h or "expir" in h:
        return f"{hostname} -> TLS certificate"

    if "subdomain" in h or "takeover" in h:
        return f"{hostname} -> CNAME takeover risk"

    return None
