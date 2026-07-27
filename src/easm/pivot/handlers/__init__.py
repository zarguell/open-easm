"""Pivot handler package — groups handlers by domain.

The original flat ``easm.pivot.handlers`` module grew past 1300 LOC. It is
now a package with four domain submodules:

* :mod:`easm.pivot.handlers.dns`        — DNS resolution + mail records + IP/ASN helpers
* :mod:`easm.pivot.handlers.cert`       — crt.sh search + live TLS certificate grab
* :mod:`easm.pivot.handlers.enrichment` — Shodan / AbuseIPDB / GreyNoise / Censys / etc.
* :mod:`easm.pivot.handlers.takeover`   — subdomain-takeover signal collection

This ``__init__`` re-exports every public handler, exposes the
``PIVOT_HANDLER_REGISTRY`` and ``PIVOT_SOURCE_NAMES`` maps used by the pivot
workers, and re-exports two helpers (``GeoIpLookup``, ``_certificate_to_raw_dict``)
that legacy callers still import from ``easm.pivot.handlers`` directly.
"""

from __future__ import annotations

from typing import Any

from easm.geoip import GeoIpLookup
from easm.pivot.handlers.cert import _certificate_to_raw_dict, crtsh_search, tls_cert_grab
from easm.pivot.handlers.dns import (
    dns_mail_records,
    dns_resolve,
    domain_extract,
    ip_in_range,
    ip_to_asn,
    reverse_dns,
)
from easm.pivot.handlers.enrichment import (
    _enrichment_keys,
    abuseipdb_enrich,
    censys_enrich,
    configure_enrichment_keys,
    domain_rdap,
    geoip_enrich,
    greynoise_enrich,
    passive_dns,
    rdap_lookup,
    reverse_whois,
    shodan_enrich,
    subdomain_enum,
    urlscan_enrich,
)
from easm.pivot.handlers.takeover import subdomain_takeover, takeover_detect
from easm.vuln_enrichment import cpe_vuln_enrich

PIVOT_HANDLER_REGISTRY: dict[str, Any] = {
    "dns_resolve": dns_resolve,
    "reverse_dns": reverse_dns,
    "domain_extract": domain_extract,
    "geoip_enrich": geoip_enrich,
    "tls_cert_grab": tls_cert_grab,
    "dns_mail_records": dns_mail_records,
    "crtsh_search": crtsh_search,
    "subdomain_enum": subdomain_enum,
    "subdomain_takeover": subdomain_takeover,
    "takeover_detect": takeover_detect,
    "passive_dns": passive_dns,
    "rdap_lookup": rdap_lookup,
    "reverse_whois": reverse_whois,
    "domain_rdap": domain_rdap,
    "shodan_enrich": shodan_enrich,
    "abuseipdb_enrich": abuseipdb_enrich,
    "greynoise_enrich": greynoise_enrich,
    "urlscan_enrich": urlscan_enrich,
    "censys_enrich": censys_enrich,
    "cpe_vuln_enrich": cpe_vuln_enrich,
    "ip_to_asn": ip_to_asn,
    "ip_in_range": ip_in_range,
}

PIVOT_SOURCE_NAMES: dict[str, str] = {
    "dns_resolve": "dns",
    "reverse_dns": "reverse_dns",
    "domain_extract": "domain_extract",
    "geoip_enrich": "geoip",
    "tls_cert_grab": "tls_cert",
    "dns_mail_records": "dns_mail_records",
    "crtsh_search": "crtsh",
    "subdomain_enum": "subfinder",
    "subdomain_takeover": "takeover",
    "takeover_detect": "takeover",
    "passive_dns": "securitytrails",
    "rdap_lookup": "rdap",
    "reverse_whois": "reverse_whois",
    "domain_rdap": "domain_rdap",
    "shodan_enrich": "shodan",
    "abuseipdb_enrich": "abuseipdb",
    "greynoise_enrich": "greynoise",
    "urlscan_enrich": "urlscan",
    "censys_enrich": "censys",
    "cpe_vuln_enrich": "cpe_vuln_enrich",
    "ip_to_asn": "ripe_stat",
}

__all__ = [
    "GeoIpLookup",
    "PIVOT_HANDLER_REGISTRY",
    "PIVOT_SOURCE_NAMES",
    "_certificate_to_raw_dict",
    "_enrichment_keys",
    "abuseipdb_enrich",
    "censys_enrich",
    "configure_enrichment_keys",
    "cpe_vuln_enrich",
    "crtsh_search",
    "dns_mail_records",
    "dns_resolve",
    "domain_extract",
    "domain_rdap",
    "geoip_enrich",
    "greynoise_enrich",
    "ip_in_range",
    "ip_to_asn",
    "passive_dns",
    "rdap_lookup",
    "reverse_dns",
    "reverse_whois",
    "shodan_enrich",
    "subdomain_enum",
    "subdomain_takeover",
    "takeover_detect",
    "tls_cert_grab",
    "urlscan_enrich",
]
