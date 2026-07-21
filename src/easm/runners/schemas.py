from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from easm.certificates.analysis import analyze_certificate_profile
from easm.certificates.profile import build_certificate_profile
from easm.entity_store import normalize_entity_value


@dataclass
class EntityCandidate:
    entity_type: str
    value: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class RelationshipCandidate:
    source_type: str
    source_value: str
    target_type: str
    target_value: str
    relationship_type: str
    relationship_source: str = "runner_direct"


OutputSchemaFn = Callable[[dict[str, Any]], tuple[list[EntityCandidate], list[RelationshipCandidate]]]


def _profile_with_analysis(source: str, raw: dict[str, Any]) -> dict[str, Any]:
    profile = build_certificate_profile(source=source, raw=raw)
    profile["analysis"] = analyze_certificate_profile(profile)
    return profile


def asnmap(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    asn_val = raw.get("as_number", str(raw.get("asn", ""))).strip()
    if not asn_val:
        return [], []
    n_asn = normalize_entity_value("asn", asn_val)
    entities = [EntityCandidate("asn", n_asn, {
        "source": "asnmap", "as_name": raw.get("as_name", ""),
        "as_country": raw.get("as_country", ""),
    })]
    rels: list[RelationshipCandidate] = []
    for cidr in raw.get("as_range", []):
        cv = cidr.get("ipv4", "").strip() if isinstance(cidr, dict) else str(cidr).strip()
        if cv:
            rv = normalize_entity_value("ip_range", cv)
            entities.append(EntityCandidate("ip_range", rv, {"source": "asnmap"}))
            rels.append(RelationshipCandidate("asn", n_asn, "ip_range", rv, "owns"))
    return entities, rels


def subfinder(raw: dict | str) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    if isinstance(raw, str):
        host = raw.strip()
    else:
        host = raw.get("host", "").strip()
    if not host:
        return [], []
    return [EntityCandidate("hostname", normalize_entity_value("hostname", host),
                            {"source": "subfinder"})], []


def dnstwist(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    lookalike = raw.get("domain", "").strip()
    if not lookalike:
        return [], []
    original = raw.get("original_domain", "").strip()
    n = normalize_entity_value("domain", lookalike)
    entities = [EntityCandidate("domain", n, {
        "source": "dnstwist",
        "dnstwist": {
            "permutation_type": raw.get("type", ""),
            "original_domain": original,
            "dns_records": raw.get("dns", {}),
            "is_registered": raw.get("registered", False),
        },
    })]
    rels: list[RelationshipCandidate] = []
    if original:
        rels.append(RelationshipCandidate(
            "domain", normalize_entity_value("domain", original), "domain", n, "discovered_lookalike"))
    return entities, rels


def crtsh(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    import uuid as _uuid
    all_names: set[str] = set()
    nv = raw.get("name_value", "")
    if nv:
        for line in nv.split("\n"):
            d = line.strip()
            if d:
                all_names.add(d)
    if not all_names:
        return [], []
    entities: list[EntityCandidate] = []
    rels: list[RelationshipCandidate] = []
    cert_val = raw.get("fingerprint", raw.get("serial_number", str(_uuid.uuid4())))
    profile = _profile_with_analysis("crtsh", raw)
    entities.append(EntityCandidate("certificate", cert_val, {
        "issuer_name_id": raw.get("issuer_name_id", ""),
        "not_before": raw.get("not_before", ""),
        "not_after": raw.get("not_after", ""),
        "source": "crtsh",
        "certificate_profile": profile,
    }))
    for name in all_names:
        nn = normalize_entity_value("domain", name)
        entities.append(EntityCandidate("domain", nn, {"source": "crtsh"}))
        rels.append(RelationshipCandidate("domain", nn, "certificate", cert_val, "cert_discovered"))
        rels.append(RelationshipCandidate(
            "domain", nn, "certificate", cert_val, "reverse_of", "correlation"))
    return entities, rels


def nuclei(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    hostname = raw.get("hostname", "").strip()
    if not hostname or "template-id" not in raw:
        return [], []
    n = normalize_entity_value("hostname", hostname)
    return [EntityCandidate("hostname", n, {
        "source": "nuclei",
        "vulnerability": {
            "template_id": raw.get("template-id", ""),
            "name": raw.get("info", {}).get("name", ""),
            "severity": raw.get("info", {}).get("severity", "unknown"),
            "description": raw.get("info", {}).get("description", ""),
            "matched_at": raw.get("matched-at", ""),
            "curl_command": raw.get("curl-command", ""),
        },
    })], []


def wappalyzer(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    hostname = raw.get("hostname", "").strip()
    if not hostname:
        return [], []
    return [EntityCandidate("hostname", normalize_entity_value("hostname", hostname),
                            {"source": "wappalyzer", "technologies": raw.get("technologies", [])})], []


def commoncrawl(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    import re as _re
    url = raw.get("url", "").strip()
    if not url:
        return [], []
    hm = _re.search(r'://([^/]+)', url)
    if not hm:
        return [], []
    host = hm.group(1).split(":")[0]
    parts = host.split(".")
    subdomain = ".".join(parts[-2:]) if len(parts) >= 2 else host
    return [EntityCandidate("domain", normalize_entity_value("domain", subdomain), {
        "source": "commoncrawl", "url": url,
        "discovered_from": raw.get("domain", ""),
    })], []


def portscan(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    hostname = raw.get("hostname", "").strip()
    ip = raw.get("ip", "").strip()
    ports = raw.get("ports", [])
    if not hostname or not ports:
        return [], []
    entities: list[EntityCandidate] = []
    nh = normalize_entity_value("hostname", hostname)
    entities.append(EntityCandidate("hostname", nh, {"source": "portscan", "open_ports": ports}))
    if ip:
        entities.append(EntityCandidate("ip", normalize_entity_value("ip", ip),
                                        {"source": "portscan", "open_ports": ports}))
    return entities, []


def screenshot(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    hostname = raw.get("hostname", "").strip()
    sp = raw.get("screenshot_path", "")
    if not hostname or not sp:
        return [], []
    return [EntityCandidate("hostname", normalize_entity_value("hostname", hostname),
                            {"source": "screenshot", "screenshot_path": sp})], []


def certstream(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    import uuid as _uuid
    cert_data = _certstream_cert_data(raw)
    all_names: set[str] = set()
    cn = cert_data.get("subject", {}).get("CN", "")
    if cn:
        all_names.add(cn)
    san_ext = cert_data.get("extensions", {}).get("subjectAltName", {})
    if isinstance(san_ext, dict):
        for names in san_ext.values():
            if isinstance(names, list):
                all_names.update(names)
            elif isinstance(names, str):
                all_names.add(names)
    elif isinstance(san_ext, str):
        for name in san_ext.split(","):
            clean_name = name.strip()
            if clean_name.startswith("DNS:"):
                clean_name = clean_name[4:]
            if clean_name:
                all_names.add(clean_name)
    if not all_names:
        return [], []
    entities: list[EntityCandidate] = []
    rels: list[RelationshipCandidate] = []
    cert_val = raw.get("fingerprint", raw.get("serial_number", str(_uuid.uuid4())))
    profile_raw = {
        **raw,
        "fingerprint": raw.get("fingerprint") or cert_data.get("fingerprint"),
        "serial_number": raw.get("serial_number") or cert_data.get("serial_number"),
        "subject_cn": cn,
        "not_before": raw.get("not_before") or cert_data.get("not_before"),
        "not_after": raw.get("not_after") or cert_data.get("not_after"),
        "san_dns_names": sorted(all_names),
    }
    profile = _profile_with_analysis("certstream", profile_raw)
    entities.append(EntityCandidate("certificate", cert_val, {
        "subject": cert_data.get("subject", {}),
        "issuer": cert_data.get("issuer", {}),
        "not_before": cert_data.get("not_before"),
        "not_after": cert_data.get("not_after"),
        "source": "certstream",
        "certificate_profile": profile,
    }))
    for name in all_names:
        nn = normalize_entity_value("domain", name)
        entities.append(EntityCandidate("domain", nn, {"source": "certstream"}))
        rels.append(RelationshipCandidate("domain", nn, "certificate", cert_val, "cert_discovered"))
        rels.append(RelationshipCandidate(
            "domain", nn, "certificate", cert_val, "reverse_of", "correlation"))
    return entities, rels


def dns(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    hostname = raw.get("hostname", "").strip()
    record_type = raw.get("record_type", "A")

    if record_type == "CNAME":
        cname_target = raw.get("cname_target", "").strip()
        if not hostname or not cname_target:
            return [], []
        nh = normalize_entity_value("hostname", hostname)
        nc = normalize_entity_value("hostname", cname_target)
        return [
            EntityCandidate("hostname", nh, {
                "source": "dns", "record_type": "CNAME",
                "cname_target": cname_target,
            }),
            EntityCandidate("hostname", nc, {
                "source": "dns_cname",
                "cname_for": hostname,
            }),
        ], [
            RelationshipCandidate("hostname", nh, "hostname", nc, "cname_to", "pivot"),
        ]

    # A record (existing behavior)
    ip = raw.get("ip", "").strip()
    if not hostname or not ip:
        return [], []
    nh = normalize_entity_value("hostname", hostname)
    ni = normalize_entity_value("ip", ip)
    return [
        EntityCandidate("hostname", nh, {"source": "dns", "record_type": "A"}),
        EntityCandidate("ip", ni, {"source": "dns"}),
    ], [
        RelationshipCandidate("hostname", nh, "ip", ni, "resolves_to", "pivot"),
        RelationshipCandidate("ip", ni, "hostname", nh, "reverse_of", "correlation"),
    ]


def reverse_dns(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    ip = raw.get("ip", "").strip()
    hostname = raw.get("hostname", "").strip()
    if not ip or not hostname:
        return [], []
    ni = normalize_entity_value("ip", ip)
    nh = normalize_entity_value("hostname", hostname)
    return [
        EntityCandidate("ip", ni, {"source": "reverse_dns"}),
        EntityCandidate("hostname", nh, {"source": "reverse_dns"}),
    ], [
        RelationshipCandidate("ip", ni, "hostname", nh, "reverse_of", "pivot"),
    ]


def domain_extract(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    domain = raw.get("domain", "").strip()
    if not domain:
        return [], []
    nd = normalize_entity_value("domain", domain)
    nh = raw.get("source_hostname", "").strip()
    rels: list[RelationshipCandidate] = []
    if nh:
        rels.append(RelationshipCandidate(
            "hostname", normalize_entity_value("hostname", nh),
            "domain", nd,
            "registered_domain_of", "pivot",
        ))
    return [EntityCandidate("domain", nd, {
        "source": "domain_extract", "source_hostname": nh,
    })], rels


def geoip(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    ip = raw.get("ip", "").strip()
    geo = raw.get("geo")
    if not ip or not geo:
        return [], []
    return [EntityCandidate("ip", normalize_entity_value("ip", ip), {"source": "geoip", "geo": geo})], []


def tls_cert(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    hostname = raw.get("hostname", "").strip()
    cert_data = raw.get("cert")
    if not hostname or not cert_data:
        return [], []
    cert_val = cert_data.get("fingerprint_sha256", cert_data.get("serial_number", ""))
    if not cert_val:
        return [], []
    nh = normalize_entity_value("hostname", hostname)
    san_names = cert_data.get("san_dns_names", [])
    entities: list[EntityCandidate] = []
    rels: list[RelationshipCandidate] = []
    profile = _profile_with_analysis("tls_cert", raw)
    entities.append(EntityCandidate("certificate", cert_val, {
        "source": "tls_cert", "subject_cn": cert_data.get("subject_cn", ""),
        "issuer_cn": cert_data.get("issuer_cn", ""), "issuer_org": cert_data.get("issuer_org", ""),
        "serial_number": cert_data.get("serial_number", ""),
        "not_before": cert_data.get("not_before", ""), "not_after": cert_data.get("not_after", ""),
        "fingerprint_sha256": cert_data.get("fingerprint_sha256", ""),
        "san_dns_names": san_names, "grabbed_from": nh,
        "certificate_profile": profile,
    }))
    rels.append(RelationshipCandidate("hostname", nh, "certificate", cert_val, "issued_for", "pivot"))
    rels.append(RelationshipCandidate("hostname", nh, "certificate", cert_val, "deployed_on", "pivot"))
    for san in san_names:
        ns = normalize_entity_value("domain", san)
        entities.append(EntityCandidate("domain", ns, {"source": "tls_cert"}))
        rels.append(RelationshipCandidate("certificate", cert_val, "domain", ns, "san_contains", "pivot"))
        rels.append(RelationshipCandidate("domain", ns, "certificate", cert_val, "reverse_of", "correlation"))
    return entities, rels


def dns_mail_records(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    domain = raw.get("domain", "").strip()
    if not domain:
        return [], []
    from easm.mail_provider import classify_mail_provider
    nd = normalize_entity_value("domain", domain)
    mx_records = raw.get("mx_records", [])
    spf = raw.get("spf_record", "")
    dmarc = raw.get("dmarc_record", "")
    attrs: dict[str, Any] = {"source": "dns_mail_records", "mx_records": mx_records}
    if spf:
        attrs["spf_record"] = spf
    if dmarc:
        attrs["dmarc_record"] = dmarc
    attrs["mail_provider"] = classify_mail_provider(mx_records=mx_records, spf_record=spf)
    entities = [EntityCandidate("domain", nd, attrs)]
    rels: list[RelationshipCandidate] = []
    for mx in mx_records:
        exchange = mx.get("exchange", "").strip()
        if exchange:
            ne = normalize_entity_value("hostname", exchange)
            entities.append(EntityCandidate("hostname", ne, {"source": "dns_mail_records", "mx_for": nd}))
            rels.append(RelationshipCandidate("domain", nd, "hostname", ne, "mail_handled_by", "pivot"))
    return entities, rels


def shodan(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    ip = raw.get("ip", "").strip()
    if not ip:
        return [], []
    s = raw.get("shodan", raw)
    ni = normalize_entity_value("ip", ip)
    entities: list[EntityCandidate] = [
        EntityCandidate("ip", ni, {
            "source": "shodan", "ports": s.get("ports", []),
            "hostnames": s.get("hostnames", []), "domains": s.get("domains", []),
            "cpes": [c for c in s.get("cpes", []) if isinstance(c, str)],
            "vulnerabilities": [v for v in s.get("vulns", []) if isinstance(v, str)],
            "org": s.get("org", ""), "isp": s.get("isp", ""), "asn": s.get("asn", ""),
            "country": s.get("country_name", ""), "city": s.get("city", ""),
            "os": s.get("os", ""), "services": s.get("data", []),
        })
    ]
    rels: list[RelationshipCandidate] = []
    for h in s.get("hostnames", []):
        if h:
            nh = normalize_entity_value("hostname", h)
            entities.append(EntityCandidate("hostname", nh, {"source": "shodan"}))
            rels.append(RelationshipCandidate("ip", ni, "hostname", nh, "reverse_of", "pivot"))
    for d in s.get("domains", []):
        if d:
            nd = normalize_entity_value("domain", d)
            entities.append(EntityCandidate("domain", nd, {"source": "shodan"}))
            rels.append(RelationshipCandidate("ip", ni, "domain", nd, "belongs_to", "pivot"))
    return entities, rels


def abuseipdb(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    ip = raw.get("ip", "").strip()
    a = raw.get("abuseipdb")
    if not ip or not a:
        return [], []
    return [EntityCandidate("ip", normalize_entity_value("ip", ip), {
        "source": "abuseipdb", "threat_intel": {"abuseipdb": {
            "abuseConfidenceScore": a.get("abuseConfidenceScore"),
            "totalReports": a.get("totalReports"), "lastReportedAt": a.get("lastReportedAt"),
            "usageType": a.get("usageType", ""), "hostnames": a.get("hostnames", []),
            "domain": a.get("domain", ""), "countryCode": a.get("countryCode", ""),
            "isp": a.get("isp", ""),
        }},
    })], []


def greynoise(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    ip = raw.get("ip", "").strip()
    g = raw.get("greynoise")
    if not ip or not g:
        return [], []
    return [EntityCandidate("ip", normalize_entity_value("ip", ip), {
        "source": "greynoise", "threat_intel": {"greynoise": {
            "classification": g.get("classification"), "noise": g.get("noise"),
            "riot": g.get("riot"), "name": g.get("name", ""), "link": g.get("link", ""),
        }},
    })], []


def urlscan(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    domain = raw.get("domain", "").strip()
    u = raw.get("urlscan")
    if not domain or not u:
        return [], []
    results_raw = u.get("results", [])
    mc = sum(1 for r in results_raw if r.get("is_malicious"))
    return [EntityCandidate("domain", normalize_entity_value("domain", domain), {
        "source": "urlscan", "threat_intel": {"urlscan": {
            "total_results": u.get("total_results", 0), "malicious_count": mc,
            "results": [{
                "page_url": r.get("page_url", ""), "ip": r.get("ip", ""),
                "domain": r.get("domain", ""), "is_malicious": r.get("is_malicious", False),
                "screenshot_url": r.get("screenshot_url"),
            } for r in results_raw],
            "malicious_urls": [r.get("page_url", "") for r in results_raw if r.get("is_malicious")],
        }},
    })], []


def censys(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    ip = raw.get("ip", "").strip()
    c = raw.get("censys")
    if not ip or not c:
        return [], []
    return [EntityCandidate("ip", normalize_entity_value("ip", ip), {
        "source": "censys", "services": c.get("services", []),
        "location": c.get("location", {}),
        "autonomous_system": c.get("autonomous_system", {}),
        "last_updated_at": c.get("last_updated_at", ""),
    })], []


def passive_dns(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    domain = raw.get("domain", "").strip()
    pdns = raw.get("passive_dns")
    if not domain or not pdns:
        return [], []
    nd = normalize_entity_value("domain", domain)
    a_records = pdns.get("a_records", [])
    entities = [EntityCandidate("domain", nd, {"source": "securitytrails", "dns_history": a_records})]
    rels: list[RelationshipCandidate] = []
    for rec in a_records:
        ip = rec.get("ip", "").strip()
        if ip:
            ni = normalize_entity_value("ip", ip)
            entities.append(EntityCandidate("ip", ni, {
                "source": "securitytrails", "first_seen": rec.get("first_seen", ""),
                "last_seen": rec.get("last_seen", ""), "resolved_for": domain,
            }))
            rels.append(RelationshipCandidate("domain", nd, "ip", ni, "resolves_to", "pivot"))
    return entities, rels


def cloud_bucket(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    bucket_url = raw.get("bucket_url", "").strip()
    provider = raw.get("provider", "").strip()
    if not bucket_url or not provider:
        return [], []
    hostname = bucket_url.split("/")[0]
    return [EntityCandidate("domain", normalize_entity_value("domain", hostname), {
        "source": "cloud_enum", "cloud_provider": provider,
        "bucket_name": raw.get("bucket_name", ""), "public_access": raw.get("public_access", False),
        "public_list": raw.get("public_list", False), "status_code": raw.get("status_code"),
    })], []


def searchengine(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    subdomain = raw.get("subdomain", "").strip()
    if not subdomain:
        return [], []
    return [EntityCandidate("domain", normalize_entity_value("domain", subdomain), {
        "source": "searchengine", "source_engine": raw.get("source_engine", ""),
        "discovered_from": raw.get("domain", ""), "url": raw.get("url", ""),
    })], []


def subdomain_takeover(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    hostname = raw.get("hostname", "").strip()
    if not hostname:
        return [], []

    attrs: dict[str, Any] = {"source": "takeover"}

    # New v2 format: takeover_evidence
    te = raw.get("takeover_evidence")
    if te:
        attrs["takeover_evidence"] = te
        signals = te.get("signals", [])
        attrs["takeover_risk"] = len(signals) > 0
        attrs["signal_count"] = te.get("signal_count", 0)
        provider = te.get("provider")
        if provider:
            attrs["takeover_provider"] = provider["provider"]
            attrs["claimability"] = provider["claimability"]
        http_probe = te.get("http_probe")
        if http_probe and http_probe.get("fingerprint"):
            attrs["http_fingerprint"] = http_probe["fingerprint"]
        dns_chain = te.get("dns_chain")
        if dns_chain:
            attrs["dns_chain"] = {
                "a": dns_chain.get("a", []),
                "cname": dns_chain.get("cname", []),
                "terminal": dns_chain.get("terminal"),
                "delegation_ns": dns_chain.get("delegation_ns", []),
            }
            if dns_chain.get("delegation_ns"):
                attrs["ns_delegation_issues"] = True
        return [EntityCandidate("hostname", normalize_entity_value("hostname", hostname), attrs)], []

    # Legacy v1 format: takeover_check
    tc = raw.get("takeover_check")
    if tc:
        attrs["takeover_risk"] = tc.get("takeover_risk", False)
        attrs["fingerprint_matches"] = tc.get("fingerprint_matches", [])
        if tc.get("cname_target"):
            attrs["cname_target"] = tc["cname_target"]
        return [EntityCandidate("hostname", normalize_entity_value("hostname", hostname), attrs)], []

    return [], []


def ripe_stat(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    asn_val = raw.get("asn", "").strip()
    ip_val = raw.get("ip", "").strip()
    if not asn_val or not ip_val:
        return [], []
    n_asn = normalize_entity_value("asn", asn_val)
    n_ip = normalize_entity_value("ip", ip_val)
    entities = [
        EntityCandidate("asn", n_asn, {
            "source": "ripe_stat", "as_name": raw.get("as_name", ""),
        }),
        EntityCandidate("ip", n_ip, {"source": "ripe_stat"}),
    ]
    rels = [
        RelationshipCandidate("ip", n_ip, "asn", n_asn, "hosted_in", "pivot"),
    ]
    return entities, rels


def _certstream_cert_data(raw: dict[str, Any]) -> dict[str, Any]:
    cert_data = raw.get("cert_data", {})
    if isinstance(cert_data, dict) and isinstance(cert_data.get("leaf_cert"), dict):
        return cert_data["leaf_cert"]
    if isinstance(cert_data, dict):
        return cert_data
    leaf_cert = raw.get("leaf_cert", {})
    return leaf_cert if isinstance(leaf_cert, dict) else {}


def rdap(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    asn_val = raw.get("asn", "").strip()
    rdap_data = {k: v for k, v in raw.items() if k != "asn"}
    if not asn_val or not rdap_data:
        return [], []
    return [
        EntityCandidate(
            "asn",
            normalize_entity_value("asn", asn_val),
            {"source": "rdap", "rdap": rdap_data},
        ),
    ], []


def domain_rdap(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    domain = raw.get("domain", "").strip()
    if not domain:
        return [], []
    rdap_data = {k: v for k, v in raw.items() if k != "domain"}
    if not rdap_data:
        return [], []
    return [
        EntityCandidate(
            "domain",
            normalize_entity_value("domain", domain),
            {"source": "domain_rdap", "rdap": rdap_data},
        ),
    ], []


def cpe_vuln_enrich(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    entity_type = raw.get("entity_type", "").strip()
    entity_value = raw.get("entity_value", "").strip()
    if not entity_type and raw.get("hostname", "").strip():
        entity_type = "hostname"
        entity_value = raw.get("hostname", "").strip()
    if not entity_type or not entity_value:
        return [], []
    return [
        EntityCandidate(
            entity_type,
            normalize_entity_value(entity_type, entity_value),
            {
                "source": "cpe_vuln_enrich",
                "computed_cpes": raw.get("computed_cpes", []),
                "matched_cves": raw.get("matched_cves", []),
                "kev_count": raw.get("kev_count", 0),
                "total_cves": raw.get("total_cves", 0),
                "risk": raw.get("risk", "unknown"),
            },
        ),
    ], []


OUTPUT_SCHEMAS: dict[str, OutputSchemaFn] = {}


def _init_output_schemas() -> dict[str, OutputSchemaFn]:
    """Build OUTPUT_SCHEMAS by combining YAML-declared schemas with Python schemas.

    The :mod:`easm.runners.schema_engine` loads YAML schemas first (for
    simple sources like subfinder, screenshot, searchengine). Complex
    sources (certificate parsing, DNS branching, takeover fingerprinting)
    remain as Python functions in this module and overlay the YAML base.
    """
    schemas: dict[str, OutputSchemaFn] = {}
    try:
        from easm.runners.schema_engine import _load_yaml_schemas

        schemas.update(_load_yaml_schemas())
    except (ImportError, ValueError, KeyError) as exc:
        import logging as _logging

        _logging.getLogger(__name__).warning(
            "YAML schema loading skipped: %s", exc, exc_info=True,
        )

    # Python schemas — complex sources that cannot be declarative yet.
    python_schemas: dict[str, OutputSchemaFn] = {
        "asnmap": asnmap, "subfinder": subfinder, "dnstwist": dnstwist,
        "crtsh": crtsh, "certspotter": crtsh, "nuclei": nuclei, "wappalyzer": wappalyzer,
        "commoncrawl": commoncrawl, "portscan": portscan, "screenshot": screenshot,
        "certstream": certstream, "dns": dns, "reverse_dns": reverse_dns,
        "domain_extract": domain_extract, "geoip": geoip, "tls_cert": tls_cert,
        "dns_mail_records": dns_mail_records, "shodan": shodan, "abuseipdb": abuseipdb,
        "greynoise": greynoise, "urlscan": urlscan, "censys": censys,
        "securitytrails": passive_dns, "cloud_enum": cloud_bucket, "searchengine": searchengine,
        "takeover": subdomain_takeover, "takeover_detect": subdomain_takeover,
        "ripe_stat": ripe_stat, "rdap": rdap, "domain_rdap": domain_rdap,
        "cpe_vuln_enrich": cpe_vuln_enrich,
    }
    # YAML takes priority; Python fills gaps
    for name, fn in python_schemas.items():
        if name not in schemas:
            schemas[name] = fn

    return schemas


OUTPUT_SCHEMAS.update(_init_output_schemas())
