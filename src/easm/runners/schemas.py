from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

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


def subfinder(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    domain = raw.get("host", "").strip()
    if not domain:
        return [], []
    return [EntityCandidate("domain", normalize_entity_value("domain", domain),
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
            "domain", n, "domain", normalize_entity_value("domain", original), "lookalike_of"))
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
    entities.append(EntityCandidate("certificate", cert_val, {
        "issuer_name_id": raw.get("issuer_name_id", ""),
        "not_before": raw.get("not_before", ""),
        "not_after": raw.get("not_after", ""),
        "source": "crtsh",
    }))
    for name in all_names:
        nn = normalize_entity_value("domain", name)
        entities.append(EntityCandidate("domain", nn, {"source": "crtsh"}))
        rels.append(RelationshipCandidate("certificate", cert_val, "domain", nn, "issued_for"))
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
    cert_data = raw.get("cert_data", {})
    all_names: set[str] = set()
    cn = cert_data.get("subject", {}).get("CN", "")
    if cn:
        all_names.add(cn)
    san_ext = cert_data.get("extensions", {}).get("subjectAltName", {})
    for names in san_ext.values():
        if isinstance(names, list):
            all_names.update(names)
    if not all_names:
        return [], []
    entities: list[EntityCandidate] = []
    rels: list[RelationshipCandidate] = []
    cert_val = raw.get("fingerprint", raw.get("serial_number", str(_uuid.uuid4())))
    entities.append(EntityCandidate("certificate", cert_val, {
        "subject": cert_data.get("subject", {}),
        "issuer": cert_data.get("issuer", {}),
        "not_before": cert_data.get("not_before"),
        "not_after": cert_data.get("not_after"),
        "source": "certstream",
    }))
    for name in all_names:
        nn = normalize_entity_value("domain", name)
        entities.append(EntityCandidate("domain", nn, {"source": "certstream"}))
        rels.append(RelationshipCandidate("certificate", cert_val, "domain", nn, "issued_for"))
        rels.append(RelationshipCandidate(
            "domain", nn, "certificate", cert_val, "reverse_of", "correlation"))
    return entities, rels


def dns(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    hostname = raw.get("hostname", "").strip()
    ip = raw.get("ip", "").strip()
    if not hostname or not ip:
        return [], []
    nh = normalize_entity_value("hostname", hostname)
    ni = normalize_entity_value("ip", ip)
    return [
        EntityCandidate("hostname", nh, {"source": "dns", "record_type": raw.get("record_type", "A")}),
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
    return [EntityCandidate("domain", normalize_entity_value("domain", domain), {
        "source": "domain_extract", "source_hostname": raw.get("source_hostname", ""),
    })], []


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
    entities.append(EntityCandidate("certificate", cert_val, {
        "source": "tls_cert", "subject_cn": cert_data.get("subject_cn", ""),
        "issuer_cn": cert_data.get("issuer_cn", ""), "issuer_org": cert_data.get("issuer_org", ""),
        "serial_number": cert_data.get("serial_number", ""),
        "not_before": cert_data.get("not_before", ""), "not_after": cert_data.get("not_after", ""),
        "fingerprint_sha256": cert_data.get("fingerprint_sha256", ""),
        "san_dns_names": san_names, "grabbed_from": nh,
    }))
    rels.append(RelationshipCandidate("hostname", nh, "certificate", cert_val, "issued_for", "pivot"))
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
    return [EntityCandidate("ip", normalize_entity_value("ip", ip), {
        "source": "shodan", "ports": s.get("ports", []),
        "hostnames": s.get("hostnames", []), "domains": s.get("domains", []),
        "cpes": [c for c in s.get("cpes", []) if isinstance(c, str)],
        "vulnerabilities": [v for v in s.get("vulns", []) if isinstance(v, str)],
        "org": s.get("org", ""), "isp": s.get("isp", ""), "asn": s.get("asn", ""),
        "country": s.get("country_name", ""), "city": s.get("city", ""),
        "os": s.get("os", ""), "services": s.get("data", []),
    })], []


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
    for rec in a_records:
        ip = rec.get("ip", "").strip()
        if ip:
            entities.append(EntityCandidate("ip", normalize_entity_value("ip", ip), {
                "source": "securitytrails", "first_seen": rec.get("first_seen", ""),
                "last_seen": rec.get("last_seen", ""), "resolved_for": domain,
            }))
    return entities, []


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
    tc = raw.get("takeover_check")
    if not hostname or not tc:
        return [], []
    return [EntityCandidate("hostname", normalize_entity_value("hostname", hostname), {
        "source": "takeover", "takeover_risk": tc.get("takeover_risk", False),
        "fingerprint_matches": tc.get("fingerprint_matches", []),
    })], []


def _noop(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    return [], []


OUTPUT_SCHEMAS: dict[str, OutputSchemaFn] = {
    "asnmap": asnmap, "subfinder": subfinder, "dnstwist": dnstwist,
    "crtsh": crtsh, "nuclei": nuclei, "wappalyzer": wappalyzer,
    "commoncrawl": commoncrawl, "portscan": portscan, "screenshot": screenshot,
    "certstream": certstream, "dns": dns, "reverse_dns": reverse_dns,
    "domain_extract": domain_extract, "geoip": geoip, "tls_cert": tls_cert,
    "dns_mail_records": dns_mail_records, "shodan": shodan, "abuseipdb": abuseipdb,
    "greynoise": greynoise, "urlscan": urlscan, "censys": censys,
    "securitytrails": passive_dns, "cloud_enum": cloud_bucket, "searchengine": searchengine,
    "takeover": subdomain_takeover,
    "paste_monitor": _noop, "gist_monitor": _noop, "stackoverflow_monitor": _noop,
    "discord_monitor": _noop, "github_scan": _noop, "breach_monitor": _noop,
    "reverse_whois": _noop,
}
# --- pivot/enrichment schemas (used by pivot worker, not runners) ---

def dns(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    h = raw.get("hostname", "").strip(); ip = raw.get("ip", "").strip()
    if not h or not ip: return [], []
    nh = normalize_entity_value("hostname", h); ni = normalize_entity_value("ip", ip)
    return [
        EntityCandidate("hostname", nh, {"source":"dns","record_type":raw.get("record_type","A")}),
        EntityCandidate("ip", ni, {"source":"dns"}),
    ], [
        RelationshipCandidate("hostname", nh, "ip", ni, "resolves_to", "pivot"),
        RelationshipCandidate("ip", ni, "hostname", nh, "reverse_of", "correlation"),
    ]

def reverse_dns(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    ip = raw.get("ip", "").strip(); h = raw.get("hostname", "").strip()
    if not ip or not h: return [], []
    ni = normalize_entity_value("ip", ip); nh = normalize_entity_value("hostname", h)
    return [
        EntityCandidate("ip", ni, {"source":"reverse_dns"}),
        EntityCandidate("hostname", nh, {"source":"reverse_dns"}),
    ], [RelationshipCandidate("ip", ni, "hostname", nh, "reverse_of", "pivot")]

def domain_extract(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    d = raw.get("domain", "").strip()
    if not d: return [], []
    return [EntityCandidate("domain", normalize_entity_value("domain", d), {"source":"domain_extract","source_hostname":raw.get("source_hostname","")})], []

def geoip(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    ip = raw.get("ip", "").strip(); g = raw.get("geo")
    if not ip or not g: return [], []
    return [EntityCandidate("ip", normalize_entity_value("ip", ip), {"source":"geoip","geo":g})], []

def tls_cert(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    h = raw.get("hostname", "").strip(); cd = raw.get("cert")
    if not h or not cd: return [], []
    cv = cd.get("fingerprint_sha256", cd.get("serial_number", ""))
    if not cv: return [], []
    nh = normalize_entity_value("hostname", h)
    san = cd.get("san_dns_names", [])
    e = [EntityCandidate("certificate", cv, {"source":"tls_cert","subject_cn":cd.get("subject_cn",""),"issuer_cn":cd.get("issuer_cn",""),"issuer_org":cd.get("issuer_org",""),"serial_number":cd.get("serial_number",""),"not_before":cd.get("not_before",""),"not_after":cd.get("not_after",""),"fingerprint_sha256":cd.get("fingerprint_sha256",""),"san_dns_names":san,"grabbed_from":nh})]
    r = [RelationshipCandidate("hostname", nh, "certificate", cv, "issued_for", "pivot")]
    for s in san:
        ns = normalize_entity_value("domain", s)
        e.append(EntityCandidate("domain", ns, {"source":"tls_cert"}))
        r.append(RelationshipCandidate("certificate", cv, "domain", ns, "san_contains", "pivot"))
        r.append(RelationshipCandidate("domain", ns, "certificate", cv, "reverse_of", "correlation"))
    return e, r

def dns_mail_records(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    d = raw.get("domain", "").strip()
    if not d: return [], []
    from easm.mail_provider import classify_mail_provider
    nd = normalize_entity_value("domain", d); mx = raw.get("mx_records", [])
    attrs = {"source":"dns_mail_records","mx_records":mx}
    if raw.get("spf_record"): attrs["spf_record"] = raw["spf_record"]
    if raw.get("dmarc_record"): attrs["dmarc_record"] = raw["dmarc_record"]
    attrs["mail_provider"] = classify_mail_provider(mx_records=mx, spf_record=raw.get("spf_record",""))
    e = [EntityCandidate("domain", nd, attrs)]; r = []
    for m in mx:
        ex = m.get("exchange","").strip()
        if ex:
            ne = normalize_entity_value("hostname", ex)
            e.append(EntityCandidate("hostname", ne, {"source":"dns_mail_records","mx_for":nd}))
            r.append(RelationshipCandidate("domain", nd, "hostname", ne, "mail_handled_by", "pivot"))
    return e, r

def shodan(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    ip = raw.get("ip", "").strip()
    if not ip: return [], []
    s = raw.get("shodan", raw)
    return [EntityCandidate("ip", normalize_entity_value("ip", ip), {"source":"shodan","ports":s.get("ports",[]),"hostnames":s.get("hostnames",[]),"domains":s.get("domains",[]),"cpes":[c for c in s.get("cpes",[]) if isinstance(c,str)],"vulnerabilities":[v for v in s.get("vulns",[]) if isinstance(v,str)],"org":s.get("org",""),"isp":s.get("isp",""),"asn":s.get("asn",""),"country":s.get("country_name",""),"city":s.get("city",""),"os":s.get("os",""),"services":s.get("data",[])})], []

def abuseipdb(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    ip = raw.get("ip", "").strip(); a = raw.get("abuseipdb")
    if not ip or not a: return [], []
    return [EntityCandidate("ip", normalize_entity_value("ip", ip), {"source":"abuseipdb","threat_intel":{"abuseipdb":{"abuseConfidenceScore":a.get("abuseConfidenceScore"),"totalReports":a.get("totalReports"),"lastReportedAt":a.get("lastReportedAt"),"usageType":a.get("usageType",""),"hostnames":a.get("hostnames",[]),"domain":a.get("domain",""),"countryCode":a.get("countryCode",""),"isp":a.get("isp","")}}})], []

def greynoise(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    ip = raw.get("ip", "").strip(); g = raw.get("greynoise")
    if not ip or not g: return [], []
    return [EntityCandidate("ip", normalize_entity_value("ip", ip), {"source":"greynoise","threat_intel":{"greynoise":{"classification":g.get("classification"),"noise":g.get("noise"),"riot":g.get("riot"),"name":g.get("name",""),"link":g.get("link","")}}})], []

def urlscan(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    d = raw.get("domain", "").strip(); u = raw.get("urlscan")
    if not d or not u: return [], []
    rr = u.get("results", []); mc = sum(1 for r in rr if r.get("is_malicious"))
    return [EntityCandidate("domain", normalize_entity_value("domain", d), {"source":"urlscan","threat_intel":{"urlscan":{"total_results":u.get("total_results",0),"malicious_count":mc,"results":[{"page_url":r.get("page_url",""),"ip":r.get("ip",""),"domain":r.get("domain",""),"is_malicious":r.get("is_malicious",False),"screenshot_url":r.get("screenshot_url")} for r in rr],"malicious_urls":[r.get("page_url","") for r in rr if r.get("is_malicious")]}}})], []

def censys(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    ip = raw.get("ip", "").strip(); c = raw.get("censys")
    if not ip or not c: return [], []
    return [EntityCandidate("ip", normalize_entity_value("ip", ip), {"source":"censys","services":c.get("services",[]),"location":c.get("location",{}),"autonomous_system":c.get("autonomous_system",{}),"last_updated_at":c.get("last_updated_at","")})], []

def passive_dns(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    d = raw.get("domain", "").strip(); p = raw.get("passive_dns")
    if not d or not p: return [], []
    nd = normalize_entity_value("domain", d); ar = p.get("a_records", [])
    e = [EntityCandidate("domain", nd, {"source":"securitytrails","dns_history":ar})]
    for rec in ar:
        ip = rec.get("ip","").strip()
        if ip: e.append(EntityCandidate("ip", normalize_entity_value("ip", ip), {"source":"securitytrails","first_seen":rec.get("first_seen",""),"last_seen":rec.get("last_seen",""),"resolved_for":d}))
    return e, []

def cloud_bucket(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    bu = raw.get("bucket_url","").strip(); pr = raw.get("provider","").strip()
    if not bu or not pr: return [], []
    h = bu.split("/")[0]
    return [EntityCandidate("domain", normalize_entity_value("domain", h), {"source":"cloud_enum","cloud_provider":pr,"bucket_name":raw.get("bucket_name",""),"public_access":raw.get("public_access",False),"public_list":raw.get("public_list",False),"status_code":raw.get("status_code")})], []

def searchengine(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    sd = raw.get("subdomain","").strip()
    if not sd: return [], []
    return [EntityCandidate("domain", normalize_entity_value("domain", sd), {"source":"searchengine","source_engine":raw.get("source_engine",""),"discovered_from":raw.get("domain",""),"url":raw.get("url","")})], []

def subdomain_takeover(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    h = raw.get("hostname","").strip(); tc = raw.get("takeover_check")
    if not h or not tc: return [], []
    return [EntityCandidate("hostname", normalize_entity_value("hostname", h), {"source":"takeover","takeover_risk":tc.get("takeover_risk",False),"fingerprint_matches":tc.get("fingerprint_matches",[])})], []

def _noop(raw: dict) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
    return [], []


OUTPUT_SCHEMAS = {
    "asnmap": asnmap, "subfinder": subfinder, "dnstwist": dnstwist, "crtsh": crtsh,
    "nuclei": nuclei, "wappalyzer": wappalyzer, "commoncrawl": commoncrawl,
    "portscan": portscan, "screenshot": screenshot, "certstream": certstream,
    "dns": dns, "reverse_dns": reverse_dns, "domain_extract": domain_extract,
    "geoip": geoip, "tls_cert": tls_cert, "dns_mail_records": dns_mail_records,
    "shodan": shodan, "abuseipdb": abuseipdb, "greynoise": greynoise,
    "urlscan": urlscan, "censys": censys, "securitytrails": passive_dns,
    "cloud_enum": cloud_bucket, "searchengine": searchengine, "takeover": subdomain_takeover,
    "paste_monitor": _noop, "gist_monitor": _noop, "stackoverflow_monitor": _noop,
    "discord_monitor": _noop, "github_scan": _noop, "breach_monitor": _noop,
    "reverse_whois": _noop,
}
