from __future__ import annotations

import asyncio
import base64
import json
import logging
import random
import re
import socket
import ssl
from typing import Any

import dns.resolver
import dns.reversename
import httpx
import tldextract
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from easm.geoip import GeoIpLookup

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Handler functions
# ---------------------------------------------------------------------------


async def dns_resolve(job: dict, pool) -> list[dict[str, Any]]:
    hostname = job["entity_value"]
    results: list[dict[str, Any]] = []
    try:
        answers = dns.resolver.resolve(hostname, "A")
        for rdata in answers:
            results.append({"hostname": hostname, "ip": str(rdata), "record_type": "A"})
    except dns.resolver.NXDOMAIN:
        pass
    except Exception:
        pass
    return results


async def reverse_dns(job: dict, pool) -> list[dict[str, Any]]:
    import ipaddress
    ip_range = job["entity_value"]
    results: list[dict[str, Any]] = []
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        for ip in list(network.hosts())[:16]:
            try:
                rev = dns.reversename.from_address(str(ip))
                answers = dns.resolver.resolve(rev, "PTR")
                for rdata in answers:
                    results.append({"ip": str(ip), "hostname": str(rdata.target)[:-1]})
            except Exception:
                pass
    except ValueError:
        pass
    return results


async def domain_extract(job: dict, pool) -> list[dict[str, Any]]:
    hostname = job["entity_value"]
    extracted = tldextract.extract(hostname)
    apex = f"{extracted.domain}.{extracted.suffix}".lower()
    if apex == hostname.lower():
        return []
    return [{"domain": apex, "source_hostname": hostname}]


async def geoip_enrich(job: dict, pool) -> list[dict[str, Any]]:
    ip = job["entity_value"]
    lookup = GeoIpLookup()
    result = lookup.lookup(ip)
    if result is None:
        return [{"ip": ip, "message": "no geo-IP data available"}]
    return [{"ip": ip, "geo": result.to_dict()}]


async def tls_cert_grab(job: dict, pool) -> list[dict[str, Any]]:
    hostname = job["entity_value"]
    port = 443
    timeout = 10
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                der_cert = tls_sock.getpeercert(binary_form=True)
    except (ssl.SSLError, socket.timeout, socket.gaierror, ConnectionError, OSError) as e:
        logger.debug("TLS grab failed for %s: %s", hostname, e)
        return [{"hostname": hostname, "message": f"tls grab failed: {e}"}]
    if not der_cert:
        return [{"hostname": hostname, "message": "no certificate returned"}]
    cert = x509.load_der_x509_certificate(der_cert)
    try:
        subject_cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    except (IndexError, Exception):
        subject_cn = ""
    try:
        issuer_cn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    except (IndexError, Exception):
        issuer_cn = ""
    try:
        issuer_org = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value
    except (IndexError, Exception):
        issuer_org = ""
    san_dns_names: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_dns_names = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    return [{
        "hostname": hostname, "port": port, "cert": {
            "subject_cn": subject_cn, "issuer_cn": issuer_cn,
            "issuer_org": issuer_org, "serial_number": format(cert.serial_number, "x"),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
            "san_dns_names": san_dns_names,
        },
    }]


async def dns_mail_records(job: dict, pool) -> list[dict[str, Any]]:
    domain = job["entity_value"]
    result: dict[str, Any] = {"domain": domain}
    mx_records: list[dict] = []
    try:
        answers = dns.resolver.resolve(domain, "MX")
        for rdata in answers:
            mx_records.append({"preference": rdata.preference,
                               "exchange": str(rdata.exchange).rstrip(".")})
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    result["mx_records"] = mx_records
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = b" ".join(rdata.strings).decode(errors="replace")
            if txt.startswith("v=spf1"):
                result["spf_record"] = txt
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = b" ".join(rdata.strings).decode(errors="replace")
            if txt.startswith("v=DMARC1"):
                result["dmarc_record"] = txt
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    return [result]


async def crtsh_search(job: dict, pool) -> list[dict[str, Any]]:
    domain = job["entity_value"]
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    max_retries = 3
    retry_statuses = (429, 502, 503, 504)
    async with httpx.AsyncClient(timeout=30.0) as client:
        certs = None
        for attempt in range(max_retries):
            resp = await client.get(url)
            if resp.status_code == 200:
                certs = resp.json()
                break
            if resp.status_code in retry_statuses and attempt < max_retries - 1:
                retry_after = resp.headers.get("Retry-After")
                wait = float(retry_after) if retry_after else (2 ** attempt) + random.uniform(0, 1)
                logger.warning("crtsh rate limited (status %d) for %s, retrying %.1fs",
                               resp.status_code, domain, wait)
                await asyncio.sleep(wait)
                continue
            resp.raise_for_status()
        if certs is None:
            raise RuntimeError("crtsh request failed after all retries")
    return [{
        "name_value": c.get("name_value", ""),
        "issuer_name_id": c.get("issuer_name_id", ""),
        "not_before": c.get("not_before", ""),
        "not_after": c.get("not_after", ""),
        "serial_number": c.get("serial_number", ""),
        "fingerprint": c.get("fingerprint", ""),
    } for c in certs]


async def subdomain_enum(job: dict, pool) -> list[dict[str, Any]]:
    domain = job["entity_value"]
    results: list[dict[str, Any]] = []
    try:
        proc = await asyncio.create_subprocess_exec(
            "subfinder", "-d", domain, "-json", "-silent", "-nW", "-all",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        for line in stdout.decode().strip().split("\n"):
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return results


async def subdomain_takeover(job: dict, pool) -> list[dict[str, Any]]:
    hostname = job["entity_value"]
    fingerprints = {
        "github.io": "github_pages", "herokuapp.com": "heroku",
        "s3.amazonaws.com": "aws_s3", "azurewebsites.net": "azure_app",
        "cloudfront.net": "aws_cloudfront", "surge.sh": "surge",
        "bitbucket.io": "bitbucket", "netlify.app": "netlify",
        "firebaseapp.com": "firebase", "ghost.io": "ghost",
    }
    vulnerable = [{"pattern": p, "service": s}
                  for p, s in fingerprints.items() if p in hostname.lower()]
    return [{"hostname": hostname, "takeover_check": {
        "fingerprint_matches": vulnerable, "takeover_risk": len(vulnerable) > 0,
    }}]


async def passive_dns(job: dict, pool) -> list[dict[str, Any]]:
    domain = job["entity_value"]
    api_key = ""  # configured via env/API in production
    if not api_key:
        return [{"domain": domain, "message": "no securitytrails api key"}]
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(
            f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
            headers={"APIKEY": api_key})
        if resp.status_code == 404:
            return [{"domain": domain, "message": "no dns history"}]
        resp.raise_for_status()
        records = resp.json().get("records", [])
    return [{"domain": domain, "passive_dns": {
        "a_records": [{"ip": r.get("values", [{}])[0].get("ip", ""),
                       "first_seen": r.get("first_seen", ""),
                       "last_seen": r.get("last_seen", "")} for r in records],
    }}]


async def rdap_lookup(job: dict, pool) -> list[dict[str, Any]]:
    asn = job["entity_value"]
    numeric_asn = asn.replace("AS", "")
    results: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(f"https://rdap.db.ripe.net/autnum/{numeric_asn}")
        resp.raise_for_status()
        data = resp.json()
        try:
            resp2 = await client.get(f"https://rdap.arin.net/registry/autnum/{numeric_asn}")
            resp2.raise_for_status()
            data_arin = resp2.json()
        except Exception:
            data_arin = {}
        for entity in data.get("entities", []):
            for role in entity.get("roles", []):
                if role in ("registrant", "org"):
                    results.append({"asn": asn, "org": entity.get("handle", ""), "source": "ripe"})
    return results if results else [{"asn": asn, "message": "no RDAP results"}]


async def reverse_whois(job: dict, pool) -> list[dict[str, Any]]:
    domain = job["entity_value"]
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(f"https://reversewhois.io/?searchterm={domain}",
                                headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        domains = re.findall(r'<a[^>]*>([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})</a>', resp.text)
        registrars = re.findall(r'(\d{4}-\d{2}-\d{2})', resp.text)
    return [{"domain": domain, "reverse_whois": {
        "related_domains": list(set(domains)), "dates_found": registrars}}]


async def domain_rdap(job: dict, pool) -> list[dict[str, Any]]:
    domain = job["entity_value"]
    parts = domain.rsplit(".", 1)
    tld = parts[-1].lower() if len(parts) > 1 else ""
    bases = {"com": "https://rdap.verisign.com/com/v1",
             "net": "https://rdap.verisign.com/net/v1",
             "org": "https://rdap.org"}
    base = bases.get(tld, "https://rdap.org")
    url = f"{base}/domain/{domain}"
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.debug("RDAP lookup failed for %s: %s", domain, e)
            return [{"domain": domain, "message": f"rdap lookup failed: {e}"}]
    result: dict[str, Any] = {"domain": domain, "source": "domain_rdap"}
    if data.get("status"):
        result["status"] = data["status"]

    def _vcard_fn(entities):
        for entity in entities:
            vcard_arr = entity.get("vcardArray", [])
            if isinstance(vcard_arr, list) and len(vcard_arr) >= 2:
                for item in vcard_arr[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        return str(item[3])
        return ""

    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        if "registrar" in roles:
            result["registrar"] = _vcard_fn([entity])
        if "registrant" in roles:
            result["registrant_org"] = _vcard_fn([entity])
    if not result.get("registrant_org"):
        org = _vcard_fn(data.get("entities", []))
        if org:
            result["registrant_org"] = org
    for event in data.get("events", []):
        action, date = event.get("eventAction", ""), event.get("eventDate", "")
        if action == "registration":
            result["created_date"] = date
        elif action == "expiration":
            result["expiration_date"] = date
        elif action == "last changed":
            result["updated_date"] = date
    nameservers = [ns.get("ldhName", "") for ns in data.get("nameservers", [])]
    if nameservers:
        result["nameservers"] = nameservers
    return [result]


async def shodan_enrich(job: dict, pool) -> list[dict[str, Any]]:
    ip = job["entity_value"]
    api_key = ""
    async with httpx.AsyncClient(timeout=15.0) as client:
        if api_key:
            resp = await client.get(f"https://api.shodan.io/shodan/host/{ip}",
                                    params={"key": api_key})
            if resp.status_code == 404:
                return [{"ip": ip, "message": "no shodan data"}]
            resp.raise_for_status()
            data = resp.json()
            return [{"ip": ip, "shodan": {
                "ports": data.get("ports", []), "hostnames": data.get("hostnames", []),
                "domains": data.get("domains", []), "vulns": data.get("vulns", []),
                "org": data.get("org", ""), "isp": data.get("isp", ""),
                "asn": data.get("asn", ""), "country_name": data.get("country_name", ""),
                "city": data.get("city", ""), "os": data.get("os", ""),
                "data": data.get("data", []),
            }}]
        else:
            resp = await client.get(f"https://internetdb.shodan.io/{ip}")
            if resp.status_code == 404:
                return [{"ip": ip, "message": "no shodan data"}]
            resp.raise_for_status()
            data = resp.json()
            return [{"ip": ip, "ports": data.get("ports", []),
                     "hostnames": data.get("hostnames", []), "cpes": data.get("cpes", []),
                     "vulns": data.get("vulns", []), "source": "shodan"}]


async def abuseipdb_enrich(job: dict, pool) -> list[dict[str, Any]]:
    ip = job["entity_value"]
    api_key = ""
    if not api_key:
        return [{"ip": ip, "message": "no abuseipdb api key configured"}]
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get("https://api.abuseipdb.com/api/v2/check",
                                params={"ipAddress": ip, "maxAgeInDays": "90"},
                                headers={"Key": api_key, "Accept": "application/json"})
        if resp.status_code == 404:
            return [{"ip": ip, "message": "no abuseipdb data"}]
        resp.raise_for_status()
        data = resp.json().get("data", {})
    return [{"ip": ip, "abuseipdb": {
        "abuseConfidenceScore": data.get("abuseConfidenceScore"),
        "totalReports": data.get("totalReports"),
        "lastReportedAt": data.get("lastReportedAt"),
        "usageType": data.get("usageType", ""), "hostnames": data.get("hostnames", []),
        "domain": data.get("domain", ""), "countryCode": data.get("countryCode", ""),
        "isp": data.get("isp", ""),
    }}]


async def greynoise_enrich(job: dict, pool) -> list[dict[str, Any]]:
    ip = job["entity_value"]
    api_key = ""
    headers = {"key": api_key} if api_key else {}
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(f"https://api.greynoise.io/v3/community/{ip}", headers=headers)
        if resp.status_code == 404:
            return [{"ip": ip, "message": "no greynoise data"}]
        resp.raise_for_status()
        data = resp.json()
    return [{"ip": ip, "greynoise": {
        "classification": data.get("classification", ""),
        "noise": data.get("noise", False), "riot": data.get("riot", False),
        "name": data.get("name", ""), "link": data.get("link", ""),
    }}]


async def urlscan_enrich(job: dict, pool) -> list[dict[str, Any]]:
    domain = job["entity_value"]
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get("https://urlscan.io/api/v1/search/",
                                params={"q": f"domain:{domain}", "size": 100})
        if resp.status_code == 404:
            return [{"domain": domain, "message": "no urlscan data"}]
        resp.raise_for_status()
        data = resp.json()
    return [{"domain": domain, "urlscan": {
        "total_results": data.get("total", 0),
        "results": [{
            "page_url": r.get("page", {}).get("url", ""),
            "ip": r.get("page", {}).get("ip", ""),
            "domain": r.get("page", {}).get("domain", ""),
            "is_malicious": r.get("isMalicious", False),
            "screenshot_url": r.get("screenshot", ""),
        } for r in data.get("results", [])],
    }}]


async def censys_enrich(job: dict, pool) -> list[dict[str, Any]]:
    ip = job["entity_value"]
    api_id = api_secret = ""
    if not api_id or not api_secret:
        return [{"ip": ip, "message": "censys API credentials not configured"}]
    auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(f"https://search.censys.io/api/v2/hosts/{ip}",
                                headers={"Authorization": f"Basic {auth}"})
        if resp.status_code == 404:
            return [{"ip": ip, "message": "no censys data"}]
        resp.raise_for_status()
        data = resp.json().get("result", {})
    return [{"ip": ip, "censys": {
        "services": data.get("services", []), "location": data.get("location", {}),
        "autonomous_system": data.get("autonomous_system", {}),
        "last_updated_at": data.get("last_updated_at", ""),
    }}]


# ---------------------------------------------------------------------------
# Registry: pivot_type → handler function
# ---------------------------------------------------------------------------

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
    "passive_dns": passive_dns,
    "rdap_lookup": rdap_lookup,
    "reverse_whois": reverse_whois,
    "domain_rdap": domain_rdap,
    "shodan_enrich": shodan_enrich,
    "abuseipdb_enrich": abuseipdb_enrich,
    "greynoise_enrich": greynoise_enrich,
    "urlscan_enrich": urlscan_enrich,
    "censys_enrich": censys_enrich,
}

# Source name mapping (pivot_type → source_name) for use by worker
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
    "passive_dns": "securitytrails",
    "rdap_lookup": "rdap",
    "reverse_whois": "reverse_whois",
    "domain_rdap": "domain_rdap",
    "shodan_enrich": "shodan",
    "abuseipdb_enrich": "abuseipdb",
    "greynoise_enrich": "greynoise",
    "urlscan_enrich": "urlscan",
    "censys_enrich": "censys",
}
