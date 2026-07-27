"""Third-party enrichment pivot handlers.

* ``geoip_enrich``      — MaxMind GeoLite2 location (local-file lookup)
* ``shodan_enrich``     — Shodan InternetDB / API
* ``abuseipdb_enrich``  — AbuseIPDB reputation
* ``greynoise_enrich``  — GreyNoise community classification
* ``urlscan_enrich``    — urlscan.io search
* ``censys_enrich``     — Censys host inventory
* ``reverse_whois``     — reversewhois.io domain search
* ``passive_dns``       — SecurityTrails A-record history
* ``domain_rdap``       — RDAP lookup for domains (WHOIS + dates)
* ``rdap_lookup``       — RDAP lookup for autonomous systems
* ``subdomain_enum``    — subfinder subprocess invocation (used by pivots)

The enrichment-key registry (``_enrichment_keys``, ``configure_enrichment_keys``)
is loaded once at startup from config + env vars.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
from typing import Any

import httpx
import tldextract

from easm.geoip import GeoIpLookup
from easm.network_guard import create_guard_client

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Enrichment API key resolution (configured at startup)
# ---------------------------------------------------------------------------

_enrichment_keys: dict[str, str] = {}


def configure_enrichment_keys(config: Any) -> None:
    """Load enrichment API keys from config. Called once at startup."""
    keys = getattr(config, "enrichment", None)
    _enrichment_keys["shodan"] = _resolve(keys, "shodan", "SHODAN_API_KEY")
    _enrichment_keys["abuseipdb"] = _resolve(keys, "abuseipdb", "ABUSEIPDB_API_KEY")
    _enrichment_keys["greynoise"] = _resolve(keys, "greynoise", "GREYNOISE_API_KEY")
    _enrichment_keys["censys_id"] = _resolve(keys, "censys_id", "CENSYS_API_ID")
    _enrichment_keys["censys_secret"] = _resolve(keys, "censys_secret", "CENSYS_API_SECRET")
    _enrichment_keys["securitytrails"] = _resolve(keys, "securitytrails", "SECURITYTRAILS_API_KEY")


def _resolve(keys_obj: Any, attr: str, env_var: str) -> str:
    """Config value > environment variable > empty string."""
    config_val = getattr(keys_obj, attr, None) if keys_obj else None
    return config_val or os.environ.get(env_var, "")


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


async def geoip_enrich(job: dict[str, Any], pool: Any) -> list[dict[str, Any]]:
    ip = job["entity_value"]
    lookup = GeoIpLookup()
    result = lookup.lookup(ip)
    if result is None:
        return [{"ip": ip, "message": "no geo-IP data available"}]
    return [{"ip": ip, "geo": result.to_dict()}]


async def subdomain_enum(job: dict[str, Any], pool: Any) -> list[dict[str, Any]]:
    """Passive subdomain enumeration via ``subfinder``.

    Invoked as a pivot handler (not a runner). The discovery-runner form
    lives in :mod:`easm.runners`.
    """
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
                except json.JSONDecodeError as e:
                    logger.debug(
                        "skipping malformed subfinder JSON line",
                        extra={"line": line[:100], "error": str(e)},
                    )
    except FileNotFoundError:
        logger.debug("subfinder binary not found on PATH")
    except (TimeoutError, OSError, json.JSONDecodeError) as e:
        logger.debug(
            "subdomain enum failed for %s",
            domain, exc_info=True, extra={"error": str(e)},
        )
    return results


async def passive_dns(
    job: dict[str, Any],
    pool: Any,
    *,
    http_client: httpx.AsyncClient | None = None,
    limiters: Any = None,
) -> list[dict[str, Any]]:
    domain = job["entity_value"]
    api_key = _enrichment_keys.get("securitytrails", "")
    if not api_key:
        return [{"domain": domain, "message": "no securitytrails api key"}]
    sem = limiters.securitytrails if limiters else None
    if sem:
        await sem.acquire()
    try:
        if http_client is not None:
            resp = await http_client.get(
                f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
                headers={"APIKEY": api_key})
            if resp.status_code == 404:
                return [{"domain": domain, "message": "no dns history"}]
            resp.raise_for_status()
            records = resp.json().get("records", [])
        else:
            async with create_guard_client(timeout=15.0) as client:
                resp = await client.get(
                    f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
                    headers={"APIKEY": api_key})
                if resp.status_code == 404:
                    return [{"domain": domain, "message": "no dns history"}]
                resp.raise_for_status()
                records = resp.json().get("records", [])
    finally:
        if sem:
            sem.release()
    return [{"domain": domain, "passive_dns": {
        "a_records": [{"ip": r.get("values", [{}])[0].get("ip", ""),
                        "first_seen": r.get("first_seen", ""),
                        "last_seen": r.get("last_seen", "")} for r in records],
    }}]


async def rdap_lookup(
    job: dict[str, Any],
    pool: Any,
    *,
    http_client: httpx.AsyncClient | None = None,
    limiters: Any = None,
) -> list[dict[str, Any]]:
    asn = job["entity_value"]
    numeric_asn = asn.replace("AS", "")
    results: list[dict[str, Any]] = []
    sem = limiters.rdap if limiters else None
    if sem:
        await sem.acquire()
    try:
        if http_client is not None:
            try:
                resp = await http_client.get(
                    f"https://rdap.db.ripe.net/registry/autnum/{numeric_asn}",
                    follow_redirects=True
                )
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 301:
                    data = {}
                else:
                    raise
            try:
                resp2 = await http_client.get(
                    f"https://rdap.arin.net/registry/autnum/{numeric_asn}",
                    follow_redirects=True
                )
                resp2.raise_for_status()
                data_arin = resp2.json()
            except (httpx.RequestError, httpx.HTTPStatusError, ValueError) as e:
                logger.debug(
                    "RDAP ARIN lookup failed for AS %s",
                    numeric_asn, extra={"error": str(e)},
                )
                data_arin = {}
            for entity in data.get("entities", []):
                for role in entity.get("roles", []):
                    if role in ("registrant", "org"):
                        results.append({"asn": asn, "org": entity.get("handle", ""), "source": "ripe"})
        else:
            async with create_guard_client(timeout=15.0) as client:
                try:
                    resp = await client.get(
                        f"https://rdap.db.ripe.net/registry/autnum/{numeric_asn}",
                        follow_redirects=True
                    )
                    resp.raise_for_status()
                    data = resp.json()
                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 301:
                        data = {}
                    else:
                        raise
                try:
                    resp2 = await client.get(f"https://rdap.arin.net/registry/autnum/{numeric_asn}")
                    resp2.raise_for_status()
                    data_arin = resp2.json()
                except (httpx.RequestError, httpx.HTTPStatusError, ValueError) as e:
                    logger.debug(
                        "RDAP ARIN lookup failed for AS %s",
                        numeric_asn, extra={"error": str(e)},
                    )
                    data_arin = {}
                for entity in data.get("entities", []):
                    for role in entity.get("roles", []):
                        if role in ("registrant", "org"):
                            results.append({"asn": asn, "org": entity.get("handle", ""), "source": "ripe"})
    finally:
        if sem:
            sem.release()
    return results if results else [{"asn": asn, "message": "no RDAP results"}]


async def reverse_whois(
    job: dict[str, Any],
    pool: Any,
    *,
    http_client: httpx.AsyncClient | None = None,
    limiters: Any = None,
) -> list[dict[str, Any]]:
    domain = job["entity_value"]
    sem = limiters.rdap if limiters else None
    if sem:
        await sem.acquire()
    try:
        if http_client is not None:
            resp = await http_client.get(f"https://reversewhois.io/?searchterm={domain}",
                                         headers={"User-Agent": "Mozilla/5.0"})
            resp.raise_for_status()
            domains = re.findall(r'<a[^>]*>([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})</a>', resp.text)
            registrars = re.findall(r'(\d{4}-\d{2}-\d{2})', resp.text)
        else:
            async with create_guard_client(timeout=30.0) as client:
                resp = await client.get(f"https://reversewhois.io/?searchterm={domain}",
                                        headers={"User-Agent": "Mozilla/5.0"})
                resp.raise_for_status()
                domains = re.findall(r'<a[^>]*>([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})</a>', resp.text)
                registrars = re.findall(r'(\d{4}-\d{2}-\d{2})', resp.text)
    finally:
        if sem:
            sem.release()
    return [{"domain": domain, "reverse_whois": {
        "related_domains": list(set(domains)), "dates_found": registrars}}]


async def domain_rdap(
    job: dict[str, Any],
    pool: Any,
    *,
    http_client: httpx.AsyncClient | None = None,
    limiters: Any = None,
) -> list[dict[str, Any]]:
    domain = job["entity_value"]
    parts = domain.rsplit(".", 1)
    tld = parts[-1].lower() if len(parts) > 1 else ""
    bases = {"com": "https://rdap.verisign.com/com/v1",
             "net": "https://rdap.verisign.com/net/v1",
             "org": "https://rdap.org"}
    base = bases.get(tld, "https://rdap.org")
    url = f"{base}/domain/{domain}"
    sem = limiters.rdap if limiters else None
    if sem:
        await sem.acquire()
    try:
        data: dict[str, Any]
        if http_client is not None:
            try:
                resp = await http_client.get(url)
                resp.raise_for_status()
                data = resp.json()
            except (httpx.RequestError, httpx.HTTPStatusError, ValueError) as e:
                logger.debug("RDAP lookup failed for %s: %s", domain, e)
                return [{"domain": domain, "message": f"rdap lookup failed: {e}"}]
        else:
            async with create_guard_client(timeout=15.0) as client:
                try:
                    resp = await client.get(url)
                    resp.raise_for_status()
                    data = resp.json()
                except (httpx.RequestError, httpx.HTTPStatusError, ValueError) as e:
                    logger.debug("RDAP lookup failed for %s: %s", domain, e)
                    return [{"domain": domain, "message": f"rdap lookup failed: {e}"}]
    finally:
        if sem:
            sem.release()
    result: dict[str, Any] = {"domain": domain, "source": "domain_rdap"}
    if data.get("status"):
        result["status"] = data["status"]

    def _vcard_fn(entities: list[dict[str, Any]]) -> str:
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


async def shodan_enrich(
    job: dict[str, Any],
    pool: Any,
    *,
    http_client: httpx.AsyncClient | None = None,
    limiters: Any = None,
) -> list[dict[str, Any]]:
    ip = job["entity_value"]
    api_key = _enrichment_keys.get("shodan", "")
    sem = limiters.shodan if limiters else None
    if sem:
        await sem.acquire()
    try:
        if http_client is not None:
            if api_key:
                return await _shodan_api_lookup(http_client, ip, api_key)
            return await _shodan_internetdb_lookup(http_client, ip)
        async with create_guard_client(timeout=15.0) as client:
            if api_key:
                return await _shodan_api_lookup(client, ip, api_key)
            return await _shodan_internetdb_lookup(client, ip)
    finally:
        if sem:
            sem.release()


async def _shodan_api_lookup(
    client: httpx.AsyncClient, ip: str, api_key: str,
) -> list[dict[str, Any]]:
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


async def _shodan_internetdb_lookup(
    client: httpx.AsyncClient, ip: str,
) -> list[dict[str, Any]]:
    resp = await client.get(f"https://internetdb.shodan.io/{ip}")
    if resp.status_code == 404:
        return [{"ip": ip, "message": "no shodan data"}]
    resp.raise_for_status()
    data = resp.json()
    return [{"ip": ip, "ports": data.get("ports", []),
             "hostnames": data.get("hostnames", []), "cpes": data.get("cpes", []),
             "vulns": data.get("vulns", []), "source": "shodan"}]


async def abuseipdb_enrich(
    job: dict[str, Any],
    pool: Any,
    *,
    http_client: httpx.AsyncClient | None = None,
    limiters: Any = None,
) -> list[dict[str, Any]]:
    ip = job["entity_value"]
    api_key = _enrichment_keys.get("abuseipdb", "")
    if not api_key:
        return [{"ip": ip, "message": "no abuseipdb api key configured"}]
    sem = limiters.abuseipdb if limiters else None
    if sem:
        await sem.acquire()
    try:
        if http_client is not None:
            data = await _abuseipdb_fetch(http_client, ip, api_key)
        else:
            async with create_guard_client(timeout=15.0) as client:
                data = await _abuseipdb_fetch(client, ip, api_key)
    finally:
        if sem:
            sem.release()
    return [{"ip": ip, "abuseipdb": {
        "abuseConfidenceScore": data.get("abuseConfidenceScore"),
        "totalReports": data.get("totalReports"),
        "lastReportedAt": data.get("lastReportedAt"),
        "usageType": data.get("usageType", ""), "hostnames": data.get("hostnames", []),
        "domain": data.get("domain", ""), "countryCode": data.get("countryCode", ""),
        "isp": data.get("isp", ""),
    }}]


async def _abuseipdb_fetch(
    client: httpx.AsyncClient, ip: str, api_key: str,
) -> dict[str, Any]:
    resp = await client.get("https://api.abuseipdb.com/api/v2/check",
                            params={"ipAddress": ip, "maxAgeInDays": "90"},
                            headers={"Key": api_key, "Accept": "application/json"})
    if resp.status_code == 404:
        return {}
    resp.raise_for_status()
    return resp.json().get("data", {})


async def greynoise_enrich(
    job: dict[str, Any],
    pool: Any,
    *,
    http_client: httpx.AsyncClient | None = None,
    limiters: Any = None,
) -> list[dict[str, Any]]:
    ip = job["entity_value"]
    api_key = _enrichment_keys.get("greynoise", "")
    headers = {"key": api_key} if api_key else {}
    sem = limiters.greynoise if limiters else None
    if sem:
        await sem.acquire()
    try:
        if http_client is not None:
            resp = await http_client.get(
                f"https://api.greynoise.io/v3/community/{ip}", headers=headers)
            if resp.status_code == 404:
                return [{"ip": ip, "message": "no greynoise data"}]
            resp.raise_for_status()
            data = resp.json()
        else:
            async with create_guard_client(timeout=15.0) as client:
                resp = await client.get(
                    f"https://api.greynoise.io/v3/community/{ip}", headers=headers)
                if resp.status_code == 404:
                    return [{"ip": ip, "message": "no greynoise data"}]
                resp.raise_for_status()
                data = resp.json()
    finally:
        if sem:
            sem.release()
    return [{"ip": ip, "greynoise": {
        "classification": data.get("classification", ""),
        "noise": data.get("noise", False), "riot": data.get("riot", False),
        "name": data.get("name", ""), "link": data.get("link", ""),
    }}]


async def urlscan_enrich(
    job: dict[str, Any],
    pool: Any,
    *,
    http_client: httpx.AsyncClient | None = None,
    limiters: Any = None,
) -> list[dict[str, Any]]:
    domain = job["entity_value"]
    sem = limiters.urlscan if limiters else None
    if sem:
        await sem.acquire()
    try:
        if http_client is not None:
            resp = await http_client.get("https://urlscan.io/api/v1/search/",
                                         params={"q": f"domain:{domain}", "size": 100})
            if resp.status_code == 404:
                return [{"domain": domain, "message": "no urlscan data"}]
            resp.raise_for_status()
            data = resp.json()
        else:
            async with create_guard_client(timeout=30.0) as client:
                resp = await client.get("https://urlscan.io/api/v1/search/",
                                        params={"q": f"domain:{domain}", "size": 100})
                if resp.status_code == 404:
                    return [{"domain": domain, "message": "no urlscan data"}]
                resp.raise_for_status()
                data = resp.json()
    finally:
        if sem:
            sem.release()
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


async def censys_enrich(
    job: dict[str, Any],
    pool: Any,
    *,
    http_client: httpx.AsyncClient | None = None,
    limiters: Any = None,
) -> list[dict[str, Any]]:
    ip = job["entity_value"]
    api_id = _enrichment_keys.get("censys_id", "")
    api_secret = _enrichment_keys.get("censys_secret", "")
    if not api_id or not api_secret:
        return [{"ip": ip, "message": "censys API credentials not configured"}]
    auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    sem = limiters.censys if limiters else None
    if sem:
        await sem.acquire()
    try:
        if http_client is not None:
            resp = await http_client.get(f"https://search.censys.io/api/v2/hosts/{ip}",
                                         headers={"Authorization": f"Basic {auth}"})
            if resp.status_code == 404:
                return [{"ip": ip, "message": "no censys data"}]
            resp.raise_for_status()
            data = resp.json().get("result", {})
        else:
            async with create_guard_client(timeout=15.0) as client:
                resp = await client.get(f"https://search.censys.io/api/v2/hosts/{ip}",
                                        headers={"Authorization": f"Basic {auth}"})
                if resp.status_code == 404:
                    return [{"ip": ip, "message": "no censys data"}]
                resp.raise_for_status()
                data = resp.json().get("result", {})
    finally:
        if sem:
            sem.release()
    return [{"ip": ip, "censys": {
        "services": data.get("services", []), "location": data.get("location", {}),
        "autonomous_system": data.get("autonomous_system", {}),
        "last_updated_at": data.get("last_updated_at", ""),
    }}]
