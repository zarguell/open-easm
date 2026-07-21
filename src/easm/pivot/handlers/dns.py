"""DNS-related pivot handlers.

* ``reverse_dns``     — PTR lookups across an IP range
* ``dns_resolve``     — forward A + CNAME resolution for a hostname
* ``domain_extract``  — apex-domain extraction from a hostname
* ``dns_mail_records``— MX / SPF / DMARC collection for a domain
* ``ip_in_range``     — IP-to-range relationship probe
* ``ip_to_asn``       — ASN ownership lookup via RIPEstat
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Any

import dns.exception
import dns.resolver
import dns.reversename
import httpx
import tldextract

from easm.network_guard import create_guard_client

logger = logging.getLogger(__name__)


async def dns_resolve(job: dict[str, Any], pool: Any) -> list[dict[str, Any]]:
    hostname = job["entity_value"]
    results: list[dict[str, Any]] = []

    # Resolve CNAME chain first — reveals SaaS hosting (github.io, netlify.app, etc.)
    try:
        cname_answers = dns.resolver.resolve(hostname, "CNAME")
        for rdata in cname_answers:
            target = str(rdata.target).rstrip(".")
            results.append({
                "hostname": hostname,
                "record_type": "CNAME",
                "cname_target": target,
            })
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        logger.debug("no CNAME record for %s", hostname)
    except (dns.exception.Timeout, OSError) as e:
        logger.debug(
            "CNAME resolution failed for %s",
            hostname, extra={"error": str(e)},
        )

    # Resolve A records — always needed for IP entity creation
    try:
        answers = dns.resolver.resolve(hostname, "A")
        for rdata in answers:
            results.append({"hostname": hostname, "ip": str(rdata), "record_type": "A"})
    except dns.resolver.NXDOMAIN:
        logger.debug("hostname %s does not resolve (NXDOMAIN)", hostname)
    except (dns.resolver.NoAnswer, dns.exception.DNSException, dns.exception.Timeout, OSError) as e:
        logger.debug(
            "A record resolution failed for %s",
            hostname, extra={"error": str(e)},
        )
    return results


async def reverse_dns(job: dict[str, Any], pool: Any) -> list[dict[str, Any]]:
    ip_range = job["entity_value"]
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError:
        return []

    sem = asyncio.Semaphore(50)  # limit concurrent DNS lookups

    async def _ptr(ip_str: str) -> dict[str, Any] | None:
        async with sem:
            try:
                rev = dns.reversename.from_address(ip_str)
                answers = await asyncio.to_thread(dns.resolver.resolve, rev, "PTR")
                for rdata in answers:
                    return {"ip": ip_str, "hostname": str(rdata.target).rstrip(".")}
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException,
                    dns.exception.Timeout, OSError) as e:
                logger.debug(
                    "PTR lookup failed for %s",
                    ip_str, extra={"error": str(e)},
                )
        return None

    tasks = [asyncio.create_task(_ptr(str(ip))) for ip in network.hosts()]
    results = [r for r in (await asyncio.gather(*tasks)) if r is not None]
    return results


async def domain_extract(job: dict[str, Any], pool: Any) -> list[dict[str, Any]]:
    hostname = job["entity_value"]
    extracted = tldextract.extract(hostname)
    apex = f"{extracted.domain}.{extracted.suffix}".lower()
    if apex == hostname.lower():
        return []
    return [{"domain": apex, "source_hostname": hostname}]


async def dns_mail_records(job: dict[str, Any], pool: Any) -> list[dict[str, Any]]:
    domain = job["entity_value"]
    result: dict[str, Any] = {"domain": domain}
    mx_records: list[dict[str, Any]] = []
    try:
        answers = dns.resolver.resolve(domain, "MX")
        for rdata in answers:
            mx_records.append({"preference": rdata.preference,
                               "exchange": str(rdata.exchange).rstrip(".")})
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        logger.debug("no MX record for %s", domain)
    result["mx_records"] = mx_records
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = b" ".join(rdata.strings).decode(errors="replace")
            if txt.startswith("v=spf1"):
                result["spf_record"] = txt
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        logger.debug("no SPF record for %s", domain)
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = b" ".join(rdata.strings).decode(errors="replace")
            if txt.startswith("v=DMARC1"):
                result["dmarc_record"] = txt
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        logger.debug("no DMARC record for %s", domain)
    return [result]


async def ip_in_range(job: dict[str, Any], pool: Any) -> list[dict[str, Any]]:
    """Check if an IP falls within any known IP range and surface the range id."""
    ip = job["entity_value"]
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return []
    rows = await pool.fetch(
        """
        SELECT id, entity_value FROM entities
        WHERE org_id = $1 AND target_id = $2 AND entity_type = 'ip_range'
        """,
        job["org_id"], job["target_id"],
    )
    results: list[dict[str, Any]] = []
    for row in rows:
        try:
            network = ipaddress.ip_network(row["entity_value"], strict=False)
            if ip_obj in network:
                results.append({
                    "source_ip": ip,
                    "ip_range": row["entity_value"],
                    "range_entity_id": str(row["id"]),
                })
        except ValueError:
            continue
    return results


async def ip_to_asn(
    job: dict[str, Any],
    pool: Any,
    *,
    http_client: httpx.AsyncClient | None = None,
    limiters: Any = None,
) -> list[dict[str, Any]]:
    ip = job["entity_value"]
    results: list[dict[str, Any]] = []
    try:
        network = ipaddress.ip_network(ip, strict=False)
        if network.num_addresses > 1:
            return [{"ip": ip, "message": "ip_to_asn skipped for ranges"}]
    except ValueError:
        logger.debug("ip_to_asn received non-IP value: %s", ip)

    url = f"https://stat.ripe.net/data/network-info/data.json?resource={ip}"
    if http_client is not None:
        resp = await http_client.get(url, timeout=15.0)
        if resp.status_code != 200:
            return [{"ip": ip, "message": "ripe stat lookup failed"}]
        data = resp.json()
    else:
        async with create_guard_client(timeout=15.0) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return [{"ip": ip, "message": "ripe stat lookup failed"}]
            data = resp.json()

    infos = data.get("data", {}).get("asns", [])
    if not infos:
        return [{"ip": ip, "message": "no asn data found"}]

    for info in infos:
        asn_num = info.get("asn")
        holder = info.get("holder", "")
        if asn_num:
            results.append({
                "ip": ip,
                "asn": f"AS{asn_num}",
                "as_name": holder,
                "source": "ripe_stat",
            })
    return results if results else [{"ip": ip, "message": "no asn data found"}]
