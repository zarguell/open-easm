"""Subdomain takeover signal collection.

``takeover_detect`` collects a DNS graph, provider classification,
HTTP/TLS evidence, and RDAP domain-lifecycle signals for a hostname.
The correlation engine evaluates the signals to produce severity ×
confidence findings.

This module owns the fingerprint databases (CNAME + HTTP) and the
``_dns_chain`` / ``_classify_provider`` / ``_http_probe`` helpers — the
shape of takeover detection does not appear anywhere else in the codebase.
"""

from __future__ import annotations

import asyncio
import logging
import re
import ssl
from typing import Any

import dns.exception
import dns.resolver
import httpx
import tldextract
from cryptography import x509

from easm.network_guard import create_guard_client

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Provider fingerprint database for subdomain takeover detection
# Each entry: suffix → (provider_id, claimability: unclaimed|conditional|owned)
# claimability = unclaimed: platform allows any tenant to bind a hostname
# claimability = conditional: platform requires ownership verification
# claimability = owned: actively hosted by a known org (not takeover-able)
# ---------------------------------------------------------------------------
_TAKEOVER_FINGERPRINTS: dict[str, tuple[str, str]] = {
    # Cloud & CDN
    "cloudfront.net": ("aws_cloudfront", "conditional"),
    "s3.amazonaws.com": ("aws_s3", "unclaimed"),
    "s3-website.amazonaws.com": ("aws_s3_website", "unclaimed"),
    "s3-website-us-east-1.amazonaws.com": ("aws_s3_website", "unclaimed"),
    "azureedge.net": ("azure_cdn", "conditional"),
    "azurewebsites.net": ("azure_app_service", "unclaimed"),
    "azurefd.net": ("azure_front_door", "conditional"),
    "trafficmanager.net": ("azure_traffic_manager", "conditional"),
    "cloudapp.net": ("azure_cloud_service", "unclaimed"),
    "blob.core.windows.net": ("azure_blob", "unclaimed"),
    # Static hosting & PaaS
    "github.io": ("github_pages", "unclaimed"),
    "herokuapp.com": ("heroku", "unclaimed"),
    "herokussl.com": ("heroku_ssl", "unclaimed"),
    "netlify.app": ("netlify", "unclaimed"),
    "netlify.com": ("netlify", "unclaimed"),
    "firebaseapp.com": ("firebase", "unclaimed"),
    "web.app": ("firebase", "unclaimed"),
    "pages.dev": ("cloudflare_pages", "unclaimed"),
    "r2.dev": ("cloudflare_r2", "unclaimed"),
    "fly.dev": ("fly_io", "unclaimed"),
    "render.com": ("render", "unclaimed"),
    "onrender.com": ("render", "unclaimed"),
    "railway.app": ("railway", "unclaimed"),
    "vercel.app": ("vercel", "unclaimed"),
    "pantheon.io": ("pantheon", "unclaimed"),
    "pantheonsite.io": ("pantheon", "unclaimed"),
    "surge.sh": ("surge", "unclaimed"),
    "bitbucket.io": ("bitbucket", "unclaimed"),
    "ghost.io": ("ghost", "unclaimed"),
    "pages.gitlab.io": ("gitlab_pages", "unclaimed"),
    # SaaS & status pages
    "myshopify.com": ("shopify", "unclaimed"),
    "shopify.com": ("shopify", "conditional"),
    "readme.io": ("readme", "conditional"),
    "readme.com": ("readme", "conditional"),
    "statuspage.io": ("statuspage", "unclaimed"),
    "freshdesk.com": ("freshdesk", "unclaimed"),
    "zendesk.com": ("zendesk", "conditional"),
    "helpscout.net": ("helpscout", "conditional"),
    "intercom.io": ("intercom", "conditional"),
    "canny.io": ("canny", "unclaimed"),
    "uvp.page": ("canny", "unclaimed"),
    "tawk.to": ("tawk", "unclaimed"),
    "smartsheet.com": ("smartsheet", "conditional"),
    # DNS & email providers
    "dnscontrol.com": ("dnscontrol", "conditional"),
    "nsone.net": ("ns1", "conditional"),
    "cname.sh": ("cname_sh", "unclaimed"),
}

# HTTP fingerprints: (status_code, body_substring, title_substring) → provider
_HTTP_FINGERPRINTS: list[tuple[int, str | None, str | None, str, str]] = [
    (404, "NoSuchBucket", None, "aws_s3", "unclaimed"),
    (404, "The specified bucket does not exist", None, "aws_s3", "unclaimed"),
    (404, "Not Found, github pages", None, "github_pages", "unclaimed"),
    (404, "There is no site here", None, "github_pages", "unclaimed"),
    (200, "herokunoapp", None, "heroku", "unclaimed"),
    (404, "Application not found", None, "heroku", "unclaimed"),
    (404, "No app found", None, "heroku", "unclaimed"),
    (400, "Bad Request", "Azure Web Apps", "azure_app_service", "unclaimed"),
    (404, "Azure Web Apps", None, "azure_app_service", "unclaimed"),
    (200, "Site Not Found", "site_not_found", "netlify", "unclaimed"),
    (404, "Not Found - Request ID", None, "netlify", "unclaimed"),
    (404, "The page you were looking for doesn't exist", None, "netlify", "unclaimed"),
    (404, "404 Not Found", "Firebase", "firebase", "unclaimed"),
    (404, "There isn't a site here", None, "cloudflare_pages", "unclaimed"),
    (404, "There is no such site", None, "surge", "unclaimed"),
    (404, "Project not found", None, "render", "unclaimed"),
    (404, "Not Found", "Airtable", "airtable", "conditional"),
]


async def _dns_resolve(hostname: str, rtype: str, timeout: float = 5.0) -> list[str]:
    """Async DNS resolution via thread pool."""
    try:
        answers = await asyncio.to_thread(
            lambda: dns.resolver.resolve(hostname, rtype, lifetime=timeout)
        )
        return [str(r).rstrip(".") for r in answers]
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return []
    except dns.exception.Timeout:
        logger.debug("DNS timeout resolving %s %s", rtype, hostname)
        return []
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException, OSError) as e:
        logger.debug(
            "DNS error resolving %s %s",
            rtype, hostname, exc_info=True, extra={"error": str(e)},
        )
        return []


async def _dns_ns_delegation(domain: str) -> list[dict[str, Any]]:
    """Check NS delegation for a domain — critical for NS takeover detection."""
    ns_records = await _dns_resolve(domain, "NS")
    if not ns_records:
        return []
    results: list[dict[str, Any]] = []
    for ns in ns_records:
        ns_domain = ns.lower()
        # Extract the registrable domain from the NS hostname
        ext = tldextract.extract(ns_domain)
        ns_reg_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ns_domain
        # Check if NS domain resolves
        ns_ips = await _dns_resolve(ns_domain, "A")
        if not ns_ips:
            results.append({
                "nameserver": ns_domain,
                "registrable_domain": ns_reg_domain,
                "resolves": False,
                "signal": "ns_not_resolving",
            })
    return results


async def _dns_chain(hostname: str) -> dict[str, Any]:
    """Resolve the full DNS graph for a hostname."""
    chain: dict[str, Any] = {
        "a": [], "aaaa": [], "cname": [], "mx": [], "txt": [], "ns": [],
        "delegation_ns": [],
    }

    ext = tldextract.extract(hostname)
    registrable = f"{ext.domain}.{ext.suffix}" if ext.suffix else hostname

    # A records
    chain["a"] = await _dns_resolve(hostname, "A")
    # AAAA records
    chain["aaaa"] = await _dns_resolve(hostname, "AAAA")
    # CNAME (follow chain)
    cname_targets: list[str] = []
    current = hostname
    for _ in range(10):  # limit chain depth
        cnames = await _dns_resolve(current, "CNAME")
        if not cnames:
            break
        cname_targets.append(cnames[0])
        current = cnames[0]
    chain["cname"] = cname_targets
    chain["terminal"] = cname_targets[-1] if cname_targets else hostname

    # MX records — check if they point outside the org
    mx_hosts = await _dns_resolve(hostname, "MX")
    for mx in mx_hosts:
        # MX format: "10 mail.example.com" — extract hostname
        parts = mx.split()
        mx_target = parts[-1] if len(parts) > 1 else mx
        ext_mx = tldextract.extract(mx_target)
        if ext_mx.suffix and f"{ext_mx.domain}.{ext_mx.suffix}" != registrable:
            chain["mx"].append(mx_target)

    # NS delegation check for the registrable domain
    chain["delegation_ns"] = await _dns_ns_delegation(registrable)

    return chain


async def _classify_provider(terminal: str, hostname: str) -> dict[str, Any] | None:
    """Classify the terminal target against fingerprint database."""
    terminal_lower = terminal.lower()

    # Check CNAME terminal against fingerprints
    for pattern, (provider, claimability) in _TAKEOVER_FINGERPRINTS.items():
        if terminal_lower.endswith("." + pattern) or terminal_lower == pattern:
            return {
                "provider": provider,
                "claimability": claimability,
                "matched_on": "cname_pattern",
                "pattern": pattern,
            }

    # Check hostname itself against fingerprints
    for pattern, (provider, claimability) in _TAKEOVER_FINGERPRINTS.items():
        if pattern in hostname.lower():
            return {
                "provider": provider,
                "claimability": claimability,
                "matched_on": "hostname_pattern",
                "pattern": pattern,
            }

    return None


async def _http_probe(hostname: str, timeout: float = 8.0) -> dict[str, Any]:
    """Lightweight HTTP/HTTPS probe for fingerprinting."""
    result: dict[str, Any] = {
        "tried": False, "status": None, "body_snippet": None, "title": None,
        "redirect_url": None, "tls_san": [], "fingerprint": None,
    }

    for scheme in ("https", "http"):
        try:
            async with create_guard_client(timeout=timeout) as client:
                resp = await client.get(f"{scheme}://{hostname}",
                                        headers={"User-Agent": "Mozilla/5.0",
                                                  "Host": hostname})
                result["tried"] = True
                result["status"] = resp.status_code
                result["redirect_url"] = str(resp.url) if resp.url else None

                body = resp.text[:2000]
                result["body_snippet"] = body[:200]

                # Extract title
                title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                if title_match:
                    result["title"] = title_match.group(1).strip()[:100]

                # Check HTTP fingerprints
                for status_code, body_sub, title_sub, provider, claim in _HTTP_FINGERPRINTS:
                    if resp.status_code != status_code:
                        continue
                    if body_sub and body_sub not in body:
                        continue
                    if title_sub and title_sub not in (result.get("title") or ""):
                        continue
                    result["fingerprint"] = {"provider": provider, "claimability": claim,
                                              "matched_on": "http_response"}
                    break
                break  # Don't try http if https worked
        except httpx.TimeoutException:
            logger.debug("HTTP timeout probing %s (%s)", hostname, scheme)
            continue
        except (httpx.RequestError, httpx.HTTPStatusError, OSError) as e:
            logger.debug(
                "HTTP probe error for %s (%s)",
                hostname, scheme, exc_info=True, extra={"error": str(e)},
            )
            continue

    # TLS certificate SANs (only if HTTPS was attempted)
    if result["tried"] and result.get("status"):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, 443, ssl=ctx), timeout=5.0)
            cert = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
            if cert:
                from cryptography import x509 as cx509
                parsed = cx509.load_der_x509_certificate(cert)
                result["tls_san"] = [san.value for san in
                                      parsed.extensions.get_extension_for_class(
                                          cx509.SubjectAlternativeName).value]
            writer.close()
        except asyncio.TimeoutError:
            logger.debug("TLS timeout for %s", hostname)
        except (ssl.SSLError, OSError, x509.ExtensionNotFound) as e:
            logger.debug(
                "TLS probe error for %s",
                hostname, exc_info=True, extra={"error": str(e)},
            )

    return result


async def _rdap_domain_check(
    domain: str, http_client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Check domain registration status via RDAP. Returns registration/expiry info."""
    parts = domain.rsplit(".", 1)
    tld = parts[-1].lower() if len(parts) > 1 else ""
    bases = {"com": "https://rdap.verisign.com/com/v1",
             "net": "https://rdap.verisign.com/net/v1",
             "org": "https://rdap.org"}
    base = bases.get(tld, "https://rdap.org")
    url = f"{base}/domain/{domain}"
    result: dict[str, Any] = {
        "domain": domain, "registered": None, "expires": None,
        "status": None, "error": None,
    }

    try:
        if http_client is not None:
            resp = await http_client.get(url)
        else:
            async with create_guard_client(timeout=10.0) as client:
                resp = await client.get(url)
        if resp.status_code == 404:
            result["registered"] = False
            result["status"] = "not_found"
            return result
        resp.raise_for_status()
        data = resp.json()
        result["registered"] = True
        result["status"] = data.get("status", [])
        # Extract events (registration, expiration)
        for event in data.get("events", []):
            action = event.get("eventAction")
            date = event.get("eventDate", "")[:10]
            if action == "registration":
                result["registered_date"] = date
            elif action == "expiration":
                result["expires_date"] = date
    except httpx.HTTPStatusError as e:
        if e.response.status_code != 404:
            logger.debug("RDAP HTTP error for %s: %s", domain, e)
            result["error"] = f"http_{e.response.status_code}"
    except (httpx.RequestError, ValueError, KeyError, OSError) as e:
        logger.debug("RDAP error for %s: %s", domain, e)
        result["error"] = str(e)[:100]

    return result


async def takeover_detect(
    job: dict[str, Any],
    pool: Any,
    *,
    http_client: httpx.AsyncClient | None = None,
    limiters: Any = None,
) -> list[dict[str, Any]]:
    """Multi-signal subdomain takeover detection.

    Collects DNS graph, provider classification, domain lifecycle (via RDAP),
    and HTTP/TLS evidence for a hostname. The correlation engine evaluates
    the signals to produce severity × confidence findings.
    """
    hostname = job["entity_value"]

    ext = tldextract.extract(hostname)
    registrable = f"{ext.domain}.{ext.suffix}" if ext.suffix else hostname

    # Phase 1: DNS chain
    chain = await _dns_chain(hostname)
    terminal = chain["terminal"]

    # Phase 2: Provider classification
    provider = await _classify_provider(terminal, hostname)

    # Phase 3: HTTP/TLS probe (only if we have a CNAME to a known provider or no A records)
    http_evidence = None
    if provider or not chain["a"]:
        http_evidence = await _http_probe(hostname)

    # Phase 4: Domain lifecycle check for external target domain
    # Uses RDAP to check if the external domain is registered, expired, or available.
    domain_check = None
    ext_target = tldextract.extract(terminal)
    target_registrable = (
        f"{ext_target.domain}.{ext_target.suffix}" if ext_target.suffix else None
    )
    if target_registrable and target_registrable != registrable:
        target_a = await _dns_resolve(target_registrable, "A")
        sem = limiters.rdap if limiters else None
        if sem:
            await sem.acquire()
        try:
            rdap_info = await _rdap_domain_check(target_registrable, http_client)
        finally:
            if sem:
                sem.release()
        domain_check = {
            "external_domain": target_registrable,
            "resolves": len(target_a) > 0,
            "rdap": rdap_info,
            "terminal_ip": chain["a"][0] if chain["a"] else None,
        }

    # Build signal summary
    signals: list[str] = []
    if chain["delegation_ns"]:
        for ns in chain["delegation_ns"]:
            if not ns["resolves"]:
                signals.append("ns_not_resolving")
    if provider:
        signals.append(f"provider:{provider['provider']}")
        if provider["claimability"] == "unclaimed":
            signals.append("provider_unclaimed")
    if http_evidence and http_evidence.get("fingerprint"):
        signals.append(f"http_fingerprint:{http_evidence['fingerprint']['provider']}")
        if http_evidence["fingerprint"]["claimability"] == "unclaimed":
            signals.append("http_unclaimed")
    if domain_check and not domain_check["resolves"]:
        signals.append("external_domain_not_found")

    return [{
        "hostname": hostname,
        "takeover_evidence": {
            "dns_chain": chain,
            "provider": provider,
            "http_probe": http_evidence,
            "domain_check": domain_check,
            "signals": signals,
            "signal_count": len(signals),
        },
    }]


# Backward-compat alias. The pivot handler registry and ``PIVOT_SOURCE_NAMES``
# historically listed ``subdomain_takeover`` as the canonical handler name,
# while the function definition was ``takeover_detect``. Both names now
# resolve to the same coroutine.
subdomain_takeover = takeover_detect
