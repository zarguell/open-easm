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
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from easm.geoip import GeoIpLookup
from easm.network_guard import create_guard_client, resolve_and_validate
from easm.vuln_enrichment import cpe_vuln_enrich

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Enrichment API key resolution (configured at startup)
# ---------------------------------------------------------------------------
import os as _os

_enrichment_keys: dict[str, str] = {}


def configure_enrichment_keys(config) -> None:
    """Load enrichment API keys from config. Called once at startup."""
    keys = getattr(config, "enrichment", None)
    _enrichment_keys["shodan"] = _resolve(keys, "shodan", "SHODAN_API_KEY")
    _enrichment_keys["abuseipdb"] = _resolve(keys, "abuseipdb", "ABUSEIPDB_API_KEY")
    _enrichment_keys["greynoise"] = _resolve(keys, "greynoise", "GREYNOISE_API_KEY")
    _enrichment_keys["censys_id"] = _resolve(keys, "censys_id", "CENSYS_API_ID")
    _enrichment_keys["censys_secret"] = _resolve(keys, "censys_secret", "CENSYS_API_SECRET")
    _enrichment_keys["securitytrails"] = _resolve(keys, "securitytrails", "SECURITYTRAILS_API_KEY")


def _resolve(keys_obj, attr: str, env_var: str) -> str:
    """Config value > environment variable > empty string."""
    config_val = getattr(keys_obj, attr, None) if keys_obj else None
    return config_val or _os.environ.get(env_var, "")

# ---------------------------------------------------------------------------
# Handler functions
# ---------------------------------------------------------------------------


def _certificate_to_raw_dict(cert: x509.Certificate, hostname: str, port: int) -> dict[str, Any]:
    try:
        subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, Exception):
        subject_cn = ""
    try:
        issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, Exception):
        issuer_cn = ""
    try:
        issuer_org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    except (IndexError, Exception):
        issuer_org = ""

    san_dns_names: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_dns_names = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    public_key = cert.public_key()
    public_key_algorithm = type(public_key).__name__
    public_key_size_bits = getattr(public_key, "key_size", None)
    public_key_curve = None
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key_algorithm = "RSA"
    elif isinstance(public_key, dsa.DSAPublicKey):
        public_key_algorithm = "DSA"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key_algorithm = "EC"
        public_key_curve = public_key.curve.name

    signature_hash_algorithm = ""
    if cert.signature_hash_algorithm is not None:
        signature_hash_algorithm = cert.signature_hash_algorithm.name.lower()
    signature_algorithm = getattr(
        cert.signature_algorithm_oid,
        "_name",
        cert.signature_algorithm_oid.dotted_string,
    )

    is_ca = False
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        is_ca = basic_constraints.value.ca
    except x509.ExtensionNotFound:
        pass

    key_usage: list[str] = []
    try:
        usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if usage.digital_signature:
            key_usage.append("digital_signature")
        if usage.content_commitment:
            key_usage.append("content_commitment")
        if usage.key_encipherment:
            key_usage.append("key_encipherment")
        if usage.data_encipherment:
            key_usage.append("data_encipherment")
        if usage.key_agreement:
            key_usage.append("key_agreement")
            if usage.encipher_only:
                key_usage.append("encipher_only")
            if usage.decipher_only:
                key_usage.append("decipher_only")
        if usage.key_cert_sign:
            key_usage.append("key_cert_sign")
        if usage.crl_sign:
            key_usage.append("crl_sign")
    except x509.ExtensionNotFound:
        pass

    extended_key_usage: list[str] = []
    try:
        usages = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        if ExtendedKeyUsageOID.SERVER_AUTH in usages:
            extended_key_usage.append("server_auth")
    except x509.ExtensionNotFound:
        pass

    cert_dict: dict[str, Any] = {
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "issuer_org": issuer_org,
        "serial_number": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "san_dns_names": san_dns_names,
        "public_key_algorithm": public_key_algorithm,
        "public_key_size_bits": public_key_size_bits,
        "public_key_curve": public_key_curve,
        "signature_algorithm": signature_algorithm,
        "signature_hash_algorithm": signature_hash_algorithm,
        "is_ca": is_ca,
        "key_usage": key_usage,
        "extended_key_usage": extended_key_usage,
    }
    return {"hostname": hostname, "port": port, "cert": cert_dict}


async def dns_resolve(job: dict, pool) -> list[dict[str, Any]]:
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
        pass
    except Exception:
        pass

    # Resolve A records — always needed for IP entity creation
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
    import asyncio
    ip_range = job["entity_value"]
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError:
        return []

    sem = asyncio.Semaphore(50)  # limit concurrent DNS lookups

    async def _ptr(ip_str: str) -> dict | None:
        async with sem:
            try:
                rev = dns.reversename.from_address(ip_str)
                answers = await asyncio.to_thread(dns.resolver.resolve, rev, "PTR")
                for rdata in answers:
                    return {"ip": ip_str, "hostname": str(rdata.target).rstrip(".")}
            except Exception:
                pass
        return None

    tasks = [asyncio.create_task(_ptr(str(ip))) for ip in network.hosts()]
    results = [r for r in (await asyncio.gather(*tasks)) if r is not None]
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


async def ip_in_range(job: dict, pool) -> list[dict[str, Any]]:
    """Check if an IP falls within any known IP range and create relationship."""
    import ipaddress
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
    results = []
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


async def tls_cert_grab(job: dict, pool) -> list[dict[str, Any]]:
    hostname = job["entity_value"]

    guard = resolve_and_validate(hostname)
    if not guard.safe:
        logger.debug("TLS cert grab blocked for %s: %s", hostname, guard.reason)
        return [{"hostname": hostname, "message": f"blocked by network guard: {guard.reason}"}]

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
    return [_certificate_to_raw_dict(cert, hostname, port)]


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


async def crtsh_search(job: dict, pool, *, http_client: httpx.AsyncClient | None = None,
                       limiters=None) -> list[dict[str, Any]]:
    domain = job["entity_value"]
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    max_retries = 3
    retry_statuses = (429, 502, 503, 504)
    sem = limiters.crtsh if limiters else None
    if sem:
        await sem.acquire()
    try:
        if http_client is not None:
            certs = None
            for attempt in range(max_retries):
                try:
                    resp = await http_client.get(url)
                except (httpx.ReadTimeout, httpx.ConnectError, httpx.NetworkError) as e:
                    wait = (2 ** attempt) + random.uniform(0, 1)
                    logger.warning("crtsh request failed (%s) for %s, retrying %.1fs",
                                   type(e).__name__, domain, wait)
                    if attempt < max_retries - 1:
                        await asyncio.sleep(wait)
                        continue
                    break
                if resp.status_code == 200:
                    certs = resp.json()
                    break
                if resp.status_code in retry_statuses:
                    retry_after = resp.headers.get("Retry-After")
                    wait = float(retry_after) if retry_after else (2 ** attempt) + random.uniform(0, 1)
                    logger.warning("crtsh rate limited (status %d) for %s, retrying %.1fs",
                                   resp.status_code, domain, wait)
                    if attempt < max_retries - 1:
                        await asyncio.sleep(wait)
                        continue
                    break
                resp.raise_for_status()
            if certs is None:
                raise RuntimeError("crtsh request failed after all retries")
        else:
            async with create_guard_client(timeout=30.0) as client:
                certs = None
                for attempt in range(max_retries):
                    try:
                        resp = await client.get(url)
                    except (httpx.ReadTimeout, httpx.ConnectError, httpx.NetworkError) as e:
                        wait = (2 ** attempt) + random.uniform(0, 1)
                        logger.warning("crtsh request failed (%s) for %s, retrying %.1fs",
                                       type(e).__name__, domain, wait)
                        if attempt < max_retries - 1:
                            await asyncio.sleep(wait)
                            continue
                        break
                    if resp.status_code == 200:
                        certs = resp.json()
                        break
                    if resp.status_code in retry_statuses:
                        retry_after = resp.headers.get("Retry-After")
                        wait = float(retry_after) if retry_after else (2 ** attempt) + random.uniform(0, 1)
                        logger.warning("crtsh rate limited (status %d) for %s, retrying %.1fs",
                                       resp.status_code, domain, wait)
                        if attempt < max_retries - 1:
                            await asyncio.sleep(wait)
                            continue
                        break
                    resp.raise_for_status()
                if certs is None:
                    raise RuntimeError("crtsh request failed after all retries")
    finally:
        if sem:
            sem.release()
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
    except Exception:
        logger.debug("DNS error resolving %s %s", rtype, hostname, exc_info=True)
        return []


async def _dns_ns_delegation(domain: str) -> list[dict]:
    """Check NS delegation for a domain — critical for NS takeover detection."""
    ns_records = await _dns_resolve(domain, "NS")
    if not ns_records:
        return []
    results = []
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


async def _dns_chain(hostname: str) -> dict:
    """Resolve the full DNS graph for a hostname."""
    chain = {"a": [], "aaaa": [], "cname": [], "mx": [], "txt": [], "ns": [], "delegation_ns": []}

    ext = tldextract.extract(hostname)
    registrable = f"{ext.domain}.{ext.suffix}" if ext.suffix else hostname

    # A records
    chain["a"] = await _dns_resolve(hostname, "A")
    # AAAA records
    chain["aaaa"] = await _dns_resolve(hostname, "AAAA")
    # CNAME (follow chain)
    cname_targets = []
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


async def _classify_provider(terminal: str, hostname: str) -> dict | None:
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


async def _http_probe(hostname: str, timeout: float = 8.0) -> dict:
    """Lightweight HTTP/HTTPS probe for fingerprinting."""
    result: dict = {"tried": False, "status": None, "body_snippet": None, "title": None,
                     "redirect_url": None, "tls_san": [], "fingerprint": None}

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
        except Exception:
            logger.debug("HTTP probe error for %s (%s)", hostname, scheme, exc_info=True)
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
        except Exception:
            logger.debug("TLS probe error for %s", hostname, exc_info=True)

    return result


async def _rdap_domain_check(domain: str, http_client: httpx.AsyncClient | None = None) -> dict:
    """Check domain registration status via RDAP. Returns registration/expiry info."""
    parts = domain.rsplit(".", 1)
    tld = parts[-1].lower() if len(parts) > 1 else ""
    bases = {"com": "https://rdap.verisign.com/com/v1",
             "net": "https://rdap.verisign.com/net/v1",
             "org": "https://rdap.org"}
    base = bases.get(tld, "https://rdap.org")
    url = f"{base}/domain/{domain}"
    result: dict = {"domain": domain, "registered": None, "expires": None, "status": None, "error": None}

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
    except Exception as e:
        logger.debug("RDAP error for %s: %s", domain, e)
        result["error"] = str(e)[:100]

    return result


async def takeover_detect(job: dict, pool, *, http_client: httpx.AsyncClient | None = None,
                          limiters=None) -> list[dict[str, Any]]:
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
    target_registrable = f"{ext_target.domain}.{ext_target.suffix}" if ext_target.suffix else None
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
    signals = []
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


async def passive_dns(job: dict, pool, *, http_client: httpx.AsyncClient | None = None,
                      limiters=None) -> list[dict[str, Any]]:
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


async def rdap_lookup(job: dict, pool, *, http_client: httpx.AsyncClient | None = None,
                      limiters=None) -> list[dict[str, Any]]:
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
            except Exception:
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
                except Exception:
                    data_arin = {}
                for entity in data.get("entities", []):
                    for role in entity.get("roles", []):
                        if role in ("registrant", "org"):
                            results.append({"asn": asn, "org": entity.get("handle", ""), "source": "ripe"})
    finally:
        if sem:
            sem.release()
    return results if results else [{"asn": asn, "message": "no RDAP results"}]


async def reverse_whois(job: dict, pool, *, http_client: httpx.AsyncClient | None = None,
                        limiters=None) -> list[dict[str, Any]]:
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


async def domain_rdap(job: dict, pool, *, http_client: httpx.AsyncClient | None = None,
                      limiters=None) -> list[dict[str, Any]]:
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
        if http_client is not None:
            try:
                resp = await http_client.get(url)
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                logger.debug("RDAP lookup failed for %s: %s", domain, e)
                return [{"domain": domain, "message": f"rdap lookup failed: {e}"}]
        else:
            async with create_guard_client(timeout=15.0) as client:
                try:
                    resp = await client.get(url)
                    resp.raise_for_status()
                    data = resp.json()
                except Exception as e:
                    logger.debug("RDAP lookup failed for %s: %s", domain, e)
                    return [{"domain": domain, "message": f"rdap lookup failed: {e}"}]
    finally:
        if sem:
            sem.release()
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


async def shodan_enrich(job: dict, pool, *, http_client: httpx.AsyncClient | None = None,
                        limiters=None) -> list[dict[str, Any]]:
    ip = job["entity_value"]
    api_key = _enrichment_keys.get("shodan", "")
    sem = limiters.shodan if limiters else None
    if sem:
        await sem.acquire()
    try:
        if http_client is not None:
            if api_key:
                resp = await http_client.get(f"https://api.shodan.io/shodan/host/{ip}",
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
                resp = await http_client.get(f"https://internetdb.shodan.io/{ip}")
                if resp.status_code == 404:
                    return [{"ip": ip, "message": "no shodan data"}]
                resp.raise_for_status()
                data = resp.json()
                return [{"ip": ip, "ports": data.get("ports", []),
                         "hostnames": data.get("hostnames", []), "cpes": data.get("cpes", []),
                         "vulns": data.get("vulns", []), "source": "shodan"}]
        else:
            async with create_guard_client(timeout=15.0) as client:
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
    finally:
        if sem:
            sem.release()


async def abuseipdb_enrich(job: dict, pool, *, http_client: httpx.AsyncClient | None = None,
                           limiters=None) -> list[dict[str, Any]]:
    ip = job["entity_value"]
    api_key = _enrichment_keys.get("abuseipdb", "")
    if not api_key:
        return [{"ip": ip, "message": "no abuseipdb api key configured"}]
    sem = limiters.abuseipdb if limiters else None
    if sem:
        await sem.acquire()
    try:
        if http_client is not None:
            resp = await http_client.get("https://api.abuseipdb.com/api/v2/check",
                                    params={"ipAddress": ip, "maxAgeInDays": "90"},
                                    headers={"Key": api_key, "Accept": "application/json"})
            if resp.status_code == 404:
                return [{"ip": ip, "message": "no abuseipdb data"}]
            resp.raise_for_status()
            data = resp.json().get("data", {})
        else:
            async with create_guard_client(timeout=15.0) as client:
                resp = await client.get("https://api.abuseipdb.com/api/v2/check",
                                        params={"ipAddress": ip, "maxAgeInDays": "90"},
                                        headers={"Key": api_key, "Accept": "application/json"})
                if resp.status_code == 404:
                    return [{"ip": ip, "message": "no abuseipdb data"}]
                resp.raise_for_status()
                data = resp.json().get("data", {})
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


async def greynoise_enrich(job: dict, pool, *, http_client: httpx.AsyncClient | None = None,
                           limiters=None) -> list[dict[str, Any]]:
    ip = job["entity_value"]
    api_key = _enrichment_keys.get("greynoise", "")
    headers = {"key": api_key} if api_key else {}
    sem = limiters.greynoise if limiters else None
    if sem:
        await sem.acquire()
    try:
        if http_client is not None:
            resp = await http_client.get(f"https://api.greynoise.io/v3/community/{ip}", headers=headers)
            if resp.status_code == 404:
                return [{"ip": ip, "message": "no greynoise data"}]
            resp.raise_for_status()
            data = resp.json()
        else:
            async with create_guard_client(timeout=15.0) as client:
                resp = await client.get(f"https://api.greynoise.io/v3/community/{ip}", headers=headers)
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


async def urlscan_enrich(job: dict, pool, *, http_client: httpx.AsyncClient | None = None,
                         limiters=None) -> list[dict[str, Any]]:
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


async def censys_enrich(job: dict, pool, *, http_client: httpx.AsyncClient | None = None,
                        limiters=None) -> list[dict[str, Any]]:
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


async def ip_to_asn(job: dict, pool, *, http_client: httpx.AsyncClient | None = None,
                    limiters=None) -> list[dict[str, Any]]:
    import ipaddress
    ip = job["entity_value"]
    results: list[dict[str, Any]] = []
    try:
        network = ipaddress.ip_network(ip, strict=False)
        if network.num_addresses > 1:
            return [{"ip": ip, "message": "ip_to_asn skipped for ranges"}]
    except ValueError:
        pass

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
    "subdomain_takeover": takeover_detect,
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
