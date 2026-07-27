from __future__ import annotations

import asyncio
import base64
import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

import httpx

from easm.runners.engine import (
    get_runner_config,
    iterate_hostnames_x2,
    standard_http_run,
    standard_subprocess_run,
)
from easm.runners.schemas import OUTPUT_SCHEMAS

logger = logging.getLogger(__name__)

# Type alias for the run function contract.
# async def run_fn(target, store, trigger_type, run_id, log, http_client) -> (int, int, int)
RunFn = Callable[..., Awaitable[tuple[int, int, int]]]


@dataclass(frozen=True)
class RunnerDef:
    """Declarative runner definition used by the registry."""

    source_name: str
    run_fn: RunFn
    output_schema: Any | None = None
    supports_schedule: bool = True
    supports_manual_trigger: bool = True
    is_continuous: bool = False


# ---------------------------------------------------------------------------
# Standard subprocess runners
# ---------------------------------------------------------------------------

async def _asnmap_run(target, store, trigger_type, run_id, log, http_client):
    cfg = get_runner_config(target, "asnmap")
    timeout = cfg.get("args", {}).get("timeout_seconds", 300)
    return await standard_subprocess_run(
        target, store, trigger_type, run_id, log, http_client,
        source_name="asnmap",
        binary="asnmap",
        args_template=["-a", "[item]", "-json"],
        iterate_over=lambda t: t.match_rules.asns,
        timeout=timeout,
        output_schema=OUTPUT_SCHEMAS.get("asnmap"),
    )


async def _subfinder_run(target, store, trigger_type, run_id, log, http_client):
    cfg = get_runner_config(target, "subfinder")
    args_cfg = cfg.get("args", {})
    timeout = args_cfg.get("timeout_seconds", 300)
    recursive = args_cfg.get("recursive", False)
    args_template = ["-d", "[item]", "-json", "-silent", "-nW", "-all"]
    if recursive:
        args_template.append("-recursive")
    return await standard_subprocess_run(
        target, store, trigger_type, run_id, log, http_client,
        source_name="subfinder",
        binary="subfinder",
        args_template=args_template,
        iterate_over=lambda t: t.match_rules.domains,
        timeout=timeout,
        output_schema=OUTPUT_SCHEMAS.get("subfinder"),
    )


async def _dnstwist_run(target, store, trigger_type, run_id, log, http_client):
    def transform_fn(parsed, item):
        return {
            "domain": parsed.get("domain", ""),
            "original_domain": item,
            "type": parsed.get("fuzzer", ""),
            "dns": parsed.get("dns", {}),
            "registered": parsed.get("registered", False),
        }

    return await standard_subprocess_run(
        target, store, trigger_type, run_id, log, http_client,
        source_name="dnstwist",
        binary="dnstwist",
        args_template=["--format=json", "[item]"],
        iterate_over=lambda t: t.match_rules.domains,
        timeout=120,
        transform_fn=transform_fn,
        output_schema=OUTPUT_SCHEMAS.get("dnstwist"),
    )


async def _nuclei_run(target, store, trigger_type, run_id, log, http_client):
    cfg = get_runner_config(target, "nuclei")
    args_cfg = cfg.get("args", {})
    timeout = args_cfg.get("timeout_seconds", 900)
    templates = args_cfg.get("templates", "exposures,misconfigurations")
    severity = args_cfg.get("severity", "critical,high")

    from urllib.parse import urlparse

    def transform_fn(parsed, item):
        hostname = urlparse(item).hostname or ""
        parsed["hostname"] = hostname
        parsed["url"] = item
        return parsed

    # Get discovered hostnames from DB
    hostnames = await iterate_hostnames_x2(target, store.pool)
    log(f"[runner] nuclei: scanning {len(hostnames)} hostname(s)")

    return await standard_subprocess_run(
        target, store, trigger_type, run_id, log, http_client,
        source_name="nuclei",
        binary="nuclei",
        args_template=[
            "-u", "[item]",
            "-t", templates,
            "-severity", severity,
            "-jsonl", "-silent", "-no-interactsh",
        ],
        iterate_over=lambda t: hostnames,
        timeout=timeout,
        transform_fn=transform_fn,
        output_schema=OUTPUT_SCHEMAS.get("nuclei"),
    )


async def _wappalyzer_run(target, store, trigger_type, run_id, log, http_client):
    cfg = get_runner_config(target, "wappalyzer")
    timeout = cfg.get("args", {}).get("timeout_seconds", 120)

    from urllib.parse import urlparse

    def transform_fn(parsed, item):
        hostname = urlparse(item).hostname or ""
        matches = parsed.get("matches", [])
        technologies = [
            {"name": m.get("app_name", ""), "version": m.get("version", "")}
            for m in matches
            if m.get("app_name")
        ]
        return {"hostname": hostname, "url": item, "technologies": technologies}

    hostnames = await iterate_hostnames_x2(target, store.pool)
    log(f"[runner] wappalyzer: scanning {len(hostnames)} hostname(s)")

    return await standard_subprocess_run(
        target, store, trigger_type, run_id, log, http_client,
        source_name="wappalyzer",
        binary="webanalyze",
        args_template=["-host", "[item]", "-output", "json", "-silent"],
        iterate_over=lambda t: hostnames,
        timeout=timeout,
        transform_fn=transform_fn,
        output_schema=OUTPUT_SCHEMAS.get("wappalyzer"),
    )


# ---------------------------------------------------------------------------
# Standard HTTP runners
# ---------------------------------------------------------------------------

async def _crtsh_run(target, store, trigger_type, run_id, log, http_client):
    def transform_fn(parsed, item):
        return {
            "name_value": parsed.get("name_value", ""),
            "issuer_name_id": parsed.get("issuer_name_id", ""),
            "not_before": parsed.get("not_before", ""),
            "not_after": parsed.get("not_after", ""),
            "serial_number": parsed.get("serial_number", ""),
            "fingerprint": parsed.get("fingerprint", ""),
        }

    return await standard_http_run(
        target, store, trigger_type, run_id, log, http_client,
        source_name="crtsh",
        url_template="https://crt.sh/?q=%.[item]&output=json",
        iterate_over=lambda t: t.match_rules.domains,
        timeout=30.0,
        transform_fn=transform_fn,
        max_retries=3,
        retry_statuses=(429, 502, 503, 504),
        inter_delay=1.5,
        max_concurrent=3,
        output_schema=OUTPUT_SCHEMAS.get("crtsh"),
    )


async def _certspotter_run(target, store, trigger_type, run_id, log, http_client):
    import os

    api_key = os.environ.get("CERTSPOTTER_API_KEY", "")
    if not api_key:
        raise RuntimeError("CERTSPOTTER_API_KEY not set — get a free key at https://sslmate.com/certspotter/")

    headers = {"Authorization": f"Bearer {api_key}"}
    base_url = "https://api.certspotter.com/v1/issuances"

    inserted = 0
    deduped = 0
    errors = 0

    for domain in target.match_rules.domains:
        recent = await store.pool.fetchval(
            "SELECT COUNT(*) FROM raw_events "
            "WHERE target_id = $1 AND source = 'certspotter' "
            "AND raw::text LIKE $2 AND collected_at > NOW() - INTERVAL '24 hours'",
            target.id, f'%{domain}%',
        )
        if recent and recent > 0:
            log(f"certspotter: skipping {domain}, already fetched {recent} issuances in last 24h")
            continue

        try:
            url = (
                f"{base_url}?domain={domain}&include_subdomains=true"
                f"&expand=dns_names&expand=issuer&expand=revocation"
            )
            after = None
            rate_limit_retries = 0
            max_rate_limit_retries = 3
            while True:
                query_url = url
                if after:
                    query_url = f"{url}&after={after}"
                resp = await http_client.get(query_url, headers=headers)
                if resp.status_code == 429:
                    rate_limit_retries += 1
                    if rate_limit_retries > max_rate_limit_retries:
                        log(f"certspotter rate limit exceeded for {domain} after {max_rate_limit_retries} retries, skipping")
                        errors += 1
                        break
                    retry_after = resp.headers.get("Retry-After")
                    if retry_after:
                        try:
                            backoff = float(retry_after)
                        except ValueError:
                            backoff = 10 * (2 ** rate_limit_retries)
                    else:
                        backoff = 10 * (2 ** rate_limit_retries)
                    log(f"certspotter rate limited for {domain}, backing off {backoff}s (attempt {rate_limit_retries}/{max_rate_limit_retries})")
                    await asyncio.sleep(backoff)
                    continue
                rate_limit_retries = 0
                if resp.status_code != 200:
                    log(f"certspotter error: {resp.status_code} for {domain}")
                    errors += 1
                    break
                issuances = resp.json()
                if not issuances:
                    break
                for issuance in issuances:
                    dns_names = issuance.get("dns_names", [])
                    if not dns_names:
                        continue

                    issuer_obj = issuance.get("issuer") or {}
                    revocation_obj = issuance.get("revocation") or {}
                    issuer_name = issuer_obj.get("name", "")
                    issuer_friendly = issuer_obj.get("friendly_name", "")
                    issuer_org = _parse_x509_field(issuer_name, "O=")
                    issuer_cn = _parse_x509_field(issuer_name, "CN=")

                    raw = {
                        "name_value": "\n".join(dns_names),
                        "issuer_name_id": "",
                        "not_before": issuance.get("not_before", ""),
                        "not_after": issuance.get("not_after", ""),
                        "serial_number": issuance.get("cert_sha256", ""),
                        "fingerprint": issuance.get("tbs_sha256", ""),
                        "fingerprint_sha256": issuance.get("cert_sha256", ""),
                        "issuer_cn": issuer_cn or issuer_friendly,
                        "issuer_org": issuer_org or issuer_friendly,
                        "revoked": issuance.get("revoked"),
                        "revocation_time": revocation_obj.get("time"),
                        "revocation_reason": revocation_obj.get("reason"),
                    }

                    cert_der_b64 = issuance.get("cert_der")
                    if cert_der_b64:
                        try:
                            parsed = _parse_cert_der(cert_der_b64)
                            raw.update(parsed)
                        except (ValueError, TypeError, base64.binascii.Error) as e:
                            logger.debug(
                                "failed to parse cert DER for issuance",
                                exc_info=True, extra={"error": str(e)},
                            )

                    raw_event_id = await store.insert_raw_event(
                        target.org_id, target.id, "certspotter", raw, run_id
                    )
                    if raw_event_id:
                        inserted += 1
                        from easm.runners.engine import _ingest_entities
                        from easm.runners.schemas import OUTPUT_SCHEMAS
                        schema_fn = OUTPUT_SCHEMAS.get("certspotter")
                        if schema_fn:
                            await _ingest_entities(
                                store, schema_fn, raw, run_id,
                                target.org_id, target.id, target=target,
                                pool=getattr(store, "pool", None),
                                raw_event_id=raw_event_id,
                            )
                    else:
                        deduped += 1
                after = issuances[-1].get("id")
        except (httpx.RequestError, httpx.HTTPStatusError, ValueError, KeyError) as e:
            log(f"certspotter error for {domain}: {e}")

    return inserted, deduped, errors


def _parse_x509_field(dn: str, prefix: str) -> str | None:
    for part in dn.split(","):
        part = part.strip()
        if part.startswith(prefix):
            return part[len(prefix):].strip()
    return None


def _parse_cert_der(cert_der_b64: str) -> dict[str, Any]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    der_bytes = base64.b64decode(cert_der_b64)
    cert = x509.load_der_x509_certificate(der_bytes)

    subject_cn = None
    subject_org = None
    for attr in cert.subject:
        if attr.oid == x509.oid.NameOID.COMMON_NAME:
            subject_cn = attr.value
        elif attr.oid == x509.oid.NameOID.ORGANIZATION_NAME:
            subject_org = attr.value

    san_names = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_names = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        logger.debug("certificate has no SubjectAlternativeName extension")

    pub = cert.public_key()
    pub_info = {"algorithm": type(pub).__name__.replace("_", " ").replace("RSAPublicKey", "RSA")}
    if hasattr(pub, "key_size"):
        pub_info["size_bits"] = pub.key_size
    if hasattr(pub, "curve"):
        pub_info["curve"] = pub.curve.name if hasattr(pub.curve, "name") else str(pub.curve)

    sig_alg = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, "_name") else ""

    return {
        "subject_cn": subject_cn,
        "subject_org": subject_org,
        "san_dns_names": san_names,
        "public_key_algorithm": pub_info.get("algorithm", ""),
        "public_key_size_bits": pub_info.get("size_bits"),
        "public_key_curve": pub_info.get("curve", ""),
        "signature_algorithm": sig_alg,
        "is_ca": _is_ca(cert),
    }


def _is_ca(cert) -> bool:
    from cryptography import x509
    try:
        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        return basic_constraints.value.ca
    except x509.ExtensionNotFound:
        return False


async def _commoncrawl_run(target, store, trigger_type, run_id, log, http_client):
    from urllib.parse import parse_qs, urlparse

    # Resolve latest CommonCrawl index dynamically
    cc_idx = "2026-17"  # fallback if fetch fails
    try:
        resp = await http_client.get("https://index.commoncrawl.org/collinfo.json")
        if resp.status_code == 200:
            data = resp.json()
            if data and len(data) > 0:
                cc_idx = data[0]["id"].replace("CC-MAIN-", "")
    except (httpx.RequestError, httpx.HTTPStatusError, ValueError, KeyError) as e:
        log("commoncrawl: failed to fetch latest index, using fallback")
        logger.debug(
            "commoncrawl index fetch failed",
            exc_info=True, extra={"error": str(e)},
        )

    def _cc_iterate(t):
        urls: list[str] = []
        for domain in t.match_rules.domains:
            base = f"https://index.commoncrawl.org/CC-MAIN-{cc_idx}-index"
            urls.append(f"{base}?url=*.{domain}&output=json")
            urls.append(f"{base}?url={domain}&output=json")
        return urls

    def transform_fn(parsed, item):
        qs = parse_qs(urlparse(item).query)
        url_param = qs.get("url", [""])[0]
        domain = url_param.lstrip("*.")
        return {
            "url": parsed.get("url", ""),
            "domain": domain,
            "source": "commoncrawl",
            "status": parsed.get("status", ""),
            "mime": parsed.get("mime", ""),
            "languages": parsed.get("languages", ""),
            "timestamp": parsed.get("timestamp", ""),
        }

    return await standard_http_run(
        target, store, trigger_type, run_id, log, http_client,
        source_name="commoncrawl",
        url_template="[item]",
        iterate_over=_cc_iterate,
        timeout=30.0,
        transform_fn=transform_fn,
        output_schema=OUTPUT_SCHEMAS.get("commoncrawl"),
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def get_runner_registry() -> dict[str, RunnerDef]:
    """Return the declarative registry of all standard runners.

    Custom runners (portscan, monitors, etc.) are not included here;
    they remain as class-based runners in the legacy ``RUNNER_REGISTRY``.
    """
    return {
        "asnmap": RunnerDef(
            source_name="asnmap",
            run_fn=_asnmap_run,
            supports_schedule=True,
            supports_manual_trigger=True,
            is_continuous=False,
            output_schema=OUTPUT_SCHEMAS.get("asnmap"),
        ),
        "subfinder": RunnerDef(
            source_name="subfinder",
            run_fn=_subfinder_run,
            supports_schedule=True,
            supports_manual_trigger=True,
            is_continuous=False,
            output_schema=OUTPUT_SCHEMAS.get("subfinder"),
        ),
        "dnstwist": RunnerDef(
            source_name="dnstwist",
            run_fn=_dnstwist_run,
            supports_schedule=True,
            supports_manual_trigger=True,
            is_continuous=False,
            output_schema=OUTPUT_SCHEMAS.get("dnstwist"),
        ),
        "nuclei": RunnerDef(
            source_name="nuclei",
            run_fn=_nuclei_run,
            supports_schedule=True,
            supports_manual_trigger=True,
            is_continuous=False,
            output_schema=OUTPUT_SCHEMAS.get("nuclei"),
        ),
        "wappalyzer": RunnerDef(
            source_name="wappalyzer",
            run_fn=_wappalyzer_run,
            supports_schedule=True,
            supports_manual_trigger=True,
            is_continuous=False,
            output_schema=OUTPUT_SCHEMAS.get("wappalyzer"),
        ),
        "crtsh": RunnerDef(
            source_name="crtsh",
            run_fn=_crtsh_run,
            supports_schedule=True,
            supports_manual_trigger=True,
            is_continuous=False,
            output_schema=OUTPUT_SCHEMAS.get("crtsh"),
        ),
        "certspotter": RunnerDef(
            source_name="certspotter",
            run_fn=_certspotter_run,
            supports_schedule=True,
            supports_manual_trigger=True,
            is_continuous=False,
            output_schema=OUTPUT_SCHEMAS.get("crtsh"),
        ),
        "commoncrawl": RunnerDef(
            source_name="commoncrawl",
            run_fn=_commoncrawl_run,
            supports_schedule=True,
            supports_manual_trigger=True,
            is_continuous=False,
            output_schema=OUTPUT_SCHEMAS.get("commoncrawl"),
        ),
    }
