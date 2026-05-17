from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from easm.runners.engine import (
    get_runner_config,
    iterate_domains_x2,
    standard_http_run,
    standard_subprocess_run,
)
from easm.runners.schemas import OUTPUT_SCHEMAS

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

    return await standard_subprocess_run(
        target, store, trigger_type, run_id, log, http_client,
        source_name="nuclei",
        binary="nuclei",
        args_template=[
            "-u", "[item]",
            "-t", templates,
            "-severity", severity,
            "-json", "-silent", "-no-interactsh",
        ],
        iterate_over=iterate_domains_x2,
        timeout=timeout,
        transform_fn=transform_fn,
    )


async def _wappalyzer_run(target, store, trigger_type, run_id, log, http_client):
    cfg = get_runner_config(target, "wappalyzer")
    timeout = cfg.get("args", {}).get("timeout_seconds", 120)

    from urllib.parse import urlparse

    def transform_fn(parsed, item):
        hostname = urlparse(item).hostname or ""
        return {"hostname": hostname, "url": item, "technologies": parsed}

    return await standard_subprocess_run(
        target, store, trigger_type, run_id, log, http_client,
        source_name="wappalyzer",
        binary="wappalyzer",
        args_template=["[item]"],
        iterate_over=iterate_domains_x2,
        timeout=timeout,
        transform_fn=transform_fn,
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
    )


async def _commoncrawl_run(target, store, trigger_type, run_id, log, http_client):
    from urllib.parse import parse_qs, urlparse

    def _cc_iterate(t):
        urls: list[str] = []
        for domain in t.match_rules.domains:
            for idx in ("2025-13", "2025-09", "2025-05"):
                base = f"http://index.commoncrawl.org/CC-MAIN-{idx}-index"
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
        }

    return await standard_http_run(
        target, store, trigger_type, run_id, log, http_client,
        source_name="commoncrawl",
        url_template="[item]",
        iterate_over=_cc_iterate,
        timeout=30.0,
        transform_fn=transform_fn,
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
        "commoncrawl": RunnerDef(
            source_name="commoncrawl",
            run_fn=_commoncrawl_run,
            supports_schedule=True,
            supports_manual_trigger=True,
            is_continuous=False,
            output_schema=OUTPUT_SCHEMAS.get("commoncrawl"),
        ),
    }
