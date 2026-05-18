from __future__ import annotations

from pathlib import Path

from easm.pivot.handlers import PIVOT_SOURCE_NAMES
from easm.runners.schemas import OUTPUT_SCHEMAS


SCHEMAS_PATH = Path(__file__).parents[1] / "src" / "easm" / "runners" / "schemas.py"

RAW_ONLY_PIVOT_SOURCES = {
    "reverse_whois",
}


def test_output_schemas_assigned_once() -> None:
    source = SCHEMAS_PATH.read_text(encoding="utf-8")
    assert source.count("OUTPUT_SCHEMAS") == 1


def test_schema_functions_are_not_redefined() -> None:
    source = SCHEMAS_PATH.read_text(encoding="utf-8")
    for name in [
        "dns",
        "reverse_dns",
        "domain_extract",
        "geoip",
        "tls_cert",
        "dns_mail_records",
        "shodan",
        "abuseipdb",
        "greynoise",
        "urlscan",
        "censys",
        "passive_dns",
        "cloud_bucket",
        "searchengine",
        "subdomain_takeover",
    ]:
        assert source.count(f"def {name}(") == 1


def test_pivot_sources_have_output_schemas_or_raw_only_reason() -> None:
    missing = sorted(
        source
        for source in set(PIVOT_SOURCE_NAMES.values())
        if source not in OUTPUT_SCHEMAS and source not in RAW_ONLY_PIVOT_SOURCES
    )
    assert missing == []


def test_raw_only_pivot_sources_do_not_have_output_schemas() -> None:
    unexpected = sorted(source for source in RAW_ONLY_PIVOT_SOURCES if source in OUTPUT_SCHEMAS)
    assert unexpected == []
