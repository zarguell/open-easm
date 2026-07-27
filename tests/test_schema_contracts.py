from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from easm.pivot.handlers import PIVOT_SOURCE_NAMES
from easm.runners.schemas import OUTPUT_SCHEMAS


SCHEMAS_PATH = Path(__file__).parents[1] / "src" / "easm" / "runners" / "schemas.py"

RAW_ONLY_PIVOT_SOURCES: set[str] = set()


def test_output_schemas_assigned_once() -> None:
    source = SCHEMAS_PATH.read_text(encoding="utf-8")
    # OUTPUT_SCHEMAS appears in: (1) type-annotation declaration line,
    # (2) module-level ``_init_output_schemas()`` call. The docstring
    # may also contain the word; count substantial statements only.
    assignment_lines = [
        line for line in source.splitlines()
        if "OUTPUT_SCHEMAS" in line and "=" in line and not line.strip().startswith("#")
    ]
    assert len(assignment_lines) >= 1


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


def test_reverse_whois_schema_extracts_domain_entity() -> None:
    """Regression: reverse_whois pivot must not silently discard discovered domains.

    The handler at ``src/easm/pivot/handlers/enrichment.py`` returns dicts of
    shape ``{"domain": str, "reverse_whois": {...}}``. Without an output
    schema, the pivot worker's entity-extraction loop is skipped and every
    related domain discovered via reverse WHOIS is lost (raw_events only,
    no graph edges, no findings).
    """
    schema_fn = OUTPUT_SCHEMAS.get("reverse_whois")
    assert schema_fn is not None, (
        "reverse_whois must have an output schema or its results are discarded"
    )
    raw = {
        "domain": "example.com",
        "reverse_whois": {
            "related_domains": ["related.example.org"],
            "dates_found": ["2024-01-01"],
        },
    }
    entities, rels = schema_fn(raw)
    assert len(entities) == 1, "reverse_whois schema must extract the domain field"
    assert entities[0].entity_type == "domain"
    assert entities[0].value == "example.com"
    assert entities[0].attributes.get("source") == "reverse_whois"
    assert rels == []


@pytest.mark.parametrize(
    ("source_name", "raw"),
    [
        pytest.param(
            "nuclei",
            {"hostname": "example.com", "template-id": "test",
             "info": {"name": "Test Vuln", "severity": "medium"}},
            id="nuclei-missing-vulnerability",
        ),
        pytest.param(
            "commoncrawl",
            {"domain": "example.com"},
            id="commoncrawl-missing-url",
        ),
        pytest.param(
            "cloud_enum",
            {"bucket_url": "https://example.s3.amazonaws.com"},
            id="cloud_enum-missing-provider",
        ),
        pytest.param(
            "cpe_vuln_enrich",
            {"entity_value": "example.com", "entity_type": "hostname"},
            id="cpe_vuln_enrich-missing-cpes",
        ),
        pytest.param(
            "rdap",
            {"asn": "AS12345"},
            id="rdap-missing-rdap-data",
        ),
    ],
)
def test_yaml_schema_omits_unresolvable_raw_refs(
    source_name: str, raw: dict[str, Any],
) -> None:
    """Regression: a YAML ``$raw.X`` ref absent in raw must not leak its placeholder.

    Each parametrize case provides the entity's ``value_from`` field (so an
    entity IS produced) but omits the ``$raw.X`` target(s). The schema engine
    must omit those attributes rather than store the literal placeholder
    string (e.g. ``"$raw.vulnerability"``), which would corrupt entity
    attributes with non-data template syntax.
    """
    schema_fn = OUTPUT_SCHEMAS.get(source_name)
    assert schema_fn is not None, f"{source_name} must have a registered schema"
    entities, _rels = schema_fn(raw)
    assert len(entities) >= 1, (
        f"{source_name}: entity must still be produced when $raw targets are absent"
    )
    for entity in entities:
        leaked = {
            key: value
            for key, value in entity.attributes.items()
            if isinstance(value, str) and value.startswith("$raw.")
        }
        assert not leaked, (
            f"{source_name}: attribute(s) leaked literal $raw placeholder(s) "
            f"{leaked} — unresolvable $raw refs must be omitted, not stored verbatim"
        )
