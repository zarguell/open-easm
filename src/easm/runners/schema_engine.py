"""Declarative output-schema engine.

Replaces 30+ isomorphic Python schema functions from :mod:`easm.runners.schemas`
with a single generic engine driven by YAML definitions. Complex schemas
(certificate parsing, DNS with CNAME branching, takeover fingerprinting)
remain as Python functions in ``yaml_compat.py`` and are loaded alongside
the YAML-defined schemas.

YAML schema format::

    source: subfinder
    entities:
      - type: hostname
        value_from: host                # raw-key → entity_value
        normalize: true
        attributes:
          source: subfinder              # literal key-values
    relations:
      - source_type: domain
        source_value_from: domain       # raw-key for source value
        target_type: hostname
        target_value_from: host
        via: resolve   # relationship_type (optional)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from easm.entity_store import normalize_entity_value
from easm.runners.schemas import EntityCandidate, OutputSchemaFn, RelationshipCandidate

logger = logging.getLogger(__name__)

_SCHEMAS_DIR = Path(__file__).resolve().parent / "schemas"


class _YamlSchema:
    """Parsed YAML schema definition."""

    __slots__ = ("entities", "relations", "source")

    def __init__(
        self,
        source: str,
        entities: list[dict[str, Any]],
        relations: list[dict[str, Any]],
    ) -> None:
        self.source = source
        self.entities = entities
        self.relations = relations


def _load_yaml_schema(filepath: Path) -> _YamlSchema:
    """Load and parse a single YAML schema file."""
    with filepath.open(encoding="utf-8") as f:
        data: dict[str, Any] = yaml.safe_load(f)
    return _YamlSchema(
        source=data["source"],
        entities=data.get("entities", []),
        relations=data.get("relations", []),
    )


def _make_yaml_schema_fn(  # noqa: C901 — schema compilation is inherently complex
    schema: _YamlSchema,
) -> OutputSchemaFn:
    """Compile a YAML schema definition into a callable schema function."""

    def _schema_fn(  # noqa: C901, PLR0912 — schema mapping is inherently branchy
        raw: dict[str, Any],
    ) -> tuple[list[EntityCandidate], list[RelationshipCandidate]]:
        entities: list[EntityCandidate] = []
        relations: list[RelationshipCandidate] = []

        # --- Collect entity values first (needed for relationship lookup) ---
        resolved_entities: list[dict[str, Any]] = []
        for ent_def in schema.entities:
            ent_type: str = ent_def["type"]
            value_from: str = ent_def.get("value_from", ent_def.get("value_field", ""))
            normalize: bool = ent_def.get("normalize", True)
            raw_value = raw.get(value_from, "")
            if not raw_value:
                continue
            if not isinstance(raw_value, str):
                raw_value = str(raw_value)
            raw_value = raw_value.strip()
            if not raw_value:
                continue
            value = normalize_entity_value(ent_type, raw_value) if normalize else raw_value

            # Build attributes dict from literal values in the YAML
            attrs: dict[str, Any] = dict(ent_def.get("attributes", {}))
            # Allow attribute values to reference raw fields via "from_raw" keys
            for key, ref in list(attrs.items()):
                if isinstance(ref, str) and ref.startswith("$raw."):
                    raw_key = ref[5:]  # strip "$raw."
                    if raw_key in raw:
                        attrs[key] = raw[raw_key]
                    else:
                        # Referenced field absent in raw data — omit the
                        # attribute rather than store the literal "$raw.X"
                        # placeholder string, which would corrupt the entity.
                        del attrs[key]

            entities.append(EntityCandidate(ent_type, value, attrs))
            resolved_entities.append({"type": ent_type, "value": value, "raw_value": raw_value})

        # --- Resolve relationships ---
        for rel_def in schema.relations:
            src_type: str = rel_def["source_type"]
            tgt_type: str = rel_def["target_type"]
            via: str = rel_def.get("via", "pivot")

            src_value_from: str = rel_def.get("source_value_from", "")
            tgt_value_from: str = rel_def.get("target_value_from", "")

            # Resolve source value: find the entity matching source_type
            src_value = ""
            for e in resolved_entities:
                if e["type"] == src_type:
                    src_value = e["value"]
                    break
            if not src_value and src_value_from:
                src_value = normalize_entity_value(src_type, str(raw.get(src_value_from, "")).strip())

            # Resolve target value
            tgt_value = ""
            for e in resolved_entities:
                if e["type"] == tgt_type:
                    tgt_value = e["value"]
                    break
            if not tgt_value and tgt_value_from:
                tgt_value = normalize_entity_value(tgt_type, str(raw.get(tgt_value_from, "")).strip())

            if not src_value or not tgt_value:
                continue

            # Special handling: "source" relationship key means source/target are in entity list
            rel_source: str = rel_def.get("source", "pivot")
            relations.append(
                RelationshipCandidate(src_type, src_value, tgt_type, tgt_value, via, rel_source)
            )

        return entities, relations

    return _schema_fn


# Built-in YAML schemas for simple enrichment sources.
# Complex schemas (cert, dns CNAME, takeover, etc.) remain Python functions.
_YAML_SOURCE_NAMES = {
    "subfinder",
    "wappalyzer",
    "screenshot",
    "searchengine",
    "cloud_enum",
    "nuclei",
    "portscan",
    "commoncrawl",
    "geoip",
    "abuseipdb",
    "greynoise",
    "urlscan",
    "censys",
    "domain_rdap",
    "cpe_vuln_enrich",
}

_PYTHON_ONLY_SOURCES = {
    "asnmap",       # iterates over as_range list
    "dnstwist",     # conditional original_domain relationship
    "crtsh",        # certificate profile + SAN loop
    "certspotter",  # same as crtsh
    "certstream",   # complex cert parsing + SAN loop
    "reverse_dns",  # dual entity + relationship
    "dns",          # CNAME vs A branching
    "domain_extract",  # conditional relationship
    "tls_cert",     # certificate profile + SAN loop
    "dns_mail_records",  # MX record loop
    "shodan",       # hostnames/domains iteration
    "passive_dns",  # a_records iteration
    "subdomain_takeover",  # two-format branching
    "takeover",     # alias
    "takeover_detect",  # alias
    "ripe_stat",    # dual entity
    "rdap",         # passthrough
    "securitytrails",  # alias for passive_dns
}


def _load_yaml_schemas() -> dict[str, OutputSchemaFn]:
    """Load all YAML schema files and return compiled functions."""
    schemas: dict[str, OutputSchemaFn] = {}
    if not _SCHEMAS_DIR.is_dir():
        logger.warning("YAML schema directory not found: %s", _SCHEMAS_DIR)
        return schemas
    for filepath in sorted(_SCHEMAS_DIR.glob("*.yaml")):
        try:
            parsed = _load_yaml_schema(filepath)
            schemas[parsed.source] = _make_yaml_schema_fn(parsed)
        except (yaml.YAMLError, KeyError, ValueError, TypeError) as e:
            logger.warning(
                "Failed to load YAML schema %s: %s",
                filepath.name, e, exc_info=True,
            )
    return schemas


def build_output_schemas() -> dict[str, OutputSchemaFn]:
    """Build the complete OUTPUT_SCHEMAS dict from YAML + Python sources.

    YAML schemas are loaded first, then Python schemas from
    :mod:`easm.runners.schemas` fill in the complex sources.
    """
    schemas: dict[str, OutputSchemaFn] = {}

    # Load YAML schemas
    yaml_schemas = _load_yaml_schemas()
    schemas.update(yaml_schemas)

    # Load Python schemas for complex/non-declarative sources
    from easm.runners.schemas import (  # noqa: F401
        _profile_with_analysis,
        abuseipdb,
        asnmap,
        censys,
        certstream,
        cloud_bucket,
        commoncrawl,
        cpe_vuln_enrich,
        crtsh,
        dns,
        dns_mail_records,
        dnstwist,
        domain_extract,
        domain_rdap,
        geoip,
        greynoise,
        nuclei,
        passive_dns,
        portscan,
        rdap,
        reverse_dns,
        ripe_stat,
        screenshot,
        searchengine,
        shodan,
        subdomain_takeover,
        subfinder,
        tls_cert,
        urlscan,
        wappalyzer,
    )

    _python_schemas: dict[str, OutputSchemaFn] = {
        "asnmap": asnmap,
        "dnstwist": dnstwist,
        "crtsh": crtsh,
        "certspotter": crtsh,
        "certstream": certstream,
        "reverse_dns": reverse_dns,
        "dns": dns,
        "domain_extract": domain_extract,
        "tls_cert": tls_cert,
        "dns_mail_records": dns_mail_records,
        "shodan": shodan,
        "passive_dns": passive_dns,
        "subdomain_takeover": subdomain_takeover,
        "takeover": subdomain_takeover,
        "takeover_detect": subdomain_takeover,
        "ripe_stat": ripe_stat,
        "rdap": rdap,
        "securitytrails": passive_dns,
    }

    # YAML schemas take priority; Python schemas fill gaps
    for name, fn in _python_schemas.items():
        if name not in schemas:
            schemas[name] = fn

    return schemas


__all__ = ["build_output_schemas"]
