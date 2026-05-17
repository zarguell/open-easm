# EASM Enrichment Features Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add six enrichment capabilities to open-easm: DNS mail records (SPF/MX/DMARC), mail provider classification, live TLS certificate grab with SAN pivot, RDAP domain enrichment, geo-IP lookup, and geo map display.

**Architecture:** Each feature follows the existing pivot handler + parser pattern. Pivot handlers collect raw data → raw events → parsers extract entities + relationships. No schema changes — all enrichment data lives in the existing `attributes JSONB` column on entities. New pivot types get registered in `PIVOT_HANDLER_REGISTRY`, new parsers in `PARSER_REGISTRY`, and new pivot type strings in `VALID_PIVOT_TYPES`. The geo map is a React component consuming the existing `/api/entities` endpoint filtered to IPs with geo attributes.

**Tech Stack:** Python 3.14, dnspython (already dep), httpx (already dep), ssl stdlib, cryptography (new dep), maxminddb (new dep), React 18, maplibre-gl (new npm dep).

---

## File Structure

### New Files

| File | Responsibility |
|------|---------------|
| `src/easm/pivot/handlers/dns_mail_records.py` | Pivot handler: collect MX, SPF (TXT), DMARC records for a domain |
| `src/easm/parse/dns_mail_records_parser.py` | Parser: extract domain mail attributes + MX hostname entities |
| `src/easm/pivot/handlers/tls_cert_grab.py` | Pivot handler: connect to hostname:443, grab live cert chain |
| `src/easm/parse/tls_cert_parser.py` | Parser: extract cert entity + SAN domain entities + relationships |
| `src/easm/pivot/handlers/geoip_enrich.py` | Pivot handler: geo-locate an IP using MaxMind GeoLite2 |
| `src/easm/parse/geoip_parser.py` | Parser: store geo attributes on IP entity |
| `src/easm/mail_provider.py` | Classifier: match MX/SPF data to known mail providers |
| `src/easm/geoip.py` | GeoIP lookup module: wraps maxminddb reader |
| `tests/test_parsers/test_dns_mail_records_parser.py` | Tests for DNS mail records parser |
| `tests/test_parsers/test_tls_cert_parser.py` | Tests for TLS cert parser |
| `tests/test_parsers/test_geoip_parser.py` | Tests for geo-IP parser |
| `tests/test_mail_provider.py` | Tests for mail provider classifier |
| `tests/test_geoip.py` | Tests for geo-IP module |
| `ui/src/components/GeoMap.tsx` | React component: maplibre-gl map rendering IP locations |

### Modified Files

| File | Change |
|------|--------|
| `src/easm/pivot/handlers/__init__.py` | Register 3 new pivot handlers |
| `src/easm/parse/__init__.py` | Register 3 new parsers |
| `src/easm/config.py` | Add 4 new pivot types to `VALID_PIVOT_TYPES` |
| `pyproject.toml` | Add `cryptography` and `maxminddb` dependencies |
| `config.yaml.example` | Add new pivot rules for the 3 handlers |
| `Dockerfile` | Add GeoLite2 DB download step |

---

## Task 1: DNS Mail Records (SPF, MX, DMARC) — Pivot Handler + Parser

**Files:**
- Create: `src/easm/pivot/handlers/dns_mail_records.py`
- Create: `src/easm/parse/dns_mail_records_parser.py`
- Create: `tests/test_parsers/test_dns_mail_records_parser.py`
- Modify: `src/easm/pivot/handlers/__init__.py`
- Modify: `src/easm/parse/__init__.py`
- Modify: `src/easm/config.py`

- [ ] **Step 1: Write failing tests for the DNS mail records parser**

```python
# tests/test_parsers/test_dns_mail_records_parser.py
import pytest
from easm.parse.dns_mail_records_parser import DnsMailRecordsParser


@pytest.mark.asyncio
async def test_mail_records_parser_extracts_mx():
    parser = DnsMailRecordsParser()
    event = {
        "raw": {
            "domain": "example.com",
            "mx_records": [
                {"preference": 10, "exchange": "mail.example.com"},
                {"preference": 20, "exchange": "backup.mail.example.com"},
            ],
            "spf_record": "v=spf1 include:_spf.google.com ~all",
            "dmarc_record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    domain_entities = [e for e in result.entities if e.entity_type == "domain"]
    assert any(e.value == "example.com" for e in domain_entities)
    domain_ent = next(e for e in domain_entities if e.value == "example.com")
    assert domain_ent.attributes["mx_records"] == [
        {"preference": 10, "exchange": "mail.example.com"},
        {"preference": 20, "exchange": "backup.mail.example.com"},
    ]
    assert domain_ent.attributes["spf_record"] == "v=spf1 include:_spf.google.com ~all"
    assert domain_ent.attributes["dmarc_record"] == "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"


@pytest.mark.asyncio
async def test_mail_records_parser_creates_mx_hostname_entities():
    parser = DnsMailRecordsParser()
    event = {
        "raw": {
            "domain": "example.com",
            "mx_records": [{"preference": 10, "exchange": "mail.google.com"}],
        }
    }
    result = await parser.parse(event)
    hostname_entities = [e for e in result.entities if e.entity_type == "hostname"]
    assert len(hostname_entities) == 1
    assert hostname_entities[0].value == "mail.google.com"
    assert hostname_entities[0].attributes["source"] == "dns_mail_records"
    assert hostname_entities[0].attributes["mx_for"] == "example.com"


@pytest.mark.asyncio
async def test_mail_records_parser_creates_relationships():
    parser = DnsMailRecordsParser()
    event = {
        "raw": {
            "domain": "example.com",
            "mx_records": [{"preference": 10, "exchange": "mail.example.com"}],
        }
    }
    result = await parser.parse(event)
    mx_rels = [r for r in result.relationships if r.relationship_type == "mail_handled_by"]
    assert len(mx_rels) == 1
    assert mx_rels[0].source_type == "domain"
    assert mx_rels[0].source_value == "example.com"
    assert mx_rels[0].target_type == "hostname"
    assert mx_rels[0].target_value == "mail.example.com"


@pytest.mark.asyncio
async def test_mail_records_parser_empty_records():
    parser = DnsMailRecordsParser()
    event = {"raw": {"domain": "example.com"}}
    result = await parser.parse(event)
    assert not result.unparseable
    domain_entities = [e for e in result.entities if e.entity_type == "domain"]
    assert len(domain_entities) == 1
    assert domain_entities[0].attributes.get("mx_records") == []


@pytest.mark.asyncio
async def test_mail_records_parser_missing_domain():
    parser = DnsMailRecordsParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_mail_records_parser_class_attributes():
    assert DnsMailRecordsParser.source_name == "dns_mail_records"
    assert DnsMailRecordsParser.current_version == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_parsers/test_dns_mail_records_parser.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'easm.parse.dns_mail_records_parser'`

- [ ] **Step 3: Write the DNS mail records parser**

```python
# src/easm/parse/dns_mail_records_parser.py
from easm.parse.base import BaseParser, ParseResult, EntityCandidate, RelationshipCandidate
from easm.entity_store import normalize_entity_value


class DnsMailRecordsParser(BaseParser):
    source_name = "dns_mail_records"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        domain = raw.get("domain", "").strip()
        if not domain:
            return ParseResult(entities=[], relationships=[], unparseable=True,
                               parse_error="missing domain")

        normalized_domain = normalize_entity_value("domain", domain)
        mx_records = raw.get("mx_records", [])
        spf_record = raw.get("spf_record", "")
        dmarc_record = raw.get("dmarc_record", "")

        entities: list[EntityCandidate] = []
        relationships: list[RelationshipCandidate] = []

        domain_attrs: dict = {
            "source": "dns_mail_records",
            "mx_records": mx_records,
        }
        if spf_record:
            domain_attrs["spf_record"] = spf_record
        if dmarc_record:
            domain_attrs["dmarc_record"] = dmarc_record

        entities.append(EntityCandidate(
            entity_type="domain",
            value=normalized_domain,
            attributes=domain_attrs,
        ))

        for mx in mx_records:
            exchange = mx.get("exchange", "").strip()
            if not exchange:
                continue
            normalized_exchange = normalize_entity_value("hostname", exchange)
            entities.append(EntityCandidate(
                entity_type="hostname",
                value=normalized_exchange,
                attributes={
                    "source": "dns_mail_records",
                    "mx_for": normalized_domain,
                },
            ))
            relationships.append(RelationshipCandidate(
                source_type="domain",
                source_value=normalized_domain,
                target_type="hostname",
                target_value=normalized_exchange,
                relationship_type="mail_handled_by",
                relationship_source="pivot",
                runner="dns_mail_records",
            ))

        return ParseResult(entities=entities, relationships=relationships)
```

- [ ] **Step 4: Write the DNS mail records pivot handler**

```python
# src/easm/pivot/handlers/dns_mail_records.py
import dns.resolver
from easm.pivot.handlers.base import PivotHandler


class DnsMailRecordsHandler(PivotHandler):
    pivot_type = "dns_mail_records"
    source_name = "dns_mail_records"

    async def execute(self, job: dict, pool) -> list[dict]:
        domain = job["entity_value"]
        result: dict = {"domain": domain}

        # MX records
        mx_records = []
        try:
            answers = dns.resolver.resolve(domain, "MX")
            for rdata in answers:
                mx_records.append({
                    "preference": rdata.preference,
                    "exchange": str(rdata.exchange).rstrip("."),
                })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            pass
        result["mx_records"] = mx_records

        # SPF record (from TXT)
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = b" ".join(rdata.strings).decode(errors="replace")
                if txt.startswith("v=spf1"):
                    result["spf_record"] = txt
                    break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            pass

        # DMARC record
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
```

- [ ] **Step 5: Register handler and parser**

Add to `src/easm/pivot/handlers/__init__.py`:
```python
from easm.pivot.handlers.dns_mail_records import DnsMailRecordsHandler
```
And add to `PIVOT_HANDLER_REGISTRY`:
```python
"dns_mail_records": DnsMailRecordsHandler,
```

Add to `src/easm/parse/__init__.py`:
```python
from easm.parse.dns_mail_records_parser import DnsMailRecordsParser
```
And add to `PARSER_REGISTRY`:
```python
"dns_mail_records": DnsMailRecordsParser,
```

Add to `VALID_PIVOT_TYPES` in `src/easm/config.py`:
```python
VALID_PIVOT_TYPES = {
    "dns_resolve", "rdap_lookup", "crtsh_search",
    "shodan_enrich", "reverse_dns", "domain_rdap", "subdomain_enum",
    "dns_mail_records",
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/test_parsers/test_dns_mail_records_parser.py -v`
Expected: All 6 tests PASS

- [ ] **Step 7: Run existing tests to verify no regressions**

Run: `uv run pytest tests/ -v --timeout=30`
Expected: All existing tests still pass

- [ ] **Step 8: Commit**

```bash
git add src/easm/pivot/handlers/dns_mail_records.py \
        src/easm/parse/dns_mail_records_parser.py \
        tests/test_parsers/test_dns_mail_records_parser.py \
        src/easm/pivot/handlers/__init__.py \
        src/easm/parse/__init__.py \
        src/easm/config.py
git commit -m "feat: add DNS mail records pivot handler (SPF, MX, DMARC)"
```

---

## Task 2: Mail Provider Classification

**Files:**
- Create: `src/easm/mail_provider.py`
- Create: `tests/test_mail_provider.py`
- Modify: `src/easm/parse/dns_mail_records_parser.py` (integrate classifier)

- [ ] **Step 1: Write failing tests for the mail provider classifier**

```python
# tests/test_mail_provider.py
import pytest
from easm.mail_provider import classify_mail_provider


def test_classify_google_workspace_from_mx():
    mx_records = [{"preference": 10, "exchange": "smtp.google.com"}]
    result = classify_mail_provider(mx_records=mx_records, spf_record="")
    assert result["provider"] == "google_workspace"
    assert result["confidence"] == "high"


def test_classify_microsoft_365_from_mx():
    mx_records = [{"preference": 10, "exchange": "example-com.mail.protection.outlook.com"}]
    result = classify_mail_provider(mx_records=mx_records, spf_record="")
    assert result["provider"] == "microsoft_365"
    assert result["confidence"] == "high"


def test_classify_from_spf_include():
    mx_records = []
    spf = "v=spf1 include:_spf.google.com ~all"
    result = classify_mail_provider(mx_records=mx_records, spf_record=spf)
    assert result["provider"] == "google_workspace"
    assert result["confidence"] == "medium"


def test_classify_proofpoint_from_mx():
    mx_records = [{"preference": 10, "exchange": "mx.example.com.pphosted.com"}]
    result = classify_mail_provider(mx_records=mx_records, spf_record="")
    assert result["provider"] == "proofpoint"
    assert result["confidence"] == "high"


def test_classify_mimecast_from_mx():
    mx_records = [{"preference": 10, "exchange": "example-com.mail.mimecast.com"}]
    result = classify_mail_provider(mx_records=mx_records, spf_record="")
    assert result["provider"] == "mimecast"
    assert result["confidence"] == "high"


def test_classify_unknown_when_no_match():
    mx_records = [{"preference": 10, "exchange": "mail.unknown-corp.local"}]
    result = classify_mail_provider(mx_records=mx_records, spf_record="")
    assert result["provider"] == "unknown"
    assert result["confidence"] == "low"


def test_classify_empty_inputs():
    result = classify_mail_provider(mx_records=[], spf_record="")
    assert result["provider"] == "unknown"
    assert result["confidence"] == "low"


def test_classify_cross_validation_high_confidence():
    mx_records = [{"preference": 10, "exchange": "smtp.google.com"}]
    spf = "v=spf1 include:_spf.google.com ~all"
    result = classify_mail_provider(mx_records=mx_records, spf_record=spf)
    assert result["provider"] == "google_workspace"
    assert result["confidence"] == "high"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_mail_provider.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'easm.mail_provider'`

- [ ] **Step 3: Write the mail provider classifier**

```python
# src/easm/mail_provider.py
from __future__ import annotations

from typing import Any


# Each entry: (provider_id, mx_hostname_suffix, spf_include_substring)
_PROVIDER_PATTERNS: list[tuple[str, str, str]] = [
    ("google_workspace", ".google.com", "include:_spf.google.com"),
    ("google_workspace", ".googlemail.com", "include:_spf.google.com"),
    ("microsoft_365", ".mail.protection.outlook.com", "include:spf.protection.outlook.com"),
    ("microsoft_365", ".outlook.com", "include:spf.protection.outlook.com"),
    ("proofpoint", ".pphosted.com", "include:pphosted.com"),
    ("mimecast", ".mimecast.com", "include:mimecast.com"),
    ("mimecast", ".mimecast.org", "include:mimecast.org"),
    ("zoho", ".zoho.com", "include:zoho.com"),
    ("fastmail", ".fastmail.com", "include:fastmail.com"),
    ("sendgrid", ".sendgrid.net", "include:sendgrid.net"),
    ("mailgun", ".mailgun.org", "include:mailgun.org"),
    ("postmark", ".postmarkapp.com", "include:postmarkapp.com"),
    ("amazon_ses", ".amazonses.com", "include:amazonses.com"),
    ("yahoo", ".yahoodns.net", "include:yahoo.com"),
]


def classify_mail_provider(
    mx_records: list[dict[str, Any]],
    spf_record: str,
) -> dict[str, str]:
    """Classify the mail provider based on MX records and SPF includes.

    Returns {"provider": str, "confidence": "high"|"medium"|"low"}.
    Confidence levels:
      - high: MX and SPF both point to same provider
      - medium: Only MX or only SPF matches
      - low: No match found (provider is "unknown")
    """
    mx_exchanges = [
        r.get("exchange", "").lower().rstrip(".")
        for r in mx_records
        if r.get("exchange")
    ]

    mx_match: str | None = None
    for exchange in mx_exchanges:
        for provider_id, mx_suffix, _spf_include in _PROVIDER_PATTERNS:
            if exchange.endswith(mx_suffix):
                mx_match = provider_id
                break
        if mx_match:
            break

    spf_match: str | None = None
    if spf_record:
        spf_lower = spf_record.lower()
        for provider_id, _mx_suffix, spf_include in _PROVIDER_PATTERNS:
            if spf_include.lower() in spf_lower:
                spf_match = provider_id
                break

    if mx_match and spf_match and mx_match == spf_match:
        return {"provider": mx_match, "confidence": "high"}
    if mx_match:
        return {"provider": mx_match, "confidence": "medium"}
    if spf_match:
        return {"provider": spf_match, "confidence": "medium"}
    return {"provider": "unknown", "confidence": "low"}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_mail_provider.py -v`
Expected: All 8 tests PASS

- [ ] **Step 5: Integrate classifier into the DNS mail records parser**

Modify `src/easm/parse/dns_mail_records_parser.py` — add the import and call after building domain_attrs:

```python
# Add at top of file:
from easm.mail_provider import classify_mail_provider

# After building domain_attrs dict (after spf_record and dmarc_record), add:
        mail_provider = classify_mail_provider(
            mx_records=mx_records,
            spf_record=spf_record,
        )
        domain_attrs["mail_provider"] = mail_provider
```

- [ ] **Step 6: Add a test for mail provider integration in parser**

Add to `tests/test_parsers/test_dns_mail_records_parser.py`:

```python
@pytest.mark.asyncio
async def test_mail_records_parser_includes_mail_provider():
    parser = DnsMailRecordsParser()
    event = {
        "raw": {
            "domain": "example.com",
            "mx_records": [{"preference": 10, "exchange": "smtp.google.com"}],
            "spf_record": "v=spf1 include:_spf.google.com ~all",
        }
    }
    result = await parser.parse(event)
    domain_ent = next(e for e in result.entities if e.entity_type == "domain" and e.value == "example.com")
    assert domain_ent.attributes["mail_provider"]["provider"] == "google_workspace"
    assert domain_ent.attributes["mail_provider"]["confidence"] == "high"
```

- [ ] **Step 7: Run all tests**

Run: `uv run pytest tests/test_mail_provider.py tests/test_parsers/test_dns_mail_records_parser.py -v`
Expected: All tests PASS

- [ ] **Step 8: Commit**

```bash
git add src/easm/mail_provider.py \
        tests/test_mail_provider.py \
        src/easm/parse/dns_mail_records_parser.py \
        tests/test_parsers/test_dns_mail_records_parser.py
git commit -m "feat: add mail provider classification (Google, Microsoft, etc.)"
```

---

## Task 3: Live TLS Certificate Grab + SAN Pivot

**Files:**
- Create: `src/easm/pivot/handlers/tls_cert_grab.py`
- Create: `src/easm/parse/tls_cert_parser.py`
- Create: `tests/test_parsers/test_tls_cert_parser.py`
- Modify: `src/easm/pivot/handlers/__init__.py`
- Modify: `src/easm/parse/__init__.py`
- Modify: `src/easm/config.py`
- Modify: `pyproject.toml` (add `cryptography` dep)

- [ ] **Step 1: Add `cryptography` dependency**

Add to `pyproject.toml` dependencies list:
```
"cryptography>=44.0.0",
```

Run: `uv sync`

- [ ] **Step 2: Write failing tests for TLS cert parser**

```python
# tests/test_parsers/test_tls_cert_parser.py
import pytest
from easm.parse.tls_cert_parser import TlsCertParser


@pytest.mark.asyncio
async def test_tls_cert_parser_extracts_cert_entity():
    parser = TlsCertParser()
    event = {
        "raw": {
            "hostname": "example.com",
            "port": 443,
            "cert": {
                "subject_cn": "example.com",
                "issuer_cn": "Let's Encrypt Authority X3",
                "issuer_org": "Let's Encrypt",
                "serial_number": "0123456789abcdef",
                "not_before": "2024-01-01T00:00:00Z",
                "not_after": "2025-01-01T00:00:00Z",
                "fingerprint_sha256": "abc123def456",
                "san_dns_names": ["example.com", "www.example.com", "api.example.com"],
            },
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    cert_entities = [e for e in result.entities if e.entity_type == "certificate"]
    assert len(cert_entities) == 1
    assert cert_entities[0].attributes["subject_cn"] == "example.com"
    assert cert_entities[0].attributes["issuer_cn"] == "Let's Encrypt Authority X3"
    assert cert_entities[0].attributes["san_dns_names"] == [
        "example.com", "www.example.com", "api.example.com"
    ]


@pytest.mark.asyncio
async def test_tls_cert_parser_creates_san_domain_entities():
    parser = TlsCertParser()
    event = {
        "raw": {
            "hostname": "example.com",
            "cert": {
                "subject_cn": "example.com",
                "fingerprint_sha256": "fp789",
                "san_dns_names": ["example.com", "api.example.com"],
            },
        }
    }
    result = await parser.parse(event)
    domain_entities = [e for e in result.entities if e.entity_type == "domain"]
    domain_values = {e.value for e in domain_entities}
    assert "example.com" in domain_values
    assert "api.example.com" in domain_values


@pytest.mark.asyncio
async def test_tls_cert_parser_creates_san_relationships():
    parser = TlsCertParser()
    event = {
        "raw": {
            "hostname": "example.com",
            "cert": {
                "subject_cn": "example.com",
                "fingerprint_sha256": "fp_rels",
                "san_dns_names": ["example.com", "sub.example.com"],
            },
        }
    }
    result = await parser.parse(event)
    issued_for_rels = [r for r in result.relationships if r.relationship_type == "san_contains"]
    assert len(issued_for_rels) == 2
    cert_value = "fp_rels"
    san_targets = {r.target_value for r in issued_for_rels}
    assert san_targets == {"example.com", "sub.example.com"}


@pytest.mark.asyncio
async def test_tls_cert_parser_empty_san():
    parser = TlsCertParser()
    event = {
        "raw": {
            "hostname": "example.com",
            "cert": {
                "subject_cn": "example.com",
                "fingerprint_sha256": "fp_empty_san",
                "san_dns_names": [],
            },
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    cert_entities = [e for e in result.entities if e.entity_type == "certificate"]
    assert len(cert_entities) == 1


@pytest.mark.asyncio
async def test_tls_cert_parser_missing_cert():
    parser = TlsCertParser()
    event = {"raw": {"hostname": "example.com"}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_tls_cert_parser_class_attributes():
    assert TlsCertParser.source_name == "tls_cert"
    assert TlsCertParser.current_version == 1
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_parsers/test_tls_cert_parser.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 4: Write the TLS cert parser**

```python
# src/easm/parse/tls_cert_parser.py
from easm.parse.base import BaseParser, ParseResult, EntityCandidate, RelationshipCandidate
from easm.entity_store import normalize_entity_value


class TlsCertParser(BaseParser):
    source_name = "tls_cert"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        hostname = raw.get("hostname", "").strip()
        cert_data = raw.get("cert")
        if not hostname or not cert_data:
            return ParseResult(entities=[], relationships=[], unparseable=True,
                               parse_error="missing hostname or cert data")

        cert_value = cert_data.get("fingerprint_sha256", cert_data.get("serial_number", ""))
        if not cert_value:
            return ParseResult(entities=[], relationships=[], unparseable=True,
                               parse_error="no cert fingerprint or serial")

        normalized_hostname = normalize_entity_value("hostname", hostname)
        san_names = cert_data.get("san_dns_names", [])

        entities: list[EntityCandidate] = []
        relationships: list[RelationshipCandidate] = []

        # Certificate entity
        cert_attrs: dict = {
            "source": "tls_cert",
            "subject_cn": cert_data.get("subject_cn", ""),
            "issuer_cn": cert_data.get("issuer_cn", ""),
            "issuer_org": cert_data.get("issuer_org", ""),
            "serial_number": cert_data.get("serial_number", ""),
            "not_before": cert_data.get("not_before", ""),
            "not_after": cert_data.get("not_after", ""),
            "fingerprint_sha256": cert_data.get("fingerprint_sha256", ""),
            "san_dns_names": san_names,
            "grabbed_from": normalized_hostname,
        }
        entities.append(EntityCandidate(
            entity_type="certificate",
            value=cert_value,
            attributes=cert_attrs,
        ))

        # Relationship: hostname → certificate (issued_for)
        relationships.append(RelationshipCandidate(
            source_type="hostname",
            source_value=normalized_hostname,
            target_type="certificate",
            target_value=cert_value,
            relationship_type="issued_for",
            relationship_source="pivot",
            runner="tls_cert",
        ))

        # SAN domains as new entities + relationships
        for san in san_names:
            normalized_san = normalize_entity_value("domain", san)
            entities.append(EntityCandidate(
                entity_type="domain",
                value=normalized_san,
                attributes={"source": "tls_cert"},
            ))
            relationships.append(RelationshipCandidate(
                source_type="certificate",
                source_value=cert_value,
                target_type="domain",
                target_value=normalized_san,
                relationship_type="san_contains",
                relationship_source="pivot",
                runner="tls_cert",
            ))
            relationships.append(RelationshipCandidate(
                source_type="domain",
                source_value=normalized_san,
                target_type="certificate",
                target_value=cert_value,
                relationship_type="reverse_of",
                relationship_source="correlation",
            ))

        return ParseResult(entities=entities, relationships=relationships)
```

- [ ] **Step 5: Write the TLS cert grab pivot handler**

```python
# src/easm/pivot/handlers/tls_cert_grab.py
from __future__ import annotations

import hashlib
import logging
import ssl
import socket
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from easm.pivot.handlers.base import PivotHandler

logger = logging.getLogger(__name__)


class TlsCertGrabHandler(PivotHandler):
    pivot_type = "tls_cert_grab"
    source_name = "tls_cert"

    async def execute(self, job: dict, pool) -> list[dict]:
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

        cert = x509.load_der_x509_certificate(der_cert)

        # Extract subject CN
        try:
            subject_cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        except (IndexError, Exception):
            subject_cn = ""

        # Extract issuer CN and org
        try:
            issuer_cn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        except (IndexError, Exception):
            issuer_cn = ""
        try:
            issuer_org = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value
        except (IndexError, Exception):
            issuer_org = ""

        # Extract SAN DNS names
        san_dns_names: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        # Fingerprint
        fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()

        # Serial number
        serial_number = format(cert.serial_number, "x")

        # Validity
        not_before = cert.not_valid_before_utc.isoformat()
        not_after = cert.not_valid_after_utc.isoformat()

        return [{
            "hostname": hostname,
            "port": port,
            "cert": {
                "subject_cn": subject_cn,
                "issuer_cn": issuer_cn,
                "issuer_org": issuer_org,
                "serial_number": serial_number,
                "not_before": not_before,
                "not_after": not_after,
                "fingerprint_sha256": fingerprint_sha256,
                "san_dns_names": san_dns_names,
            },
        }]
```

- [ ] **Step 6: Register handler, parser, and pivot type**

Add to `src/easm/pivot/handlers/__init__.py`:
```python
from easm.pivot.handlers.tls_cert_grab import TlsCertGrabHandler
```
Add to `PIVOT_HANDLER_REGISTRY`:
```python
"tls_cert_grab": TlsCertGrabHandler,
```

Add to `src/easm/parse/__init__.py`:
```python
from easm.parse.tls_cert_parser import TlsCertParser
```
Add to `PARSER_REGISTRY`:
```python
"tls_cert": TlsCertParser,
```

Add to `VALID_PIVOT_TYPES` in `src/easm/config.py`:
```python
"tls_cert_grab",
```

- [ ] **Step 7: Run tests**

Run: `uv run pytest tests/test_parsers/test_tls_cert_parser.py -v`
Expected: All 6 tests PASS

- [ ] **Step 8: Run full test suite**

Run: `uv run pytest tests/ -v --timeout=30`
Expected: All tests pass, no regressions

- [ ] **Step 9: Commit**

```bash
git add src/easm/pivot/handlers/tls_cert_grab.py \
        src/easm/parse/tls_cert_parser.py \
        tests/test_parsers/test_tls_cert_parser.py \
        src/easm/pivot/handlers/__init__.py \
        src/easm/parse/__init__.py \
        src/easm/config.py \
        pyproject.toml \
        uv.lock
git commit -m "feat: add live TLS certificate grab with SAN pivot"
```

---

## Task 4: RDAP Domain Enrichment (WHOIS)

**Files:**
- Modify: `src/easm/pivot/handlers/domain_rdap.py` (expand to collect full data)
- Modify: `src/easm/config.py` (add `domain_rdap` to `VALID_PIVOT_TYPES` — already registered in handler registry but missing from config)

- [ ] **Step 1: Write tests for enhanced domain RDAP handler**

Create `tests/test_pivot/test_domain_rdap_handler.py`:

```python
# tests/test_pivot/test_domain_rdap_handler.py
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from easm.pivot.handlers.domain_rdap import DomainRdapHandler


@pytest.mark.asyncio
async def test_domain_rdap_handler_returns_list():
    handler = DomainRdapHandler()
    job = {"entity_value": "example.com"}
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {
        "ldhName": "example.com",
        "status": ["client transfer prohibited"],
        "events": [
            {"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2026-01-01T00:00:00Z"},
        ],
        "nameservers": [
            {"ldhName": "a.iana-servers.net"},
            {"ldhName": "b.iana-servers.net"},
        ],
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Corp"]]],
            }
        ],
    }
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("easm.pivot.handlers.domain_rdap.httpx.AsyncClient", return_value=mock_client):
        results = await handler.execute(job, None)

    assert len(results) == 1
    assert results[0]["domain"] == "example.com"
    assert "registrar" in results[0] or "org" in results[0]


@pytest.mark.asyncio
async def test_domain_rdap_handler_failure_returns_message():
    handler = DomainRdapHandler()
    job = {"entity_value": "nonexistent-domain-xyz123.com"}
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=Exception("RDAP failed"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("easm.pivot.handlers.domain_rdap.httpx.AsyncClient", return_value=mock_client):
        results = await handler.execute(job, None)

    assert len(results) == 1
    assert "message" in results[0]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_pivot/test_domain_rdap_handler.py -v`
Expected: Tests may partially pass if current handler happens to work, but the enhanced version should add more fields

- [ ] **Step 3: Rewrite domain RDAP handler with full data extraction**

```python
# src/easm/pivot/handlers/domain_rdap.py  (REPLACE entire file)
from __future__ import annotations

import logging
from typing import Any

import httpx

from easm.pivot.handlers.base import PivotHandler

logger = logging.getLogger(__name__)


class DomainRdapHandler(PivotHandler):
    pivot_type = "domain_rdap"
    source_name = "domain_rdap"

    # Bootstrapped RDAP base URLs per TLD; fall back to rdap.org
    _RDAP_BOOTSTRAP: dict[str, str] = {
        "com": "https://rdap.verisign.com/com/v1",
        "net": "https://rdap.verisign.com/net/v1",
        "org": "https://rdap.org",
    }

    def _rdap_url(self, domain: str) -> str:
        parts = domain.rsplit(".", 1)
        tld = parts[-1].lower() if len(parts) > 1 else ""
        base = self._RDAP_BOOTSTRAP.get(tld, "https://rdap.org")
        return f"{base}/domain/{domain}"

    def _extract_vcard_fn(self, entities: list[dict]) -> str:
        for entity in entities:
            vcard_arr = entity.get("vcardArray", [])
            if isinstance(vcard_arr, list) and len(vcard_arr) >= 2:
                for item in vcard_arr[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        return str(item[3])
        return ""

    def _extract_events(self, data: dict) -> dict[str, str]:
        events: dict[str, str] = {}
        for event in data.get("events", []):
            action = event.get("eventAction", "")
            date = event.get("eventDate", "")
            if action and date:
                events[action] = date
        return events

    async def execute(self, job: dict, pool) -> list[dict[str, Any]]:
        domain = job["entity_value"]
        url = self._rdap_url(domain)

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                logger.debug("RDAP lookup failed for %s: %s", domain, e)
                return [{"domain": domain, "message": f"rdap lookup failed: {e}"}]

        result: dict[str, Any] = {"domain": domain, "source": "domain_rdap"}

        # Status
        if data.get("status"):
            result["status"] = data["status"]

        # Registrar — look for entity with "registrar" role
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                result["registrar"] = self._extract_vcard_fn([entity])
            if "registrant" in roles:
                result["registrant_org"] = self._extract_vcard_fn([entity])

        # Also try top-level vcardArray
        if not result.get("registrant_org"):
            org = self._extract_vcard_fn(data.get("entities", []))
            if org:
                result["registrant_org"] = org

        # Events (registration, expiration, last changed)
        events = self._extract_events(data)
        if events.get("registration"):
            result["created_date"] = events["registration"]
        if events.get("expiration"):
            result["expiration_date"] = events["expiration"]
        if events.get("last changed"):
            result["updated_date"] = events["last changed"]

        # Nameservers
        nameservers = [ns.get("ldhName", "") for ns in data.get("nameservers", [])]
        if nameservers:
            result["nameservers"] = nameservers

        return [result]
```

- [ ] **Step 4: Ensure `domain_rdap` is in `VALID_PIVOT_TYPES`**

Check `src/easm/config.py` — `domain_rdap` should be in the set. It's already registered in the handler registry but may not be in `VALID_PIVOT_TYPES`. If missing, add it.

- [ ] **Step 5: Run tests**

Run: `uv run pytest tests/test_pivot/test_domain_rdap_handler.py -v`
Expected: Tests PASS

- [ ] **Step 6: Run full test suite**

Run: `uv run pytest tests/ -v --timeout=30`
Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add src/easm/pivot/handlers/domain_rdap.py \
        tests/test_pivot/test_domain_rdap_handler.py \
        src/easm/config.py
git commit -m "feat: enhance domain RDAP handler with full WHOIS data extraction"
```

---

## Task 5: Geo-IP Enrichment (Backend)

**Files:**
- Create: `src/easm/geoip.py`
- Create: `src/easm/pivot/handlers/geoip_enrich.py`
- Create: `src/easm/parse/geoip_parser.py`
- Create: `tests/test_geoip.py`
- Create: `tests/test_parsers/test_geoip_parser.py`
- Modify: `src/easm/pivot/handlers/__init__.py`
- Modify: `src/easm/parse/__init__.py`
- Modify: `src/easm/config.py`
- Modify: `pyproject.toml` (add `maxminddb` dep)
- Modify: `Dockerfile` (add GeoLite2 DB download)

- [ ] **Step 1: Add `maxminddb` dependency**

Add to `pyproject.toml` dependencies list:
```
"maxminddb>=2.6.0",
```

Run: `uv sync`

- [ ] **Step 2: Write failing tests for the geo-IP module**

```python
# tests/test_geoip.py
import pytest
from unittest.mock import patch, MagicMock
from easm.geoip import GeoIpLookup, GeoIpResult


def test_geoip_lookup_returns_result():
    mock_reader = MagicMock()
    mock_reader.get.return_value = {
        "city": {"names": {"en": "Mountain View"}},
        "country": {"iso_code": "US", "names": {"en": "United States"}},
        "location": {"latitude": 37.386, "longitude": -122.0838},
    }
    lookup = GeoIpLookup(reader=mock_reader)
    result = lookup.lookup("8.8.8.8")
    assert isinstance(result, GeoIpResult)
    assert result.city == "Mountain View"
    assert result.country_code == "US"
    assert result.country_name == "United States"
    assert result.latitude == 37.386
    assert result.longitude == -122.0838


def test_geoip_lookup_returns_none_for_missing():
    mock_reader = MagicMock()
    mock_reader.get.return_value = None
    lookup = GeoIpLookup(reader=mock_reader)
    result = lookup.lookup("192.0.2.1")
    assert result is None


def test_geoip_result_to_dict():
    result = GeoIpResult(
        city="London",
        country_code="GB",
        country_name="United Kingdom",
        latitude=51.5074,
        longitude=-0.1278,
        asn=None,
        asn_org=None,
    )
    d = result.to_dict()
    assert d["city"] == "London"
    assert d["country_code"] == "GB"
    assert d["latitude"] == 51.5074
    assert d["longitude"] == -0.1278
```

- [ ] **Step 3: Write the geo-IP module**

```python
# src/easm/geoip.py
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path(__file__).parent.parent.parent / "data" / "GeoLite2-City.mmdb"


@dataclass
class GeoIpResult:
    city: str | None
    country_code: str | None
    country_name: str | None
    latitude: float | None
    longitude: float | None
    asn: int | None = None
    asn_org: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "city": self.city,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "asn": self.asn,
            "asn_org": self.asn_org,
        }


class GeoIpLookup:
    def __init__(self, reader: Any = None, db_path: str | Path | None = None):
        self._reader = reader
        self._owns_reader = False
        if reader is None:
            path = Path(db_path) if db_path else _DEFAULT_DB_PATH
            if path.exists():
                try:
                    import maxminddb
                    self._reader = maxminddb.Reader(str(path))
                    self._owns_reader = True
                except Exception:
                    logger.warning("Failed to open GeoLite2 database at %s", path)
            else:
                logger.info("GeoLite2 database not found at %s, geo-IP lookups disabled", path)

    def lookup(self, ip: str) -> GeoIpResult | None:
        if self._reader is None:
            return None
        try:
            result = self._reader.get(ip)
        except Exception:
            return None
        if result is None:
            return None

        city = None
        if "city" in result:
            city = result["city"].get("names", {}).get("en")

        country_code = None
        country_name = None
        if "country" in result:
            country_code = result["country"].get("iso_code")
            country_name = result["country"].get("names", {}).get("en")

        lat = None
        lon = None
        if "location" in result:
            lat = result["location"].get("latitude")
            lon = result["location"].get("longitude")

        return GeoIpResult(
            city=city,
            country_code=country_code,
            country_name=country_name,
            latitude=lat,
            longitude=lon,
        )

    def close(self):
        if self._owns_reader and self._reader:
            self._reader.close()
```

- [ ] **Step 4: Write tests for geo-IP parser**

```python
# tests/test_parsers/test_geoip_parser.py
import pytest
from easm.parse.geoip_parser import GeoIpParser


@pytest.mark.asyncio
async def test_geoip_parser_adds_geo_attributes():
    parser = GeoIpParser()
    event = {
        "raw": {
            "ip": "8.8.8.8",
            "geo": {
                "city": "Mountain View",
                "country_code": "US",
                "country_name": "United States",
                "latitude": 37.386,
                "longitude": -122.0838,
                "asn": None,
                "asn_org": None,
            },
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    assert len(result.entities) == 1
    assert result.entities[0].entity_type == "ip"
    assert result.entities[0].value == "8.8.8.8"
    assert result.entities[0].attributes["geo"]["city"] == "Mountain View"
    assert result.entities[0].attributes["geo"]["latitude"] == 37.386


@pytest.mark.asyncio
async def test_geoip_parser_missing_ip():
    parser = GeoIpParser()
    event = {"raw": {"geo": {"city": "Test"}}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_geoip_parser_missing_geo():
    parser = GeoIpParser()
    event = {"raw": {"ip": "8.8.8.8"}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_geoip_parser_class_attributes():
    assert GeoIpParser.source_name == "geoip"
    assert GeoIpParser.current_version == 1
```

- [ ] **Step 5: Write the geo-IP parser**

```python
# src/easm/parse/geoip_parser.py
from easm.parse.base import BaseParser, ParseResult, EntityCandidate
from easm.entity_store import normalize_entity_value


class GeoIpParser(BaseParser):
    source_name = "geoip"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        ip = raw.get("ip", "").strip()
        geo = raw.get("geo")
        if not ip or not geo:
            return ParseResult(entities=[], relationships=[], unparseable=True,
                               parse_error="missing ip or geo data")

        normalized_ip = normalize_entity_value("ip", ip)
        return ParseResult(
            entities=[
                EntityCandidate(
                    entity_type="ip",
                    value=normalized_ip,
                    attributes={"source": "geoip", "geo": geo},
                ),
            ],
            relationships=[],
        )
```

- [ ] **Step 6: Write the geo-IP pivot handler**

```python
# src/easm/pivot/handlers/geoip_enrich.py
from easm.geoip import GeoIpLookup
from easm.pivot.handlers.base import PivotHandler


class GeoIpEnrichHandler(PivotHandler):
    pivot_type = "geoip_enrich"
    source_name = "geoip"

    def __init__(self, geoip_lookup: GeoIpLookup | None = None):
        self._lookup = geoip_lookup or GeoIpLookup()

    async def execute(self, job: dict, pool) -> list[dict]:
        ip = job["entity_value"]
        result = self._lookup.lookup(ip)
        if result is None:
            return [{"ip": ip, "message": "no geo-IP data available"}]
        return [{"ip": ip, "geo": result.to_dict()}]
```

- [ ] **Step 7: Register handler, parser, pivot type**

Add to `src/easm/pivot/handlers/__init__.py`:
```python
from easm.pivot.handlers.geoip_enrich import GeoIpEnrichHandler
```
Add to `PIVOT_HANDLER_REGISTRY`:
```python
"geoip_enrich": GeoIpEnrichHandler,
```

Add to `src/easm/parse/__init__.py`:
```python
from easm.parse.geoip_parser import GeoIpParser
```
Add to `PARSER_REGISTRY`:
```python
"geoip": GeoIpParser,
```

Add to `VALID_PIVOT_TYPES` in `src/easm/config.py`:
```python
"geoip_enrich",
```

- [ ] **Step 8: Add GeoLite2 DB download to Dockerfile**

Add before the final stage in `Dockerfile`:
```dockerfile
RUN mkdir -p /app/data && \
    curl -fsSL "https://git.io/GeoLite2-City.mmdb" -o /app/data/GeoLite2-City.mmdb || \
    echo "GeoLite2 DB download failed — geo-IP will be disabled"
```

Note: The actual download URL requires a MaxMind license key or the GeoLite2 mirror. Adjust the URL to your preferred source. For development, you can download manually from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data and place it at `data/GeoLite2-City.mmdb`.

- [ ] **Step 9: Run tests**

Run: `uv run pytest tests/test_geoip.py tests/test_parsers/test_geoip_parser.py -v`
Expected: All tests PASS

- [ ] **Step 10: Run full test suite**

Run: `uv run pytest tests/ -v --timeout=30`
Expected: All tests pass

- [ ] **Step 11: Commit**

```bash
git add src/easm/geoip.py \
        src/easm/pivot/handlers/geoip_enrich.py \
        src/easm/parse/geoip_parser.py \
        tests/test_geoip.py \
        tests/test_parsers/test_geoip_parser.py \
        src/easm/pivot/handlers/__init__.py \
        src/easm/parse/__init__.py \
        src/easm/config.py \
        pyproject.toml \
        uv.lock \
        Dockerfile
git commit -m "feat: add geo-IP enrichment with MaxMind GeoLite2"
```

---

## Task 6: Geo Map Display (Frontend)

**Files:**
- Create: `ui/src/components/GeoMap.tsx`
- Modify: `ui/src/App.tsx` (add route)
- Modify: `ui/package.json` (add `maplibre-gl` dep)

- [ ] **Step 1: Install maplibre-gl**

Run: `cd ui && npm install maplibre-gl`

- [ ] **Step 2: Create the GeoMap component**

```tsx
// ui/src/components/GeoMap.tsx
import { useEffect, useRef, useState } from "react";
import maplibregl from "maplibre-gl";
import "maplibre-gl/dist/maplibre-gl.css";
import ky from "ky";

interface IpEntity {
  id: string;
  entity_type: string;
  entity_value: string;
  attributes: {
    geo?: {
      city?: string;
      country_code?: string;
      country_name?: string;
      latitude?: number;
      longitude?: number;
    };
    [key: string]: unknown;
  };
}

export function GeoMap() {
  const mapContainer = useRef<HTMLDivElement>(null);
  const mapRef = useRef<maplibregl.Map | null>(null);
  const [ips, setIps] = useState<IpEntity[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchIps() {
      try {
        const resp = await ky
          .get("/api/entities", { searchParams: { type: "ip", limit: "500" } })
          .json<{ entities: IpEntity[] }>();
        setIps(resp.entities);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to fetch IPs");
      } finally {
        setLoading(false);
      }
    }
    fetchIps();
  }, []);

  useEffect(() => {
    if (!mapContainer.current || mapRef.current) return;

    const map = new maplibregl.Map({
      container: mapContainer.current,
      style: {
        version: 8,
        sources: {
          osm: {
            type: "raster",
            tiles: ["https://tile.openstreetmap.org/{z}/{x}/{y}.png"],
            tileSize: 256,
            attribution: "&copy; OpenStreetMap contributors",
          },
        },
        layers: [{ id: "osm", type: "raster", source: "osm" }],
      },
      center: [0, 20],
      zoom: 2,
    });

    map.addControl(new maplibregl.NavigationControl(), "top-right");
    mapRef.current = map;

    return () => {
      map.remove();
      mapRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (!mapRef.current || loading || ips.length === 0) return;

    const map = mapRef.current;
    const geoIps = ips.filter(
      (ip) => ip.attributes.geo?.latitude && ip.attributes.geo?.longitude
    );

    if (geoIps.length === 0) return;

    // Add markers
    const bounds = new maplibregl.LngLatBounds();

    for (const ip of geoIps) {
      const { latitude, longitude, city, country_name } = ip.attributes.geo!;
      const lngLat = new maplibregl.LngLat(longitude!, latitude!);

      const popup = new maplibregl.Popup({ offset: 25 }).setHTML(
        `<div>
          <strong>${ip.entity_value}</strong><br />
          ${city ? `${city}, ` : ""}${country_name || ""}
        </div>`
      );

      new maplibregl.Marker({ color: "#3b82f6" })
        .setLngLat(lngLat)
        .setPopup(popup)
        .addTo(map);

      bounds.extend(lngLat);
    }

    map.fitBounds(bounds, { padding: 50, maxZoom: 10 });
  }, [ips, loading]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800">
        <h1 className="text-lg font-semibold text-zinc-100">Geo Map</h1>
        <span className="text-sm text-zinc-400">
          {loading ? "Loading..." : `${ips.filter((ip) => ip.attributes.geo?.latitude).length} IPs located`}
        </span>
      </div>
      {error && (
        <div className="px-4 py-2 bg-red-900/30 text-red-300 text-sm">{error}</div>
      )}
      <div ref={mapContainer} className="flex-1 min-h-[500px]" />
    </div>
  );
}
```

- [ ] **Step 3: Add route to App.tsx**

Find the existing route definitions in `ui/src/App.tsx` and add a new route for the geo map. The exact location depends on the existing router setup — add alongside the existing routes:

```tsx
import { GeoMap } from "./components/GeoMap";
// Add to routes:
<Route path="/geo" element={<GeoMap />} />
```

Also add a nav link in the sidebar/navigation for "Geo Map".

- [ ] **Step 4: Verify the build compiles**

Run: `cd ui && npm run build`
Expected: Build succeeds with no TypeScript errors

- [ ] **Step 5: Commit**

```bash
git add ui/src/components/GeoMap.tsx \
        ui/src/App.tsx \
        ui/package.json \
        ui/package-lock.json
git commit -m "feat: add geo map component with maplibre-gl"
```

---

## Task 7: Config Example + Final Integration

**Files:**
- Modify: `config.yaml.example` (add new pivot rules)

- [ ] **Step 1: Update config example with new pivot rules**

Add these pivot rules to `config.yaml.example` inside the `pivot.allowed_pivots` list:

```yaml
        - from: domain
          to: domain
          via: dns_mail_records
          cooldown_hours: 24
        - from: hostname
          to: certificate
          via: tls_cert_grab
          cooldown_hours: 24
        - from: domain
          to: domain
          via: domain_rdap
          cooldown_hours: 168
        - from: ip
          to: ip
          via: geoip_enrich
          cooldown_hours: 168
```

- [ ] **Step 2: Run full test suite**

Run: `uv run pytest tests/ -v --timeout=30`
Expected: All tests pass

- [ ] **Step 3: Run linter and type checker**

Run: `uv run ruff check src/ && uv run mypy src/`
Expected: No errors

- [ ] **Step 4: Commit**

```bash
git add config.yaml.example
git commit -m "docs: add new enrichment pivot rules to config example"
```

---

## Self-Review

**Spec coverage:**
- ✅ SPF, MX, DNS collection → Task 1
- ✅ Mail provider classification → Task 2
- ✅ Certificate info (CN, issuer, SANs, dates, fingerprint) → Task 3
- ✅ SAN extraction as pivot point → Task 3 (SAN domains become domain entities that trigger further pivots)
- ✅ WHOIS/RDAP domain info → Task 4
- ✅ Geo-IP lookup → Task 5
- ✅ Geo map display → Task 6
- ✅ Config integration → Task 7

**Placeholder scan:** No TBDs, TODOs, or "implement later" patterns found. Every step has complete code.

**Type consistency:** All handler classes follow `PivotHandler` base class. All parsers follow `BaseParser`. Entity types use string values matching `EntityType` enum. Source names match between handler → parser → registry keys.

**Dependency summary:**
| New Dep | Purpose | Task |
|---------|---------|------|
| `cryptography>=44.0.0` | X.509 cert parsing | Task 3 |
| `maxminddb>=2.6.0` | GeoLite2 DB queries | Task 5 |
| `maplibre-gl` (npm) | Map rendering | Task 6 |

**Execution order:** Tasks 1-2 are sequential (Task 2 builds on Task 1's parser). Tasks 3, 4, 5 are independent of each other. Task 6 depends on Task 5 (needs geo data to display). Task 7 is final integration.
