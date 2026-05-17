# Phase 1 Enrichment — Threat Intel + Cloud Assets Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add threat intelligence enrichment (GreyNoise, AbuseIPDB, URLScan.io) on discovered IPs/domains and cloud storage bucket enumeration for S3, GCS, and Azure Blob.

**Architecture:** Threat intel follows the existing pivot handler + parser pattern — each source is a PivotHandler that queries an external API, returns raw data, and a BaseParser extracts entity attributes. Cloud asset discovery follows the runner pattern — a scheduled ApiRunner that enumerates bucket names and checks public access.

**Tech Stack:** Python 3.14, httpx, Pydantic, pytest-asyncio.

---

## File Structure

### New Files

| File | Responsibility |
|------|---------------|
| `src/easm/pivot/handlers/greynoise_enrich.py` | Pivot handler: query GreyNoise community API for IP reputation |
| `src/easm/parse/greynoise_parser.py` | Parser: extract threat intel attributes from GreyNoise data |
| `src/easm/pivot/handlers/abuseipdb_enrich.py` | Pivot handler: query AbuseIPDB API for IP abuse reports |
| `src/easm/parse/abuseipdb_parser.py` | Parser: extract abuse confidence, reports from AbuseIPDB data |
| `src/easm/pivot/handlers/urlscan_enrich.py` | Pivot handler: query URLScan.io search for domain scan results |
| `src/easm/parse/urlscan_parser.py` | Parser: extract scan results, malicious flags from URLScan.io data |
| `src/easm/runners/cloud_bucket_runner.py` | ApiRunner: enumerate S3/GCS/Azure Blob buckets from domain names |
| `src/easm/parse/cloud_bucket_parser.py` | Parser: extract cloud storage domain entities from bucket results |
| `tests/test_parsers/test_greynoise_parser.py` | Tests for GreyNoise parser |
| `tests/test_parsers/test_abuseipdb_parser.py` | Tests for AbuseIPDB parser |
| `tests/test_parsers/test_urlscan_parser.py` | Tests for URLScan.io parser |
| `tests/test_parsers/test_cloud_bucket_parser.py` | Tests for cloud bucket parser |
| `tests/test_runners/test_cloud_bucket_runner.py` | Tests for cloud bucket runner |

### Modified Files

| File | Change |
|------|--------|
| `src/easm/pivot/handlers/__init__.py` | Register 3 new pivot handlers |
| `src/easm/parse/__init__.py` | Register 4 new parsers |
| `src/easm/runners/__init__.py` | Register cloud bucket runner |
| `src/easm/config.py` | Add 3 pivot types to `VALID_PIVOT_TYPES`, add `cloud_enum` to `VALID_RUNNER_NAMES` and `SCHEDULABLE_RUNNERS` |
| `config.yaml.example` | Add threat intel pivot rules and cloud bucket runner config |

---

## Task 1: GreyNoise IP Reputation Enrichment

**Files:**
- Create: `src/easm/pivot/handlers/greynoise_enrich.py`
- Create: `src/easm/parse/greynoise_parser.py`
- Create: `tests/test_parsers/test_greynoise_parser.py`
- Modify: `src/easm/pivot/handlers/__init__.py`
- Modify: `src/easm/parse/__init__.py`
- Modify: `src/easm/config.py`

- [ ] **Step 1: Write failing tests for the GreyNoise parser**

```python
# tests/test_parsers/test_greynoise_parser.py
import pytest
from easm.parse.greynoise_parser import GreyNoiseParser


@pytest.mark.asyncio
async def test_greynoise_parser_extracts_attributes():
    parser = GreyNoiseParser()
    event = {
        "raw": {
            "ip": "8.8.8.8",
            "greynoise": {
                "classification": "malicious",
                "noise": True,
                "riot": False,
                "name": "Google DNS",
                "link": "https://viz.greynoise.io/ip/8.8.8.8",
            },
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    assert len(result.entities) == 1
    assert result.entities[0].entity_type == "ip"
    assert result.entities[0].value == "8.8.8.8"
    attrs = result.entities[0].attributes
    assert attrs["source"] == "greynoise"
    assert attrs["threat_intel"]["greynoise"]["classification"] == "malicious"
    assert attrs["threat_intel"]["greynoise"]["noise"] is True


@pytest.mark.asyncio
async def test_greynoise_parser_missing_ip():
    parser = GreyNoiseParser()
    event = {"raw": {"greynoise": {"classification": "benign"}}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_greynoise_parser_missing_greynoise_data():
    parser = GreyNoiseParser()
    event = {"raw": {"ip": "8.8.8.8"}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_greynoise_parser_empty_raw():
    parser = GreyNoiseParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_greynoise_parser_class_attributes():
    assert GreyNoiseParser.source_name == "greynoise"
    assert GreyNoiseParser.current_version == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_parsers/test_greynoise_parser.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'easm.parse.greynoise_parser'`

- [ ] **Step 3: Write the GreyNoise parser**

```python
# src/easm/parse/greynoise_parser.py
from easm.parse.base import BaseParser, ParseResult, EntityCandidate
from easm.entity_store import normalize_entity_value


class GreyNoiseParser(BaseParser):
    source_name = "greynoise"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        ip = raw.get("ip", "").strip()
        greynoise = raw.get("greynoise")
        if not ip or not greynoise:
            return ParseResult(
                entities=[], relationships=[], unparseable=True,
                parse_error="missing ip or greynoise data",
            )

        normalized_ip = normalize_entity_value("ip", ip)
        return ParseResult(
            entities=[
                EntityCandidate(
                    entity_type="ip",
                    value=normalized_ip,
                    attributes={
                        "source": "greynoise",
                        "threat_intel": {
                            "greynoise": {
                                "classification": greynoise.get("classification"),
                                "noise": greynoise.get("noise"),
                                "riot": greynoise.get("riot"),
                                "name": greynoise.get("name", ""),
                                "link": greynoise.get("link", ""),
                            }
                        },
                    },
                ),
            ],
            relationships=[],
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_parsers/test_greynoise_parser.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Write the GreyNoise pivot handler**

```python
# src/easm/pivot/handlers/greynoise_enrich.py
from __future__ import annotations

import logging

import httpx

from easm.pivot.handlers.base import PivotHandler

logger = logging.getLogger(__name__)

GREYNOISE_COMMUNITY_URL = "https://api.greynoise.io/v3/community/{ip}"


class GreyNoiseHandler(PivotHandler):
    pivot_type = "greynoise_enrich"
    source_name = "greynoise"

    def __init__(self, api_key: str = "", http_client: httpx.AsyncClient | None = None):
        self._api_key = api_key
        self._http_client = http_client

    async def execute(self, job: dict, pool) -> list[dict]:
        ip = job["entity_value"]
        url = GREYNOISE_COMMUNITY_URL.format(ip=ip)
        headers = {}
        if self._api_key:
            headers["key"] = self._api_key
        http = self._http_client or httpx.AsyncClient(timeout=15.0)
        try:
            resp = await http.get(url, headers=headers)
            if resp.status_code == 404:
                return [{"ip": ip, "message": "no greynoise data"}]
            resp.raise_for_status()
            data = resp.json()
            return [{
                "ip": ip,
                "greynoise": {
                    "classification": data.get("classification", ""),
                    "noise": data.get("noise", False),
                    "riot": data.get("riot", False),
                    "name": data.get("name", ""),
                    "link": data.get("link", ""),
                },
            }]
        except Exception as e:
            logger.debug("GreyNoise lookup failed for %s: %s", ip, e)
            return [{"ip": ip, "message": f"greynoise lookup failed: {e}"}]
        finally:
            if not self._http_client:
                await http.aclose()
```

- [ ] **Step 6: Run existing tests to verify no regressions**

Run: `uv run pytest tests/ -v --timeout=30`
Expected: All existing tests still pass

- [ ] **Step 7: Commit**

```bash
git add src/easm/pivot/handlers/greynoise_enrich.py \
        src/easm/parse/greynoise_parser.py \
        tests/test_parsers/test_greynoise_parser.py
git commit -m "feat: add GreyNoise IP reputation enrichment handler + parser"
```

---

## Task 2: AbuseIPDB IP Abuse Report Enrichment

**Files:**
- Create: `src/easm/pivot/handlers/abuseipdb_enrich.py`
- Create: `src/easm/parse/abuseipdb_parser.py`
- Create: `tests/test_parsers/test_abuseipdb_parser.py`
- Modify: `src/easm/pivot/handlers/__init__.py`
- Modify: `src/easm/parse/__init__.py`
- Modify: `src/easm/config.py`

- [ ] **Step 1: Write failing tests for the AbuseIPDB parser**

```python
# tests/test_parsers/test_abuseipdb_parser.py
import pytest
from easm.parse.abuseipdb_parser import AbuseIpDbParser


@pytest.mark.asyncio
async def test_abuseipdb_parser_extracts_attributes():
    parser = AbuseIpDbParser()
    event = {
        "raw": {
            "ip": "8.8.8.8",
            "abuseipdb": {
                "abuseConfidenceScore": 0,
                "totalReports": 0,
                "lastReportedAt": None,
                "usageType": "DNS",
                "hostnames": ["dns.google"],
                "domain": "google.com",
                "countryCode": "US",
                "isp": "Google LLC",
            },
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    assert len(result.entities) == 1
    assert result.entities[0].entity_type == "ip"
    assert result.entities[0].value == "8.8.8.8"
    attrs = result.entities[0].attributes
    assert attrs["source"] == "abuseipdb"
    ti = attrs["threat_intel"]["abuseipdb"]
    assert ti["abuseConfidenceScore"] == 0
    assert ti["totalReports"] == 0
    assert ti["isp"] == "Google LLC"


@pytest.mark.asyncio
async def test_abuseipdb_parser_missing_ip():
    parser = AbuseIpDbParser()
    event = {"raw": {"abuseipdb": {"abuseConfidenceScore": 100}}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_abuseipdb_parser_missing_abuseipdb_data():
    parser = AbuseIpDbParser()
    event = {"raw": {"ip": "8.8.8.8"}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_abuseipdb_parser_empty_raw():
    parser = AbuseIpDbParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_abuseipdb_parser_class_attributes():
    assert AbuseIpDbParser.source_name == "abuseipdb"
    assert AbuseIpDbParser.current_version == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_parsers/test_abuseipdb_parser.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'easm.parse.abuseipdb_parser'`

- [ ] **Step 3: Write the AbuseIPDB parser**

```python
# src/easm/parse/abuseipdb_parser.py
from easm.parse.base import BaseParser, ParseResult, EntityCandidate
from easm.entity_store import normalize_entity_value


class AbuseIpDbParser(BaseParser):
    source_name = "abuseipdb"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        ip = raw.get("ip", "").strip()
        abuseipdb = raw.get("abuseipdb")
        if not ip or not abuseipdb:
            return ParseResult(
                entities=[], relationships=[], unparseable=True,
                parse_error="missing ip or abuseipdb data",
            )

        normalized_ip = normalize_entity_value("ip", ip)
        return ParseResult(
            entities=[
                EntityCandidate(
                    entity_type="ip",
                    value=normalized_ip,
                    attributes={
                        "source": "abuseipdb",
                        "threat_intel": {
                            "abuseipdb": {
                                "abuseConfidenceScore": abuseipdb.get("abuseConfidenceScore"),
                                "totalReports": abuseipdb.get("totalReports"),
                                "lastReportedAt": abuseipdb.get("lastReportedAt"),
                                "usageType": abuseipdb.get("usageType", ""),
                                "hostnames": abuseipdb.get("hostnames", []),
                                "domain": abuseipdb.get("domain", ""),
                                "countryCode": abuseipdb.get("countryCode", ""),
                                "isp": abuseipdb.get("isp", ""),
                            }
                        },
                    },
                ),
            ],
            relationships=[],
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_parsers/test_abuseipdb_parser.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Write the AbuseIPDB pivot handler**

```python
# src/easm/pivot/handlers/abuseipdb_enrich.py
from __future__ import annotations

import logging

import httpx

from easm.pivot.handlers.base import PivotHandler

logger = logging.getLogger(__name__)

ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIpDbHandler(PivotHandler):
    pivot_type = "abuseipdb_enrich"
    source_name = "abuseipdb"

    def __init__(self, api_key: str = "", http_client: httpx.AsyncClient | None = None):
        self._api_key = api_key
        self._http_client = http_client

    async def execute(self, job: dict, pool) -> list[dict]:
        ip = job["entity_value"]
        if not self._api_key:
            return [{"ip": ip, "message": "no abuseipdb api key configured"}]

        http = self._http_client or httpx.AsyncClient(timeout=15.0)
        try:
            resp = await http.get(
                ABUSEIPDB_API_URL,
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                headers={"Key": self._api_key, "Accept": "application/json"},
            )
            if resp.status_code == 404:
                return [{"ip": ip, "message": "no abuseipdb data"}]
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return [{
                "ip": ip,
                "abuseipdb": {
                    "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                    "totalReports": data.get("totalReports"),
                    "lastReportedAt": data.get("lastReportedAt"),
                    "usageType": data.get("usageType", ""),
                    "hostnames": data.get("hostnames", []),
                    "domain": data.get("domain", ""),
                    "countryCode": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                },
            }]
        except Exception as e:
            logger.debug("AbuseIPDB lookup failed for %s: %s", ip, e)
            return [{"ip": ip, "message": f"abuseipdb lookup failed: {e}"}]
        finally:
            if not self._http_client:
                await http.aclose()
```

- [ ] **Step 6: Run existing tests to verify no regressions**

Run: `uv run pytest tests/ -v --timeout=30`
Expected: All existing tests still pass

- [ ] **Step 7: Commit**

```bash
git add src/easm/pivot/handlers/abuseipdb_enrich.py \
        src/easm/parse/abuseipdb_parser.py \
        tests/test_parsers/test_abuseipdb_parser.py
git commit -m "feat: add AbuseIPDB IP abuse report enrichment handler + parser"
```

---

## Task 3: URLScan.io Domain Scan Enrichment

**Files:**
- Create: `src/easm/pivot/handlers/urlscan_enrich.py`
- Create: `src/easm/parse/urlscan_parser.py`
- Create: `tests/test_parsers/test_urlscan_parser.py`
- Modify: `src/easm/pivot/handlers/__init__.py`
- Modify: `src/easm/parse/__init__.py`
- Modify: `src/easm/config.py`

- [ ] **Step 1: Write failing tests for the URLScan.io parser**

```python
# tests/test_parsers/test_urlscan_parser.py
import pytest
from easm.parse.urlscan_parser import UrlScanParser


@pytest.mark.asyncio
async def test_urlscan_parser_extracts_attributes():
    parser = UrlScanParser()
    event = {
        "raw": {
            "domain": "example.com",
            "urlscan": {
                "total_results": 5,
                "malicious_count": 1,
                "results": [
                    {
                        "page_url": "https://example.com/",
                        "ip": "93.184.216.34",
                        "domain": "example.com",
                        "is_malicious": False,
                        "screenshot_url": "https://urlscan.io/screenshots/abc123.png",
                    },
                    {
                        "page_url": "http://malicious.example.com/",
                        "ip": "203.0.113.5",
                        "domain": "malicious.example.com",
                        "is_malicious": True,
                        "screenshot_url": None,
                    },
                ],
                "malicious_urls": ["http://malicious.example.com/"],
            },
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    assert len(result.entities) == 1
    assert result.entities[0].entity_type == "domain"
    assert result.entities[0].value == "example.com"
    attrs = result.entities[0].attributes
    assert attrs["source"] == "urlscan"
    ti = attrs["threat_intel"]["urlscan"]
    assert ti["total_results"] == 5
    assert ti["malicious_count"] == 1
    assert len(ti["malicious_urls"]) == 1


@pytest.mark.asyncio
async def test_urlscan_parser_missing_domain():
    parser = UrlScanParser()
    event = {"raw": {"urlscan": {"total_results": 0}}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_urlscan_parser_missing_urlscan_data():
    parser = UrlScanParser()
    event = {"raw": {"domain": "example.com"}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_urlscan_parser_empty_raw():
    parser = UrlScanParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_urlscan_parser_class_attributes():
    assert UrlScanParser.source_name == "urlscan"
    assert UrlScanParser.current_version == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_parsers/test_urlscan_parser.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'easm.parse.urlscan_parser'`

- [ ] **Step 3: Write the URLScan.io parser**

```python
# src/easm/parse/urlscan_parser.py
from easm.parse.base import BaseParser, ParseResult, EntityCandidate
from easm.entity_store import normalize_entity_value


class UrlScanParser(BaseParser):
    source_name = "urlscan"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        domain = raw.get("domain", "").strip()
        urlscan = raw.get("urlscan")
        if not domain or not urlscan:
            return ParseResult(
                entities=[], relationships=[], unparseable=True,
                parse_error="missing domain or urlscan data",
            )

        normalized_domain = normalize_entity_value("domain", domain)
        results_raw = urlscan.get("results", [])
        malicious_count = sum(1 for r in results_raw if r.get("is_malicious"))
        malicious_urls = [
            r.get("page_url", "") for r in results_raw if r.get("is_malicious")
        ]

        return ParseResult(
            entities=[
                EntityCandidate(
                    entity_type="domain",
                    value=normalized_domain,
                    attributes={
                        "source": "urlscan",
                        "threat_intel": {
                            "urlscan": {
                                "total_results": urlscan.get("total_results", 0),
                                "malicious_count": malicious_count,
                                "results": [
                                    {
                                        "page_url": r.get("page_url", ""),
                                        "ip": r.get("ip", ""),
                                        "domain": r.get("domain", ""),
                                        "is_malicious": r.get("is_malicious", False),
                                        "screenshot_url": r.get("screenshot_url"),
                                    }
                                    for r in results_raw
                                ],
                                "malicious_urls": malicious_urls,
                            }
                        },
                    },
                ),
            ],
            relationships=[],
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_parsers/test_urlscan_parser.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Write the URLScan.io pivot handler**

```python
# src/easm/pivot/handlers/urlscan_enrich.py
from __future__ import annotations

import logging

import httpx

from easm.pivot.handlers.base import PivotHandler

logger = logging.getLogger(__name__)

URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"


class UrlScanHandler(PivotHandler):
    pivot_type = "urlscan_enrich"
    source_name = "urlscan"

    def __init__(self, http_client: httpx.AsyncClient | None = None):
        self._http_client = http_client

    async def execute(self, job: dict, pool) -> list[dict]:
        domain = job["entity_value"]
        http = self._http_client or httpx.AsyncClient(timeout=30.0)
        try:
            resp = await http.get(
                URLSCAN_SEARCH_URL,
                params={"q": f"domain:{domain}", "size": 100},
            )
            if resp.status_code == 404:
                return [{"domain": domain, "message": "no urlscan data"}]
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", [])
            return [{
                "domain": domain,
                "urlscan": {
                    "total_results": data.get("total", 0),
                    "results": [
                        {
                            "page_url": r.get("page", {}).get("url", ""),
                            "ip": r.get("page", {}).get("ip", ""),
                            "domain": r.get("page", {}).get("domain", ""),
                            "is_malicious": r.get("isMalicious", False),
                            "screenshot_url": r.get("screenshot", ""),
                        }
                        for r in results
                    ],
                },
            }]
        except Exception as e:
            logger.debug("URLScan lookup failed for %s: %s", domain, e)
            return [{"domain": domain, "message": f"urlscan lookup failed: {e}"}]
        finally:
            if not self._http_client:
                await http.aclose()
```

- [ ] **Step 6: Run existing tests to verify no regressions**

Run: `uv run pytest tests/ -v --timeout=30`
Expected: All existing tests still pass

- [ ] **Step 7: Commit**

```bash
git add src/easm/pivot/handlers/urlscan_enrich.py \
        src/easm/parse/urlscan_parser.py \
        tests/test_parsers/test_urlscan_parser.py
git commit -m "feat: add URLScan.io domain scan enrichment handler + parser"
```

---

## Task 4: Cloud Bucket Runner — S3/GCS/Azure Blob Enumeration

**Files:**
- Create: `src/easm/runners/cloud_bucket_runner.py`
- Create: `src/easm/parse/cloud_bucket_parser.py`
- Create: `tests/test_parsers/test_cloud_bucket_parser.py`
- Create: `tests/test_runners/test_cloud_bucket_runner.py`
- Modify: `src/easm/runners/__init__.py`
- Modify: `src/easm/parse/__init__.py`
- Modify: `src/easm/config.py`

- [ ] **Step 1: Write failing tests for the cloud bucket parser**

```python
# tests/test_parsers/test_cloud_bucket_parser.py
import pytest
from easm.parse.cloud_bucket_parser import CloudBucketParser


@pytest.mark.asyncio
async def test_cloud_bucket_parser_extracts_s3_entity():
    parser = CloudBucketParser()
    event = {
        "raw": {
            "bucket_url": "myorg-backup.s3.amazonaws.com",
            "provider": "aws_s3",
            "bucket_name": "myorg-backup",
            "public_access": True,
            "public_list": False,
            "status_code": 200,
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    assert len(result.entities) == 1
    assert result.entities[0].entity_type == "domain"
    assert result.entities[0].value == "myorg-backup.s3.amazonaws.com"
    attrs = result.entities[0].attributes
    assert attrs["source"] == "cloud_enum"
    assert attrs["cloud_provider"] == "aws_s3"
    assert attrs["public_access"] is True
    assert attrs["public_list"] is False
    assert attrs["bucket_name"] == "myorg-backup"


@pytest.mark.asyncio
async def test_cloud_bucket_parser_extracts_gcs_entity():
    parser = CloudBucketParser()
    event = {
        "raw": {
            "bucket_url": "storage.googleapis.com/myorg-backup",
            "provider": "gcs",
            "bucket_name": "myorg-backup",
            "public_access": True,
            "public_list": True,
            "status_code": 200,
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    assert result.entities[0].value == "storage.googleapis.com"
    assert result.entities[0].attributes["cloud_provider"] == "gcs"
    assert result.entities[0].attributes["bucket_name"] == "myorg-backup"


@pytest.mark.asyncio
async def test_cloud_bucket_parser_handles_no_access():
    parser = CloudBucketParser()
    event = {
        "raw": {
            "bucket_url": "myorg-restricted.s3.amazonaws.com",
            "provider": "aws_s3",
            "bucket_name": "myorg-restricted",
            "public_access": False,
            "public_list": False,
            "status_code": 403,
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    assert result.entities[0].attributes["public_access"] is False


@pytest.mark.asyncio
async def test_cloud_bucket_parser_missing_bucket_url():
    parser = CloudBucketParser()
    event = {"raw": {"provider": "aws_s3"}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_cloud_bucket_parser_missing_provider():
    parser = CloudBucketParser()
    event = {"raw": {"bucket_url": "test.s3.amazonaws.com"}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_cloud_bucket_parser_empty_raw():
    parser = CloudBucketParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_cloud_bucket_parser_class_attributes():
    assert CloudBucketParser.source_name == "cloud_enum"
    assert CloudBucketParser.current_version == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_parsers/test_cloud_bucket_parser.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'easm.parse.cloud_bucket_parser'`

- [ ] **Step 3: Write the cloud bucket parser**

```python
# src/easm/parse/cloud_bucket_parser.py
from easm.parse.base import BaseParser, ParseResult, EntityCandidate
from easm.entity_store import normalize_entity_value


class CloudBucketParser(BaseParser):
    source_name = "cloud_enum"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        bucket_url = raw.get("bucket_url", "").strip()
        provider = raw.get("provider", "").strip()
        if not bucket_url or not provider:
            return ParseResult(
                entities=[], relationships=[], unparseable=True,
                parse_error="missing bucket_url or provider",
            )

        normalized_url = normalize_entity_value("domain", bucket_url)
        return ParseResult(
            entities=[
                EntityCandidate(
                    entity_type="domain",
                    value=normalized_url,
                    attributes={
                        "source": "cloud_enum",
                        "cloud_provider": provider,
                        "bucket_name": raw.get("bucket_name", ""),
                        "public_access": raw.get("public_access", False),
                        "public_list": raw.get("public_list", False),
                        "status_code": raw.get("status_code"),
                    },
                ),
            ],
            relationships=[],
        )
```

- [ ] **Step 4: Run parser tests to verify they pass**

Run: `uv run pytest tests/test_parsers/test_cloud_bucket_parser.py -v`
Expected: All 7 tests PASS

- [ ] **Step 5: Write failing tests for the cloud bucket runner**

```python
# tests/test_runners/test_cloud_bucket_runner.py
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from easm.runners.cloud_bucket_runner import CloudBucketRunner


@pytest.mark.asyncio
async def test_cloud_bucket_runner_class_attributes():
    assert CloudBucketRunner.source_name == "cloud_enum"
    assert CloudBucketRunner.supports_schedule is True
    assert CloudBucketRunner.supports_manual_trigger is True
    assert CloudBucketRunner.is_continuous is False
    assert CloudBucketRunner.is_api_runner is True


def test_bucket_name_prefixes_from_domain():
    from easm.runners.cloud_bucket_runner import _derive_bucket_prefixes
    prefixes = _derive_bucket_prefixes("example.com")
    assert "example" in prefixes
    assert "example-com" in prefixes
    assert "example.com" in prefixes


def test_bucket_name_prefixes_from_long_domain():
    from easm.runners.cloud_bucket_runner import _derive_bucket_prefixes
    prefixes = _derive_bucket_prefixes("sub.domain.co.uk")
    assert "sub" in prefixes
    assert "sub-domain" in prefixes


def test_provider_checks_s3():
    from easm.runners.cloud_bucket_runner import _provider_check_urls
    urls = _provider_check_urls("mybucket", "aws_s3")
    assert len(urls) == 1
    assert urls[0][0] == "https://mybucket.s3.amazonaws.com"
    assert urls[0][1] == "aws_s3"


def test_provider_checks_gcs():
    from easm.runners.cloud_bucket_runner import _provider_check_urls
    urls = _provider_check_urls("mybucket", "gcs")
    assert len(urls) == 1
    assert urls[0][0] == "https://storage.googleapis.com/mybucket"
    assert urls[0][1] == "gcs"


def test_provider_checks_azure():
    from easm.runners.cloud_bucket_runner import _provider_check_urls
    urls = _provider_check_urls("mybucket", "azure_blob")
    assert len(urls) == 1
    assert urls[0][0] == "https://mybucket.blob.core.windows.net"
    assert urls[0][1] == "azure_blob"


def test_all_providers_are_checked():
    from easm.runners.cloud_bucket_runner import CLOUD_PROVIDERS
    assert "aws_s3" in CLOUD_PROVIDERS
    assert "gcs" in CLOUD_PROVIDERS
    assert "azure_blob" in CLOUD_PROVIDERS


@pytest.mark.asyncio
async def test_cloud_bucket_runner_run_once_returns_counts():
    mock_store = MagicMock()
    mock_store.pool = AsyncMock()
    mock_store.pool.execute = AsyncMock(return_value="INSERT 0 1")

    mock_target = MagicMock()
    mock_target.id = "test-target"
    mock_target.org_id = "default"
    mock_target.match_rules.domains = ["example.com"]

    mock_http = AsyncMock(spec=httpx.AsyncClient)
    mock_head_response = MagicMock(spec=httpx.Response)
    mock_head_response.status_code = 200
    mock_head_response.headers = {}
    mock_head_response.request = MagicMock()
    mock_head_response.request.url = httpx.URL("https://example-backup.s3.amazonaws.com")
    mock_http.head = AsyncMock(return_value=mock_head_response)

    runner = CloudBucketRunner(store=mock_store, http_client=mock_http)
    inserted, deduped, errors = await runner.run_once(
        mock_target, "manual", uuid.uuid4()
    )
    assert isinstance(inserted, int)
    assert isinstance(deduped, int)
    assert isinstance(errors, int)
```

- [ ] **Step 6: Run runner tests to verify they fail**

Run: `uv run pytest tests/test_runners/test_cloud_bucket_runner.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'easm.runners.cloud_bucket_runner'`

- [ ] **Step 7: Write the cloud bucket runner**

```python
# src/easm/runners/cloud_bucket_runner.py
from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid

import httpx

from easm.config import TargetConfig
from easm.runners.base import ApiRunner

logger = logging.getLogger(__name__)

CLOUD_PROVIDERS = ["aws_s3", "gcs", "azure_blob"]

COMMON_BUCKET_PREFIXES = [
    "", "backup", "backups", "uploads", "assets", "logs", "data",
    "files", "public", "static", "media", "dev", "staging", "prod",
    "test", "bucket", "storage", "archive", "cdn", "downloads",
    "resources", "config", "configs", "db", "database", "sql",
]

BUCKET_CHECK_TIMEOUT = 10.0
CONCURRENCY_LIMIT = 20


def _derive_bucket_prefixes(domain: str) -> list[str]:
    prefixes: list[str] = []
    domain = domain.lower().strip()
    prefixes.append(domain)

    parts = domain.split(".")
    if len(parts) >= 2:
        prefixes.append("-".join(parts[:-1]))
        prefixes.append(parts[0])

    tld = parts[-1] if parts else ""
    if len(parts) >= 3:
        prefixes.append("-".join(parts[:-2]))

    for common in COMMON_BUCKET_PREFIXES:
        if common:
            prefixes.append(f"{parts[0]}-{common}")
            prefixes.append(f"{common}-{parts[0]}")

    return list(dict.fromkeys(p for p in prefixes if p and len(p) <= 63))


def _provider_check_urls(prefix: str, provider: str) -> list[tuple[str, str]]:
    if provider == "aws_s3":
        return [(f"https://{prefix}.s3.amazonaws.com", "aws_s3")]
    elif provider == "gcs":
        return [(f"https://storage.googleapis.com/{prefix}", "gcs")]
    elif provider == "azure_blob":
        return [(f"https://{prefix}.blob.core.windows.net", "azure_blob")]
    return []


class CloudBucketRunner(ApiRunner):
    source_name = "cloud_enum"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False
    is_api_runner = True

    def __init__(
        self,
        store,
        http_client: httpx.AsyncClient | None = None,
        semaphore: asyncio.Semaphore | None = None,
    ):
        super().__init__(store, http_client=http_client)
        self._semaphore = semaphore or asyncio.Semaphore(CONCURRENCY_LIMIT)

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        from easm.store import _compute_event_hash

        http = self._http_client or httpx.AsyncClient(timeout=BUCKET_CHECK_TIMEOUT)
        inserted = deduped = errors = 0

        check_urls: list[tuple[str, str, str]] = []
        for domain in target.match_rules.domains:
            prefixes = _derive_bucket_prefixes(domain)
            for prefix in prefixes:
                for provider in CLOUD_PROVIDERS:
                    for url, prov in _provider_check_urls(prefix, provider):
                        check_urls.append((url, prov, prefix))

        logger.info(
            "cloud_enum: checking %d bucket URLs across %d providers for %s",
            len(check_urls), len(CLOUD_PROVIDERS), target.id,
        )

        sem = self._semaphore

        async def _check(url: str, provider: str, prefix: str) -> dict | None:
            async with sem:
                try:
                    resp = await http.head(url, follow_redirects=True)
                    status = resp.status_code
                    public_access = status in (200, 204, 403)
                    public_list = status in (200, 204)

                    if status in (200, 204, 403):
                        return {
                            "bucket_url": url,
                            "provider": provider,
                            "bucket_name": prefix,
                            "public_access": public_access,
                            "public_list": public_list,
                            "status_code": status,
                        }
                    return None
                except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError) as e:
                    logger.debug("cloud_enum: check failed for %s: %s", url, e)
                    return None

        results = await asyncio.gather(
            *[_check(url, prov, pfx) for url, prov, pfx in check_urls],
            return_exceptions=False,
        )

        for result in results:
            if result is None:
                continue
            try:
                event_hash = _compute_event_hash(
                    target.org_id, target.id, self.source_name, result
                )
                db_result = await self.store.pool.execute(
                    """INSERT INTO raw_events (org_id, target_id, source, raw, event_hash, run_id)
                       VALUES ($1, $2, $3, $4::jsonb, $5, $6)
                       ON CONFLICT (event_hash) DO NOTHING""",
                    target.org_id, target.id, self.source_name,
                    json.dumps(result), event_hash, run_id,
                )
                if db_result == "INSERT 0 0":
                    deduped += 1
                else:
                    inserted += 1
            except Exception as e:
                errors += 1
                logger.warning("cloud_enum: insert error: %s", e)

        if not self._http_client:
            await http.aclose()

        logger.info(
            "cloud_enum: inserted=%d deduped=%d errors=%d",
            inserted, deduped, errors,
        )
        return inserted, deduped, errors
```

- [ ] **Step 8: Run runner tests to verify they pass**

Run: `uv run pytest tests/test_runners/test_cloud_bucket_runner.py -v`
Expected: All tests PASS

- [ ] **Step 9: Run all parser + runner tests**

Run: `uv run pytest tests/test_parsers/test_cloud_bucket_parser.py tests/test_runners/test_cloud_bucket_runner.py -v`
Expected: All tests PASS

- [ ] **Step 10: Run existing tests to verify no regressions**

Run: `uv run pytest tests/ -v --timeout=30`
Expected: All existing tests still pass

- [ ] **Step 11: Commit**

```bash
git add src/easm/runners/cloud_bucket_runner.py \
        src/easm/parse/cloud_bucket_parser.py \
        tests/test_parsers/test_cloud_bucket_parser.py \
        tests/test_runners/test_cloud_bucket_runner.py
git commit -m "feat: add cloud bucket enumeration runner (S3, GCS, Azure Blob)"
mkdir -p tests/test_runners && touch tests/test_runners/__init__.py && git add tests/test_runners/__init__.py
```

---

## Task 5: Registration — Handlers, Parsers, Runner, Config

**Files:**
- Modify: `src/easm/pivot/handlers/__init__.py`
- Modify: `src/easm/parse/__init__.py`
- Modify: `src/easm/runners/__init__.py`
- Modify: `src/easm/config.py`
- Modify: `config.yaml.example`
- Modify: `tests/test_pivot_handlers.py`
- Modify: `tests/test_runners.py`
- Modify: `tests/test_parsers/__init__.py`
- Validate: `tests/test_parsers/test_greynoise_parser.py`
- Validate: `tests/test_parsers/test_abuseipdb_parser.py`
- Validate: `tests/test_parsers/test_urlscan_parser.py`

- [ ] **Step 1: Register GreyNoise handler and parser**

Add to `src/easm/pivot/handlers/__init__.py`:
```python
from easm.pivot.handlers.greynoise_enrich import GreyNoiseHandler
from easm.pivot.handlers.abuseipdb_enrich import AbuseIpDbHandler
from easm.pivot.handlers.urlscan_enrich import UrlScanHandler
```

Add to `PIVOT_HANDLER_REGISTRY`:
```python
    "greynoise_enrich": GreyNoiseHandler,
    "abuseipdb_enrich": AbuseIpDbHandler,
    "urlscan_enrich": UrlScanHandler,
```

Update the registry count assertion in `tests/test_pivot_handlers.py`:
```python
    assert len(PIVOT_HANDLER_REGISTRY) == 14
```

Add to `src/easm/parse/__init__.py`:
```python
from easm.parse.greynoise_parser import GreyNoiseParser
from easm.parse.abuseipdb_parser import AbuseIpDbParser
from easm.parse.urlscan_parser import UrlScanParser
from easm.parse.cloud_bucket_parser import CloudBucketParser
```

Add to `PARSER_REGISTRY`:
```python
    "greynoise": GreyNoiseParser,
    "abuseipdb": AbuseIpDbParser,
    "urlscan": UrlScanParser,
    "cloud_enum": CloudBucketParser,
```

- [ ] **Step 2: Register cloud bucket runner**

Add to `src/easm/runners/__init__.py`:
```python
from easm.runners.cloud_bucket_runner import CloudBucketRunner
```

Add to `RUNNER_REGISTRY`:
```python
    "cloud_enum": CloudBucketRunner,
```

Add to `__all__`:
```python
    "CloudBucketRunner",
```

Update `src/easm/runners/__init__.py` to also export the new runner:
```python
__all__ = [
    "ApiRunner", "BaseRunner",
    "SubfinderRunner", "AsnmapRunner", "CertStreamRunner",
    "CrtShRunner", "DnstwistRunner", "CloudBucketRunner",
]
```

- [ ] **Step 3: Update config validation**

Add to `VALID_PIVOT_TYPES` in `src/easm/config.py`:
```python
    "greynoise_enrich",
    "abuseipdb_enrich",
    "urlscan_enrich",
```

Add to `VALID_RUNNER_NAMES` and `SCHEDULABLE_RUNNERS` in `src/easm/config.py`:
```python
VALID_RUNNER_NAMES = {"certstream", "subfinder", "asnmap", "crtsh", "dnstwist", "cloud_enum"}
SCHEDULABLE_RUNNERS = {"subfinder", "asnmap", "crtsh", "dnstwist", "cloud_enum"}
```

- [ ] **Step 4: Update config.yaml.example**

```yaml
      # Threat intel enrichment pivots
      - from: ip
        to: ip
        via: greynoise_enrich
        cooldown_hours: 168
      - from: ip
        to: ip
        via: abuseipdb_enrich
        cooldown_hours: 168
      - from: domain
        to: domain
        via: urlscan_enrich
        cooldown_hours: 168

# Add under runner configs (after dnstwist):
      cloud_enum:
        enabled: true
        schedule: "0 8 * * 1"
        args:
          timeout_seconds: 600
          concurrency: 20
```

- [ ] **Step 5: Update runner registry test**

Update `tests/test_runners.py` to include cloud_enum:

```python
def test_runner_registry_has_all_runners():
    assert set(RUNNER_REGISTRY.keys()) == {
        "subfinder", "asnmap", "certstream", "crtsh", "dnstwist", "cloud_enum",
    }


def test_cloud_bucket_runner_attributes():
    assert CloudBucketRunner.source_name == "cloud_enum"
    assert CloudBucketRunner.supports_schedule is True
    assert CloudBucketRunner.supports_manual_trigger is True
    assert CloudBucketRunner.is_continuous is False
    assert CloudBucketRunner.is_api_runner is True
```

Add import:
```python
from easm.runners.cloud_bucket_runner import CloudBucketRunner
```

- [ ] **Step 6: Run all parser tests together**

Run: `uv run pytest tests/test_parsers/ -v`
Expected: All parser tests PASS (including existing ones)

- [ ] **Step 7: Run the full test suite**

Run: `uv run pytest tests/ -v --timeout=30`
Expected: All tests pass, no regressions

- [ ] **Step 8: Run linter and type checker**

Run: `uv run ruff check src/`
Expected: No lint errors

Run: `uv run mypy src/`
Expected: No type errors

- [ ] **Step 9: Final commit — all registrations + config**

```bash
git add src/easm/pivot/handlers/__init__.py \
        src/easm/parse/__init__.py \
        src/easm/runners/__init__.py \
        src/easm/config.py \
        config.yaml.example \
        tests/test_pivot_handlers.py \
        tests/test_runners.py
git commit -m "feat: register threat intel handlers, parsers, cloud bucket runner, and config"
```
