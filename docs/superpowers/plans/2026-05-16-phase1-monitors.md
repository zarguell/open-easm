# Phase 1 Monitors — Paste + GitHub + Breach Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three monitoring runners that use the shared KeywordEngine to detect credential leaks, code exposures, and breach appearances across paste sites, GitHub, and breach databases.

**Architecture:** All three are scheduled ApiRunners that poll external sources, match results against target keywords via KeywordEngine, and insert raw events. Parsers extract structured findings from the raw data. Each runner is independently configurable per-target.

**Tech Stack:** Python 3.14, httpx, Pydantic, pytest-asyncio, asyncpg, subprocess (gitleaks).

---

## File Structure

### New Files

| File | Responsibility |
|------|---------------|
| `src/easm/runners/paste_monitor_runner.py` | PasteMonitorRunner: polls Pastebin/paste.ee APIs for keyword matches |
| `src/easm/parse/paste_monitor_parser.py` | PasteMonitorParser: extracts paste findings (matched keyword, URL, metadata) |
| `tests/test_parsers/test_paste_monitor_parser.py` | Tests for paste monitor parser |
| `src/easm/runners/github_scan_runner.py` | GithubScanRunner: gitleaks subprocess + GitHub code search API |
| `src/easm/parse/github_scan_parser.py` | GithubScanParser: extracts file path, repo, matched content, severity |
| `tests/test_parsers/test_github_scan_parser.py` | Tests for GitHub scan parser |
| `src/easm/runners/breach_monitor_runner.py` | BreachMonitorRunner: HIBP + Dehashed API checks |
| `src/easm/parse/breach_monitor_parser.py` | BreachMonitorParser: extracts breach name, data classes, compromised accounts |
| `tests/test_parsers/test_breach_monitor_parser.py` | Tests for breach monitor parser |
| `src/easm/keyword_engine.py` | KeywordEngine: reusable text matching against target keywords/patterns |

### Modified Files

| File | Change |
|------|--------|
| `src/easm/runners/__init__.py` | Register 3 new runners |
| `src/easm/parse/__init__.py` | Register 3 new parsers |
| `src/easm/config.py` | Add 3 runners to VALID_RUNNER_NAMES/SCHEDULABLE_RUNNERS + config models |
| `config.yaml.example` | Add paste_monitor, github_scan, breach_monitor runner config examples |
| `tests/test_runners.py` | Add class attribute tests for 3 new runners |
| `tests/test_config.py` | Add validation tests for 3 new runner configs |

---

## Task 1: Shared KeywordEngine Module

**Files:**
- Create: `src/easm/keyword_engine.py`
- Create: `tests/test_keyword_engine.py`

The KeywordEngine takes a target's `MatchRules` and optional custom patterns, then scans text for matches. It supports exact keyword matching, regex pattern matching, and domain matching.

- [ ] **Step 1: Write failing tests for KeywordEngine**

```python
# tests/test_keyword_engine.py
import pytest
from easm.keyword_engine import KeywordEngine, KeywordMatch
from easm.config import TargetConfig, MatchRules


def _make_target(domains: list[str] | None = None, keywords: list[str] | None = None) -> TargetConfig:
    return TargetConfig(
        id="test-target",
        name="Test Target",
        type="organization",
        match_rules=MatchRules(
            domains=domains or [],
            keywords=keywords or [],
        ),
    )


def test_keyword_engine_exact_match():
    target = _make_target(keywords=["acme corp", "secret project"])
    engine = KeywordEngine(target)
    matches = engine.match("The acme corp API key is exposed")
    assert len(matches) == 1
    assert matches[0].keyword == "acme corp"
    assert matches[0].match_type == "exact"
    assert matches[0].context == "The acme corp API key is exposed"


def test_keyword_engine_multiple_exact_matches():
    target = _make_target(keywords=["acme corp", "secret project"])
    engine = KeywordEngine(target)
    matches = engine.match("acme corp and secret project are both here")
    assert len(matches) == 2
    keywords_found = {m.keyword for m in matches}
    assert keywords_found == {"acme corp", "secret project"}


def test_keyword_engine_domain_match():
    target = _make_target(domains=["example.com", "acme.org"])
    engine = KeywordEngine(target)
    matches = engine.match("Contact us at admin@example.com for support")
    assert len(matches) == 1
    assert matches[0].keyword == "example.com"
    assert matches[0].match_type == "domain"


def test_keyword_engine_no_match_returns_empty():
    target = _make_target(keywords=["nothing"])
    engine = KeywordEngine(target)
    matches = engine.match("completely unrelated text")
    assert matches == []


def test_keyword_engine_case_insensitive_by_default():
    target = _make_target(keywords=["Acme Corp"])
    engine = KeywordEngine(target)
    matches = engine.match("found ACME CORP credentials")
    assert len(matches) == 1


def test_keyword_engine_custom_patterns():
    target = _make_target(keywords=["acme"])
    custom = [
        {"pattern": r"sk-[a-zA-Z0-9]{20,}", "severity": "high", "label": "openai_key"},
        {"pattern": r"ghp_[a-zA-Z0-9]{36}", "severity": "high", "label": "github_token"},
    ]
    engine = KeywordEngine(target, custom_patterns=custom)
    matches = engine.match("sk-proj-AbCdEf1234567890AbCdEf12 and ghp_abc123def456ghi789jkl012mno345pqr678")
    assert len(matches) == 2
    assert all(m.match_type == "regex" for m in matches)
    assert all(m.severity == "high" for m in matches)


def test_keyword_engine_context_surrounding_text():
    target = _make_target(keywords=["secret"])
    engine = KeywordEngine(target)
    text = "the quick brown fox jumps over the secret door and runs away".ljust(200)
    match = engine.match(text)[0]
    assert "secret" in match.context
    assert len(match.context) <= 200


def test_keyword_engine_with_empty_target():
    target = _make_target()
    engine = KeywordEngine(target)
    matches = engine.match("anything at all")
    assert matches == []


@pytest.mark.asyncio
async def test_keyword_engine_severity_defaults_to_medium():
    target = _make_target(keywords=["test"])
    engine = KeywordEngine(target)
    matches = engine.match("this is a test pattern")
    assert matches[0].severity == "medium"
```

- [ ] **Step 2: Implement KeywordEngine**

```python
# src/easm/keyword_engine.py
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from easm.config import TargetConfig


@dataclass
class KeywordMatch:
    keyword: str
    match_type: str
    severity: str
    context: str


CONTEXT_WINDOW = 100


class KeywordEngine:
    def __init__(
        self, target: TargetConfig, custom_patterns: list[dict[str, Any]] | None = None
    ) -> None:
        self._keywords: list[str] = target.match_rules.keywords
        self._domains: list[str] = target.match_rules.domains
        self._patterns: list[tuple[re.Pattern[str], str, str]] = []
        for pat in (custom_patterns or []):
            compiled = re.compile(pat["pattern"], re.IGNORECASE)
            self._patterns.append((compiled, pat.get("severity", "high"), pat.get("label", "")))

    def match(self, text: str) -> list[KeywordMatch]:
        results: list[KeywordMatch] = []
        seen: set[tuple[str, str, int]] = set()

        text_lower = text.lower()

        for keyword in self._keywords:
            kw_lower = keyword.lower()
            idx = text_lower.find(kw_lower)
            if idx != -1:
                key = ("exact", kw_lower, idx)
                if key not in seen:
                    seen.add(key)
                    start = max(0, idx - CONTEXT_WINDOW)
                    end = min(len(text), idx + len(keyword) + CONTEXT_WINDOW)
                    context = text[start:end]
                    results.append(KeywordMatch(
                        keyword=keyword,
                        match_type="exact",
                        severity="medium",
                        context=context,
                    ))

        for domain in self._domains:
            d_lower = domain.lower()
            idx = text_lower.find(d_lower)
            if idx != -1:
                key = ("domain", d_lower, idx)
                if key not in seen:
                    seen.add(key)
                    start = max(0, idx - CONTEXT_WINDOW)
                    end = min(len(text), idx + len(domain) + CONTEXT_WINDOW)
                    context = text[start:end]
                    results.append(KeywordMatch(
                        keyword=domain,
                        match_type="domain",
                        severity="medium",
                        context=context,
                    ))

        for compiled, severity, label in self._patterns:
            for m in compiled.finditer(text):
                key = ("regex", m.group(), m.start())
                if key not in seen:
                    seen.add(key)
                    start = max(0, m.start() - CONTEXT_WINDOW)
                    end = min(len(text), m.end() + CONTEXT_WINDOW)
                    context = text[start:end]
                    results.append(KeywordMatch(
                        keyword=label or m.group(),
                        match_type="regex",
                        severity=severity,
                        context=context,
                    ))

        return results
```

- [ ] **Step 3: Run the tests to confirm they pass**

Run: `uv run pytest tests/test_keyword_engine.py -v`
Expected: All 9 tests pass

- [ ] **Step 4: Commit**

```bash
git add src/easm/keyword_engine.py tests/test_keyword_engine.py
git commit -m "feat: add KeywordEngine for text matching against target keywords/domains/patterns"
```

---

## Task 2: Paste Site Monitoring — Runner

**Files:**
- Create: `src/easm/runners/paste_monitor_runner.py`
- Create: `tests/test_runners/test_paste_monitor_runner.py`
- Modify: `tests/test_runners.py`

- [ ] **Step 1: Write failing tests for PasteMonitorRunner**

```python
# tests/test_runners/test_paste_monitor_runner.py
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from easm.config import TargetConfig
from easm.keyword_engine import KeywordMatch


@pytest.mark.asyncio
async def test_paste_monitor_class_attributes():
    from easm.runners.paste_monitor_runner import PasteMonitorRunner

    assert PasteMonitorRunner.source_name == "paste_monitor"
    assert PasteMonitorRunner.supports_schedule is True
    assert PasteMonitorRunner.supports_manual_trigger is True
    assert PasteMonitorRunner.is_continuous is False


@pytest.fixture
def target():
    return TargetConfig(
        id="test-target",
        name="Test",
        type="organization",
        match_rules={"domains": ["example.com"], "keywords": ["acme"]},
        runners={
            "paste_monitor": {
                "enabled": True,
                "schedule": "*/5 * * * *",
                "sources": ["pastebin"],
            }
        },
    )


@pytest.fixture
def mock_store():
    store = MagicMock()
    store.pool = AsyncMock()
    store.insert_raw_event = AsyncMock(return_value=True)
    store.create_run = AsyncMock(return_value=uuid.uuid7())
    store.mark_run_started = AsyncMock()
    store.mark_run_finished = AsyncMock()
    store.get_run = AsyncMock(return_value={"discovery_session_id": str(uuid.uuid7())})
    return store


@pytest.fixture
def mock_pastebin_response():
    return [
        {
            "id": "abc123",
            "title": "config dump",
            "user": "anon",
            "date": "2024-01-15 10:30:00",
            "content": "internal acme corp password: s3cret!",
            "size": 1024,
            "expire": "N",
            "scrape_url": "https://scrape.pastebin.com/api_scrape_item.php?i=abc123",
        }
    ]


@pytest.mark.asyncio
async def test_paste_monitor_run_once_polls_pastebin(target, mock_store, mock_pastebin_response):
    from easm.runners.paste_monitor_runner import PasteMonitorRunner

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json = AsyncMock(return_value=mock_pastebin_response)
    mock_client.get = AsyncMock(return_value=mock_resp)

    runner = PasteMonitorRunner(mock_store, http_client=mock_client)
    run_id = uuid.uuid7()
    inserted, deduped, errors = await runner.run_once(target, "scheduled", run_id)

    assert inserted >= 1
    assert errors == 0
    mock_client.get.assert_called_once()


@pytest.mark.asyncio
async def test_paste_monitor_run_once_handles_api_error(target, mock_store):
    from easm.runners.paste_monitor_runner import PasteMonitorRunner

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = AsyncMock()
    mock_resp.status_code = 429
    mock_client.get = AsyncMock(return_value=mock_resp)

    runner = PasteMonitorRunner(mock_store, http_client=mock_client)
    run_id = uuid.uuid7()
    inserted, deduped, errors = await runner.run_once(target, "scheduled", run_id)

    assert inserted == 0
    assert errors == 0  # rate limited, not an error — just no results


@pytest.mark.asyncio
async def test_paste_monitor_run_once_no_matches_stores_zero(target, mock_store):
    from easm.runners.paste_monitor_runner import PasteMonitorRunner

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json = AsyncMock(return_value=[
        {"id": "x1", "content": "no keywords here", "scrape_url": "http://x"}
    ])
    mock_client.get = AsyncMock(return_value=mock_resp)

    runner = PasteMonitorRunner(mock_store, http_client=mock_client)
    run_id = uuid.uuid7()
    inserted, deduped, errors = await runner.run_once(target, "scheduled", run_id)

    assert inserted == 0
    assert deduped == 0
    assert errors == 0


@pytest.mark.asyncio
async def test_paste_monitor_runner_closes_http_client(target, mock_store):
    from easm.runners.paste_monitor_runner import PasteMonitorRunner

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    runner = PasteMonitorRunner(mock_store, http_client=mock_client)
    await runner.close()
    mock_client.aclose.assert_awaited_once()
```

- [ ] **Step 2: Implement PasteMonitorRunner**

```python
# src/easm/runners/paste_monitor_runner.py
from __future__ import annotations

import json
import logging
import uuid

import httpx

from easm.config import TargetConfig
from easm.keyword_engine import KeywordEngine
from easm.runners.base import ApiRunner

logger = logging.getLogger(__name__)

PASTEBIN_SCRAPE_URL = "https://scrape.pastebin.com/api_scraping.php?limit=100"


class PasteMonitorRunner(ApiRunner):
    source_name = "paste_monitor"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        cfg = self.get_runner_config(target)
        sources: list[str] = cfg.get("sources", ["pastebin"])
        max_pastes: int = cfg.get("max_pastes_per_run", 100)
        http = self._http_client or httpx.AsyncClient(timeout=30.0)
        inserted = deduped = errors = 0

        kw_engine = KeywordEngine(target)

        try:
            if "pastebin" in sources:
                ins, ded, err = await self._poll_pastebin(http, kw_engine, target, run_id, max_pastes)
                inserted += ins
                deduped += ded
                errors += err
        finally:
            if not self._http_client:
                await http.aclose()

        return inserted, deduped, errors

    async def _poll_pastebin(
        self,
        http: httpx.AsyncClient,
        kw_engine: KeywordEngine,
        target: TargetConfig,
        run_id: uuid.UUID,
        max_pastes: int,
    ) -> tuple[int, int, int]:
        inserted = deduped = errors = 0

        try:
            resp = await http.get(PASTEBIN_SCRAPE_URL)
            if resp.status_code != 200:
                logger.warning("pastebin API returned %d", resp.status_code)
                return 0, 0, 0
            pastes = resp.json()
        except Exception as e:
            logger.warning("pastebin scrape failed: %s", e)
            return 0, 0, 1

        for paste in pastes[:max_pastes]:
            try:
                raw = {
                    "id": paste.get("id", ""),
                    "title": paste.get("title", ""),
                    "user": paste.get("user", ""),
                    "date": paste.get("date", ""),
                    "size": paste.get("size", 0),
                    "scrape_url": paste.get("scrape_url", ""),
                }

                scrape_url = paste.get("scrape_url", "")
                if scrape_url:
                    try:
                        content_resp = await http.get(scrape_url)
                        if content_resp.status_code == 200:
                            content = content_resp.text
                            raw["content_length"] = len(content)
                            matches = kw_engine.match(content)
                            raw["keyword_matches"] = [
                                {"keyword": m.keyword, "match_type": m.match_type, "severity": m.severity}
                                for m in matches
                            ]

                            if not matches:
                                continue
                        else:
                            raw["fetch_error"] = f"HTTP {content_resp.status_code}"
                    except Exception as e:
                        raw["fetch_error"] = str(e)

                result = await self.store.insert_raw_event(
                    target.org_id, target.id, self.source_name, raw, run_id,
                )
                if result:
                    inserted += 1
                else:
                    deduped += 1
            except Exception as e:
                errors += 1
                logger.warning("paste processing error: %s", e)

        return inserted, deduped, errors
```

- [ ] **Step 3: Add class attribute tests to test_runners.py**

Append to `tests/test_runners.py`:

```python
def test_paste_monitor_runner_class_attributes():
    from easm.runners.paste_monitor_runner import PasteMonitorRunner

    assert PasteMonitorRunner.source_name == "paste_monitor"
    assert PasteMonitorRunner.supports_schedule is True
    assert PasteMonitorRunner.supports_manual_trigger is True
    assert PasteMonitorRunner.is_continuous is False
    assert PasteMonitorRunner.is_api_runner is True
```

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/test_runners/test_paste_monitor_runner.py tests/test_runners.py -v`
Expected: All paste monitor tests pass; class attribute test passes

- [ ] **Step 5: Commit**

```bash
git add src/easm/runners/paste_monitor_runner.py tests/test_runners/test_paste_monitor_runner.py
git commit -m "feat: add PasteMonitorRunner for polling Pastebin pastes with keyword matching"
```

---

## Task 3: Paste Site Monitoring — Parser

**Files:**
- Create: `src/easm/parse/paste_monitor_parser.py`
- Create: `tests/test_parsers/test_paste_monitor_parser.py`

- [ ] **Step 1: Write failing tests for PasteMonitorParser**

```python
# tests/test_parsers/test_paste_monitor_parser.py
import pytest
from easm.parse.paste_monitor_parser import PasteMonitorParser


@pytest.mark.asyncio
async def test_paste_monitor_parser_extracts_finding():
    parser = PasteMonitorParser()
    event = {
        "raw": {
            "id": "abc123",
            "title": "config dump",
            "scrape_url": "https://scrape.pastebin.com/api_scrape_item.php?i=abc123",
            "keyword_matches": [
                {"keyword": "acme corp", "match_type": "exact", "severity": "medium"},
            ],
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable

    findings = [e for e in result.entities if e.entity_type == "finding"]
    assert len(findings) == 1
    assert findings[0].value.startswith("paste-abc123")
    assert findings[0].attributes["keyword"] == "acme corp"
    assert findings[0].attributes["source_url"] == "https://scrape.pastebin.com/api_scrape_item.php?i=abc123"
    assert findings[0].attributes["source_type"] == "pastebin"
    assert findings[0].attributes["severity"] == "medium"


@pytest.mark.asyncio
async def test_paste_monitor_parser_multiple_keywords():
    parser = PasteMonitorParser()
    event = {
        "raw": {
            "id": "def456",
            "title": "leak",
            "scrape_url": "https://scrape.pastebin.com/api_scrape_item.php?i=def456",
            "keyword_matches": [
                {"keyword": "acme corp", "match_type": "exact", "severity": "medium"},
                {"keyword": "secret project", "match_type": "exact", "severity": "high"},
            ],
        }
    }
    result = await parser.parse(event)
    findings = [e for e in result.entities if e.entity_type == "finding"]
    assert len(findings) == 2
    severities = {f.attributes["severity"] for f in findings}
    assert severities == {"medium", "high"}


@pytest.mark.asyncio
async def test_paste_monitor_parser_no_matches_returns_unparseable():
    parser = PasteMonitorParser()
    event = {"raw": {"id": "x1", "scrape_url": "http://x"}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_paste_monitor_parser_class_attributes():
    assert PasteMonitorParser.source_name == "paste_monitor"
    assert PasteMonitorParser.current_version == 1


@pytest.mark.asyncio
async def test_paste_monitor_parser_empty_raw():
    parser = PasteMonitorParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True
```

- [ ] **Step 2: Implement PasteMonitorParser**

```python
# src/easm/parse/paste_monitor_parser.py
from __future__ import annotations

from easm.parse.base import BaseParser, ParseResult, EntityCandidate, RelationshipCandidate


class PasteMonitorParser(BaseParser):
    source_name = "paste_monitor"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        paste_id = raw.get("id", "")
        matches = raw.get("keyword_matches", [])

        if not paste_id or not matches:
            return ParseResult(entities=[], relationships=[], unparseable=True, parse_error="no paste id or matches")

        entities: list[EntityCandidate] = []
        for m in matches:
            finding_id = f"paste-{paste_id}-{m.get('keyword', 'unknown')}"
            entities.append(EntityCandidate(
                entity_type="finding",
                value=finding_id,
                attributes={
                    "keyword": m.get("keyword", ""),
                    "match_type": m.get("match_type", ""),
                    "severity": m.get("severity", "medium"),
                    "source_type": "pastebin",
                    "source_url": raw.get("scrape_url", ""),
                    "paste_title": raw.get("title", ""),
                    "paste_date": raw.get("date", ""),
                    "paste_user": raw.get("user", ""),
                    "source": "paste_monitor",
                },
            ))

        return ParseResult(entities=entities, relationships=[])
```

- [ ] **Step 3: Run parser tests**

Run: `uv run pytest tests/test_parsers/test_paste_monitor_parser.py -v`
Expected: All 5 tests pass

- [ ] **Step 4: Commit**

```bash
git add src/easm/parse/paste_monitor_parser.py tests/test_parsers/test_paste_monitor_parser.py
git commit -m "feat: add PasteMonitorParser for extracting paste keyword findings"
```

---

## Task 4: GitHub/GitLab Code Search — Runner

**Files:**
- Create: `src/easm/runners/github_scan_runner.py`
- Create: `tests/test_runners/test_github_scan_runner.py`
- Modify: `tests/test_runners.py`

This runner has two operating modes: (1) gitleaks binary scanning repos found by searching for org domains, and (2) GitHub code search API for keyword/domain matches.

- [ ] **Step 1: Write failing tests for GithubScanRunner**

```python
# tests/test_runners/test_github_scan_runner.py
from __future__ import annotations

import uuid
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import httpx
import pytest

from easm.config import TargetConfig


@pytest.mark.asyncio
async def test_github_scan_class_attributes():
    from easm.runners.github_scan_runner import GithubScanRunner

    assert GithubScanRunner.source_name == "github_scan"
    assert GithubScanRunner.supports_schedule is True
    assert GithubScanRunner.supports_manual_trigger is True
    assert GithubScanRunner.is_continuous is False


@pytest.fixture
def target():
    return TargetConfig(
        id="test-target",
        name="Test",
        type="organization",
        match_rules={"domains": ["example.com"], "keywords": ["acme"]},
        runners={
            "github_scan": {
                "enabled": True,
                "schedule": "0 */4 * * *",
                "search_queries": ["credential_patterns", "domain_matches"],
            }
        },
    )


@pytest.fixture
def mock_store():
    store = MagicMock()
    store.pool = AsyncMock()
    store.insert_raw_event = AsyncMock(return_value=True)
    store.create_run = AsyncMock(return_value=uuid.uuid7())
    store.mark_run_started = AsyncMock()
    store.mark_run_finished = AsyncMock()
    store.get_run = AsyncMock(return_value={"discovery_session_id": str(uuid.uuid7())})
    return store


@pytest.mark.asyncio
async def test_github_scan_run_once_with_gitleaks(target, mock_store):
    from easm.runners.github_scan_runner import GithubScanRunner

    runner = GithubScanRunner(mock_store)
    runner._exec_subprocess = AsyncMock(return_value=(
        True,
        '[{"Repo":"example/repo","Line":42,"Commit":"abc123","File":"config.env","Secret":"fake","Match":"password=secret"}]',
        "",
    ))

    run_id = uuid.uuid7()
    inserted, deduped, errors = await runner.run_once(target, "scheduled", run_id)

    assert inserted >= 1
    runner._exec_subprocess.assert_called_once()
    args, kwargs = runner._exec_subprocess.call_args
    assert args[0][0] == "gitleaks"


@pytest.mark.asyncio
async def test_github_scan_run_once_gitleaks_not_found(target, mock_store):
    from easm.runners.github_scan_runner import GithubScanRunner

    runner = GithubScanRunner(mock_store)
    runner._exec_subprocess = AsyncMock(return_value=(False, "", "binary not found: gitleaks"))

    run_id = uuid.uuid7()
    inserted, deduped, errors = await runner.run_once(target, "scheduled", run_id)

    assert inserted == 0
    assert errors == 1


@pytest.mark.asyncio
async def test_github_scan_run_once_github_search_api(target, mock_store):
    from easm.runners.github_scan_runner import GithubScanRunner

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json = AsyncMock(return_value={
        "items": [
            {
                "repository": {"full_name": "example/repo"},
                "path": "src/config.py",
                "html_url": "https://github.com/example/repo/src/config.py",
                "text_matches": [{"fragment": "acme password=secret"}],
            }
        ]
    })
    mock_client.get = AsyncMock(return_value=mock_resp)

    runner = GithubScanRunner(mock_store, http_client=mock_client)
    run_id = uuid.uuid7()
    inserted, deduped, errors = await runner.run_once(target, "scheduled", run_id)

    assert inserted >= 1
    assert errors == 0


@pytest.mark.asyncio
async def test_github_scan_runner_closes_http_client(target, mock_store):
    from easm.runners.github_scan_runner import GithubScanRunner

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    runner = GithubScanRunner(mock_store, http_client=mock_client)
    await runner.close()
    mock_client.aclose.assert_awaited_once()
```

- [ ] **Step 2: Implement GithubScanRunner**

```python
# src/easm/runners/github_scan_runner.py
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass

import httpx

from easm.config import TargetConfig
from easm.keyword_engine import KeywordEngine
from easm.runners.base import ApiRunner

logger = logging.getLogger(__name__)

GITHUB_SEARCH_URL = "https://api.github.com/search/code"


class GithubScanRunner(ApiRunner):
    source_name = "github_scan"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        cfg = self.get_runner_config(target)
        http = self._http_client or httpx.AsyncClient(timeout=60.0)
        inserted = deduped = errors = 0

        kw_engine = KeywordEngine(target)

        try:
            ins, ded, err = await self._run_gitleaks(target, run_id)
            inserted += ins
            deduped += ded
            errors += err

            if target.match_rules.domains or target.match_rules.keywords:
                ins, ded, err = await self._run_github_search(http, kw_engine, target, run_id)
                inserted += ins
                deduped += ded
                errors += err
        finally:
            if not self._http_client:
                await http.aclose()

        return inserted, deduped, errors

    async def _run_gitleaks(
        self, target: TargetConfig, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        inserted = deduped = errors = 0

        for domain in target.match_rules.domains:
            cmd = ["gitleaks", "detect", "--no-git", "--source", domain, "--report-format", "json"]
            ok, stdout, stderr = await self._exec_subprocess(cmd, timeout=120)
            if not ok:
                if "binary not found" in stderr:
                    logger.warning("gitleaks binary not found, skipping gitleaks scan")
                    return inserted, deduped, errors
                logger.warning("gitleaks error for %s: %s", domain, stderr[:200])
                errors += 1
                continue

            try:
                findings = json.loads(stdout)
                if isinstance(findings, list):
                    for f in findings:
                        raw = {
                            "source": "gitleaks",
                            "repository": f.get("Repo", ""),
                            "file": f.get("File", ""),
                            "line": f.get("Line", 0),
                            "commit": f.get("Commit", ""),
                            "secret": f.get("Secret", ""),
                            "match": f.get("Match", ""),
                            "domain": domain,
                            "severity": f.get("Severity", "high"),
                        }
                        result = await self.store.insert_raw_event(
                            target.org_id, target.id, self.source_name, raw, run_id,
                        )
                        if result:
                            inserted += 1
                        else:
                            deduped += 1
            except json.JSONDecodeError:
                errors += 1

        return inserted, deduped, errors

    async def _run_github_search(
        self,
        http: httpx.AsyncClient,
        kw_engine: KeywordEngine,
        target: TargetConfig,
        run_id: uuid.UUID,
    ) -> tuple[int, int, int]:
        inserted = deduped = errors = 0

        github_token: str | None = self.get_runner_config(target).get("github_token")
        headers = {"Accept": "application/vnd.github.v3.text-match+json"}
        if github_token:
            headers["Authorization"] = f"Bearer {github_token}"

        queries: list[str] = []

        for domain in target.match_rules.domains:
            queries.append(f"org:{domain} password")
            queries.append(f"org:{domain} secret")
            queries.append(f"org:{domain} key")

        for keyword in target.match_rules.keywords:
            quoted = f'"{keyword}"'
            queries.append(quoted)

        for query in queries:
            try:
                resp = await http.get(
                    GITHUB_SEARCH_URL,
                    params={"q": query, "per_page": 50},
                    headers=headers,
                )
                if resp.status_code == 403:
                    logger.warning("GitHub API rate limited on query: %s", query)
                    continue
                if resp.status_code != 200:
                    logger.warning("GitHub API returned %d for query: %s", resp.status_code, query)
                    continue

                data = resp.json()
                for item in data.get("items", []):
                    text_matches = item.get("text_matches", [])
                    fragments = [m.get("fragment", "") for m in text_matches]

                    matched_keywords: list[dict] = []
                    for frag in fragments:
                        m = kw_engine.match(frag)
                        for match in m:
                            matched_keywords.append({
                                "keyword": match.keyword,
                                "match_type": match.match_type,
                                "severity": match.severity,
                            })

                    raw = {
                        "source": "github_search",
                        "repository": item.get("repository", {}).get("full_name", ""),
                        "file_path": item.get("path", ""),
                        "file_url": item.get("html_url", ""),
                        "query": query,
                        "matched_keywords": matched_keywords,
                        "fragments": fragments,
                    }

                    result = await self.store.insert_raw_event(
                        target.org_id, target.id, self.source_name, raw, run_id,
                    )
                    if result:
                        inserted += 1
                    else:
                        deduped += 1
            except Exception as e:
                errors += 1
                logger.warning("GitHub search error for query %s: %s", query, e)

        return inserted, deduped, errors
```

- [ ] **Step 3: Add class attribute tests to test_runners.py**

Append to `tests/test_runners.py`:

```python
def test_github_scan_runner_class_attributes():
    from easm.runners.github_scan_runner import GithubScanRunner

    assert GithubScanRunner.source_name == "github_scan"
    assert GithubScanRunner.supports_schedule is True
    assert GithubScanRunner.supports_manual_trigger is True
    assert GithubScanRunner.is_continuous is False
    assert GithubScanRunner.is_api_runner is True
```

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/test_runners/test_github_scan_runner.py tests/test_runners.py -v`
Expected: All GitHub scan tests pass; class attribute test passes

- [ ] **Step 5: Commit**

```bash
git add src/easm/runners/github_scan_runner.py tests/test_runners/test_github_scan_runner.py
git commit -m "feat: add GithubScanRunner with gitleaks subprocess + GitHub search API modes"
```

---

## Task 5: GitHub/GitLab Code Search — Parser

**Files:**
- Create: `src/easm/parse/github_scan_parser.py`
- Create: `tests/test_parsers/test_github_scan_parser.py`

- [ ] **Step 1: Write failing tests for GithubScanParser**

```python
# tests/test_parsers/test_github_scan_parser.py
import pytest
from easm.parse.github_scan_parser import GithubScanParser


@pytest.mark.asyncio
async def test_github_scan_parser_gitleaks_finding():
    parser = GithubScanParser()
    event = {
        "raw": {
            "source": "gitleaks",
            "repository": "example/repo",
            "file": "config.env",
            "line": 42,
            "commit": "abc123",
            "secret": "fake_secret",
            "match": "password=s3cret",
            "domain": "example.com",
            "severity": "high",
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable

    findings = [e for e in result.entities if e.entity_type == "finding"]
    assert len(findings) == 1
    assert findings[0].attributes["source"] == "gitleaks"
    assert findings[0].attributes["repository"] == "example/repo"
    assert findings[0].attributes["file_path"] == "config.env"
    assert findings[0].attributes["severity"] == "high"


@pytest.mark.asyncio
async def test_github_scan_parser_github_search_finding():
    parser = GithubScanParser()
    event = {
        "raw": {
            "source": "github_search",
            "repository": "example/repo",
            "file_path": "src/config.py",
            "file_url": "https://github.com/example/repo/src/config.py",
            "query": "org:example.com password",
            "matched_keywords": [
                {"keyword": "acme", "match_type": "exact", "severity": "medium"},
            ],
            "fragments": ["acme password=secret"],
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable

    findings = [e for e in result.entities if e.entity_type == "finding"]
    assert len(findings) == 1
    assert findings[0].attributes["matched_keyword"] == "acme"
    assert findings[0].attributes["severity"] == "medium"


@pytest.mark.asyncio
async def test_github_scan_parser_multiple_keywords():
    parser = GithubScanParser()
    event = {
        "raw": {
            "source": "github_search",
            "repository": "example/repo",
            "file_path": "src/config.py",
            "file_url": "https://github.com/example/repo/src/config.py",
            "matched_keywords": [
                {"keyword": "acme", "match_type": "exact", "severity": "medium"},
                {"keyword": "secret", "match_type": "exact", "severity": "high"},
            ],
        }
    }
    result = await parser.parse(event)
    findings = [e for e in result.entities if e.entity_type == "finding"]
    assert len(findings) == 2


@pytest.mark.asyncio
async def test_github_scan_parser_no_data_returns_unparseable():
    parser = GithubScanParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_github_scan_parser_class_attributes():
    assert GithubScanParser.source_name == "github_scan"
    assert GithubScanParser.current_version == 1
```

- [ ] **Step 2: Implement GithubScanParser**

```python
# src/easm/parse/github_scan_parser.py
from __future__ import annotations

from easm.parse.base import BaseParser, ParseResult, EntityCandidate


class GithubScanParser(BaseParser):
    source_name = "github_scan"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        source = raw.get("source", "")
        repository = raw.get("repository", "")
        file_path = raw.get("file_path", "") or raw.get("file", "")

        if not source or not repository:
            return ParseResult(entities=[], relationships=[], unparseable=True, parse_error="no source or repository")

        entities: list[EntityCandidate] = []

        if source == "gitleaks":
            entities.append(EntityCandidate(
                entity_type="finding",
                value=f"gitleaks-{repository}-{file_path}-{raw.get('line', 0)}",
                attributes={
                    "source": "gitleaks",
                    "repository": repository,
                    "file_path": file_path,
                    "line": raw.get("line", 0),
                    "commit": raw.get("commit", ""),
                    "secret_type": raw.get("secret", ""),
                    "severity": raw.get("severity", "high"),
                    "domain": raw.get("domain", ""),
                    "source_type": "github_scan",
                },
            ))
        elif source == "github_search":
            matches = raw.get("matched_keywords", [])
            if not matches:
                return ParseResult(entities=[], relationships=[], unparseable=True, parse_error="no keyword matches")

            for m in matches:
                finding_id = f"github-{repository}-{file_path}-{m.get('keyword', 'unknown')}"
                entities.append(EntityCandidate(
                    entity_type="finding",
                    value=finding_id,
                    attributes={
                        "source": "github_search",
                        "repository": repository,
                        "file_path": file_path,
                        "file_url": raw.get("file_url", ""),
                        "query": raw.get("query", ""),
                        "matched_keyword": m.get("keyword", ""),
                        "match_type": m.get("match_type", ""),
                        "severity": m.get("severity", "medium"),
                        "source_type": "github_scan",
                    },
                ))
        else:
            return ParseResult(entities=[], relationships=[], unparseable=True, parse_error=f"unknown source: {source}")

        return ParseResult(entities=entities, relationships=[])
```

- [ ] **Step 3: Run parser tests**

Run: `uv run pytest tests/test_parsers/test_github_scan_parser.py -v`
Expected: All 5 tests pass

- [ ] **Step 4: Commit**

```bash
git add src/easm/parse/github_scan_parser.py tests/test_parsers/test_github_scan_parser.py
git commit -m "feat: add GithubScanParser for gitleaks + GitHub search finding extraction"
```

---

## Task 6: Breach Data Monitoring — Runner

**Files:**
- Create: `src/easm/runners/breach_monitor_runner.py`
- Create: `tests/test_runners/test_breach_monitor_runner.py`
- Modify: `tests/test_runners.py`

This runner checks HaveIBeenPwned (HIBP) and Dehashed for credentials/breaches matching target domains and email patterns.

- [ ] **Step 1: Write failing tests for BreachMonitorRunner**

```python
# tests/test_runners/test_breach_monitor_runner.py
from __future__ import annotations

import uuid
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import httpx
import pytest

from easm.config import TargetConfig


@pytest.mark.asyncio
async def test_breach_monitor_class_attributes():
    from easm.runners.breach_monitor_runner import BreachMonitorRunner

    assert BreachMonitorRunner.source_name == "breach_monitor"
    assert BreachMonitorRunner.supports_schedule is True
    assert BreachMonitorRunner.supports_manual_trigger is True
    assert BreachMonitorRunner.is_continuous is False


@pytest.fixture
def target():
    return TargetConfig(
        id="test-target",
        name="Test",
        type="organization",
        match_rules={"domains": ["example.com"], "keywords": ["acme"]},
        runners={
            "breach_monitor": {
                "enabled": True,
                "schedule": "0 6 * * *",
                "sources": ["hibp"],
            }
        },
    )


@pytest.fixture
def mock_store():
    store = MagicMock()
    store.pool = AsyncMock()
    store.insert_raw_event = AsyncMock(return_value=True)
    store.create_run = AsyncMock(return_value=uuid.uuid7())
    store.mark_run_started = AsyncMock()
    store.mark_run_finished = AsyncMock()
    store.get_run = AsyncMock(return_value={"discovery_session_id": str(uuid.uuid7())})
    return store


@pytest.mark.asyncio
async def test_breach_monitor_hibp_check(target, mock_store):
    from easm.runners.breach_monitor_runner import BreachMonitorRunner

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json = AsyncMock(return_value=[
        {"Name": "Adobe", "BreachDate": "2013-10-04", "DataClasses": ["Emails", "Passwords"]},
    ])
    mock_client.get = AsyncMock(return_value=mock_resp)

    runner = BreachMonitorRunner(mock_store, http_client=mock_client)
    run_id = uuid.uuid7()
    inserted, deduped, errors = await runner.run_once(target, "scheduled", run_id)

    assert inserted >= 1
    assert errors == 0


@pytest.mark.asyncio
async def test_breach_monitor_hibp_no_breaches(target, mock_store):
    from easm.runners.breach_monitor_runner import BreachMonitorRunner

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp_ok = AsyncMock()
    mock_resp_ok.status_code = 404
    mock_client.get = AsyncMock(return_value=mock_resp_ok)

    runner = BreachMonitorRunner(mock_store, http_client=mock_client)
    run_id = uuid.uuid7()
    inserted, deduped, errors = await runner.run_once(target, "scheduled", run_id)

    assert inserted == 0
    assert errors == 0


@pytest.mark.asyncio
async def test_breach_monitor_hibp_rate_limited(target, mock_store):
    from easm.runners.breach_monitor_runner import BreachMonitorRunner

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = AsyncMock()
    mock_resp.status_code = 429
    mock_client.get = AsyncMock(return_value=mock_resp)

    runner = BreachMonitorRunner(mock_store, http_client=mock_client)
    run_id = uuid.uuid7()
    inserted, deduped, errors = await runner.run_once(target, "scheduled", run_id)

    assert inserted == 0
    assert errors == 0


@pytest.mark.asyncio
async def test_breach_monitor_dehashed_check(target, mock_store):
    from easm.runners.breach_monitor_runner import BreachMonitorRunner

    target.runners["breach_monitor"]["sources"] = ["dehashed"]
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json = AsyncMock(return_value={
        "entries": [
            {
                "id": 1,
                "email": "admin@example.com",
                "password": "s3cret",
                "database_name": "ExampleCorp",
            }
        ]
    })
    mock_client.get = AsyncMock(return_value=mock_resp)

    runner = BreachMonitorRunner(mock_store, http_client=mock_client)
    run_id = uuid.uuid7()
    inserted, deduped, errors = await runner.run_once(target, "scheduled", run_id)

    assert inserted >= 1
    assert errors == 0


@pytest.mark.asyncio
async def test_breach_monitor_runner_closes_http_client(target, mock_store):
    from easm.runners.breach_monitor_runner import BreachMonitorRunner

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    runner = BreachMonitorRunner(mock_store, http_client=mock_client)
    await runner.close()
    mock_client.aclose.assert_awaited_once()
```

- [ ] **Step 2: Implement BreachMonitorRunner**

```python
# src/easm/runners/breach_monitor_runner.py
from __future__ import annotations

import json
import logging
import uuid
from base64 import b64encode

import httpx

from easm.config import TargetConfig
from easm.keyword_engine import KeywordEngine
from easm.runners.base import ApiRunner

logger = logging.getLogger(__name__)

HIBP_API = "https://haveibeenpwned.com/api/v3/breachedaccount"
DEHASHED_API = "https://api.dehashed.com/search"


class BreachMonitorRunner(ApiRunner):
    source_name = "breach_monitor"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        cfg = self.get_runner_config(target)
        sources: list[str] = cfg.get("sources", ["hibp"])
        http = self._http_client or httpx.AsyncClient(timeout=30.0)
        inserted = deduped = errors = 0

        try:
            if "hibp" in sources:
                ins, ded, err = await self._check_hibp(http, target, run_id)
                inserted += ins
                deduped += ded
                errors += err

            if "dehashed" in sources:
                ins, ded, err = await self._check_dehashed(http, target, run_id)
                inserted += ins
                deduped += ded
                errors += err
        finally:
            if not self._http_client:
                await http.aclose()

        return inserted, deduped, errors

    async def _check_hibp(
        self,
        http: httpx.AsyncClient,
        target: TargetConfig,
        run_id: uuid.UUID,
    ) -> tuple[int, int, int]:
        cfg = self.get_runner_config(target)
        api_key: str | None = cfg.get("hibp_api_key")
        inserted = deduped = errors = 0

        emails: set[str] = set()
        for domain in target.match_rules.domains:
            emails.add(f"admin@{domain}")
            emails.add(f"security@{domain}")
            emails.add(f"noreply@{domain}")

        for email in emails:
            headers = {}
            if api_key:
                headers["hibp-api-key"] = api_key
            headers["user-agent"] = "open-easm/1.0"

            try:
                resp = await http.get(f"{HIBP_API}/{email}", headers=headers)
                if resp.status_code == 404:
                    continue
                if resp.status_code == 429:
                    logger.warning("HIBP rate limited, sleeping")
                    continue
                if resp.status_code != 200:
                    logger.warning("HIBP returned %d for %s", resp.status_code, email)
                    continue

                breaches = resp.json()
                for breach in breaches:
                    raw = {
                        "source": "hibp",
                        "email": email,
                        "breach_name": breach.get("Name", ""),
                        "breach_date": breach.get("BreachDate", ""),
                        "data_classes": breach.get("DataClasses", []),
                        "description": breach.get("Description", ""),
                        "domain": breach.get("Domain", ""),
                    }
                    result = await self.store.insert_raw_event(
                        target.org_id, target.id, self.source_name, raw, run_id,
                    )
                    if result:
                        inserted += 1
                    else:
                        deduped += 1
            except Exception as e:
                errors += 1
                logger.warning("HIBP error for %s: %s", email, e)

        return inserted, deduped, errors

    async def _check_dehashed(
        self,
        http: httpx.AsyncClient,
        target: TargetConfig,
        run_id: uuid.UUID,
    ) -> tuple[int, int, int]:
        cfg = self.get_runner_config(target)
        api_key: str | None = cfg.get("dehashed_api_key")
        dehashed_email: str | None = cfg.get("dehashed_email")
        inserted = deduped = errors = 0

        if not api_key or not dehashed_email:
            logger.warning("Dehashed requires both api_key and email configured")
            return 0, 0, 0

        auth = b64encode(f"{dehashed_email}:{api_key}".encode()).decode()
        headers = {"Accept": "application/json", "Authorization": f"Basic {auth}"}

        queries: list[str] = []
        for domain in target.match_rules.domains:
            queries.append(f"domain:{domain}")
        for email_domain in target.match_rules.domains:
            queries.append(f"email:*@{email_domain}")

        for query in queries:
            try:
                resp = await http.get(DEHASHED_API, params={"query": query, "size": 100}, headers=headers)
                if resp.status_code != 200:
                    logger.warning("Dehashed returned %d for query: %s", resp.status_code, query)
                    continue

                data = resp.json()
                for entry in data.get("entries", []):
                    raw = {
                        "source": "dehashed",
                        "query": query,
                        "email": entry.get("email", ""),
                        "password": entry.get("password", ""),
                        "username": entry.get("username", ""),
                        "hashed_password": entry.get("hashed_password", ""),
                        "database_name": entry.get("database_name", ""),
                        "ip_address": entry.get("ip_address", ""),
                        "name": entry.get("name", ""),
                    }
                    result = await self.store.insert_raw_event(
                        target.org_id, target.id, self.source_name, raw, run_id,
                    )
                    if result:
                        inserted += 1
                    else:
                        deduped += 1
            except Exception as e:
                errors += 1
                logger.warning("Dehashed error for query %s: %s", query, e)

        return inserted, deduped, errors
```

- [ ] **Step 3: Add class attribute tests to test_runners.py**

Append to `tests/test_runners.py`:

```python
def test_breach_monitor_runner_class_attributes():
    from easm.runners.breach_monitor_runner import BreachMonitorRunner

    assert BreachMonitorRunner.source_name == "breach_monitor"
    assert BreachMonitorRunner.supports_schedule is True
    assert BreachMonitorRunner.supports_manual_trigger is True
    assert BreachMonitorRunner.is_continuous is False
    assert BreachMonitorRunner.is_api_runner is True
```

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/test_runners/test_breach_monitor_runner.py tests/test_runners.py -v`
Expected: All breach monitor tests pass; class attribute test passes

- [ ] **Step 5: Commit**

```bash
git add src/easm/runners/breach_monitor_runner.py tests/test_runners/test_breach_monitor_runner.py
git commit -m "feat: add BreachMonitorRunner with HIBP + Dehashed API breach checking"
```

---

## Task 7: Breach Data Monitoring — Parser

**Files:**
- Create: `src/easm/parse/breach_monitor_parser.py`
- Create: `tests/test_parsers/test_breach_monitor_parser.py`

- [ ] **Step 1: Write failing tests for BreachMonitorParser**

```python
# tests/test_parsers/test_breach_monitor_parser.py
import pytest
from easm.parse.breach_monitor_parser import BreachMonitorParser


@pytest.mark.asyncio
async def test_breach_monitor_parser_hibp_finding():
    parser = BreachMonitorParser()
    event = {
        "raw": {
            "source": "hibp",
            "email": "admin@example.com",
            "breach_name": "Adobe",
            "breach_date": "2013-10-04",
            "data_classes": ["Emails", "Passwords"],
            "domain": "adobe.com",
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable

    findings = [e for e in result.entities if e.entity_type == "finding"]
    assert len(findings) == 1
    assert findings[0].attributes["breach_name"] == "Adobe"
    assert findings[0].attributes["compromised_email"] == "admin@example.com"
    assert findings[0].attributes["data_classes"] == ["Emails", "Passwords"]
    assert findings[0].attributes["severity"] == "high"


@pytest.mark.asyncio
async def test_breach_monitor_parser_dehashed_finding():
    parser = BreachMonitorParser()
    event = {
        "raw": {
            "source": "dehashed",
            "email": "admin@example.com",
            "password": "s3cret",
            "database_name": "ExampleCorp",
            "query": "domain:example.com",
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable

    findings = [e for e in result.entities if e.entity_type == "finding"]
    assert len(findings) == 1
    assert findings[0].attributes["compromised_email"] == "admin@example.com"
    assert findings[0].attributes["password"] == "s3cret"


@pytest.mark.asyncio
async def test_breach_monitor_parser_no_data_returns_unparseable():
    parser = BreachMonitorParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_breach_monitor_parser_class_attributes():
    assert BreachMonitorParser.source_name == "breach_monitor"
    assert BreachMonitorParser.current_version == 1
```

- [ ] **Step 2: Implement BreachMonitorParser**

```python
# src/easm/parse/breach_monitor_parser.py
from __future__ import annotations

from easm.parse.base import BaseParser, ParseResult, EntityCandidate


class BreachMonitorParser(BaseParser):
    source_name = "breach_monitor"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        source = raw.get("source", "")

        if not source:
            return ParseResult(entities=[], relationships=[], unparseable=True, parse_error="no source")

        entities: list[EntityCandidate] = []

        if source == "hibp":
            breach_name = raw.get("breach_name", "")
            email = raw.get("email", "")
            if not breach_name or not email:
                return ParseResult(entities=[], relationships=[], unparseable=True, parse_error="missing breach name or email")

            finding_id = f"hibp-{email}-{breach_name}"
            entities.append(EntityCandidate(
                entity_type="finding",
                value=finding_id,
                attributes={
                    "source": "hibp",
                    "breach_name": breach_name,
                    "breach_date": raw.get("breach_date", ""),
                    "compromised_email": email,
                    "data_classes": raw.get("data_classes", []),
                    "domain": raw.get("domain", ""),
                    "description": raw.get("description", ""),
                    "severity": "high",
                    "source_type": "breach_monitor",
                },
            ))

        elif source == "dehashed":
            email = raw.get("email", "")
            if not email:
                return ParseResult(entities=[], relationships=[], unparseable=True, parse_error="dehashed entry without email")

            finding_id = f"dehashed-{email}-{raw.get('database_name', 'unknown')}"
            entities.append(EntityCandidate(
                entity_type="finding",
                value=finding_id,
                attributes={
                    "source": "dehashed",
                    "compromised_email": email,
                    "password": raw.get("password", ""),
                    "hashed_password": raw.get("hashed_password", ""),
                    "username": raw.get("username", ""),
                    "database_name": raw.get("database_name", ""),
                    "ip_address": raw.get("ip_address", ""),
                    "name": raw.get("name", ""),
                    "severity": "critical",
                    "source_type": "breach_monitor",
                },
            ))

        else:
            return ParseResult(entities=[], relationships=[], unparseable=True, parse_error=f"unknown source: {source}")

        return ParseResult(entities=entities, relationships=[])
```

- [ ] **Step 3: Run parser tests**

Run: `uv run pytest tests/test_parsers/test_breach_monitor_parser.py -v`
Expected: All 4 tests pass

- [ ] **Step 4: Commit**

```bash
git add src/easm/parse/breach_monitor_parser.py tests/test_parsers/test_breach_monitor_parser.py
git commit -m "feat: add BreachMonitorParser for HIBP + Dehashed finding extraction"
```

---

## Task 8: Runner Registration + Config Validation

**Files:**
- Modify: `src/easm/runners/__init__.py`
- Modify: `src/easm/parse/__init__.py`
- Modify: `src/easm/config.py`
- Modify: `config.yaml.example`
- Modify: `tests/test_runners.py` (registry test)

- [ ] **Step 1: Update runner __init__.py**

Edit `src/easm/runners/__init__.py` — add imports and registry entries:

```python
from easm.runners.paste_monitor_runner import PasteMonitorRunner
from easm.runners.github_scan_runner import GithubScanRunner
from easm.runners.breach_monitor_runner import BreachMonitorRunner

__all__ = [
    "ApiRunner", "BaseRunner",
    "SubfinderRunner", "AsnmapRunner", "CertStreamRunner",
    "CrtShRunner", "DnstwistRunner",
    "PasteMonitorRunner", "GithubScanRunner", "BreachMonitorRunner",
]

RUNNER_REGISTRY = {
    "subfinder": SubfinderRunner,
    "asnmap": AsnmapRunner,
    "certstream": CertStreamRunner,
    "crtsh": CrtShRunner,
    "dnstwist": DnstwistRunner,
    "paste_monitor": PasteMonitorRunner,
    "github_scan": GithubScanRunner,
    "breach_monitor": BreachMonitorRunner,
}
```

- [ ] **Step 2: Update parse __init__.py**

Edit `src/easm/parse/__init__.py` — add imports and registry entries:

```python
from easm.parse.paste_monitor_parser import PasteMonitorParser
from easm.parse.github_scan_parser import GithubScanParser
from easm.parse.breach_monitor_parser import BreachMonitorParser

PARSER_REGISTRY = {
    # ... existing entries ...
    "paste_monitor": PasteMonitorParser,
    "github_scan": GithubScanParser,
    "breach_monitor": BreachMonitorParser,
}
```

- [ ] **Step 3: Update config.py**

Edit `src/easm/config.py` — add runner names to validation sets:

```python
VALID_RUNNER_NAMES = {"certstream", "subfinder", "asnmap", "crtsh", "dnstwist", "paste_monitor", "github_scan", "breach_monitor"}
SCHEDULABLE_RUNNERS = {"subfinder", "asnmap", "crtsh", "dnstwist", "paste_monitor", "github_scan", "breach_monitor"}
```

Add config models for the new runners:

```python
class PasteMonitorRunnerConfig(BaseModel):
    enabled: bool = False
    schedule: str = "*/5 * * * *"
    sources: list[str] = Field(default_factory=lambda: ["pastebin"])
    pastebin_api_key: str | None = None
    max_pastes_per_run: int = 100


class GithubScanRunnerConfig(BaseModel):
    enabled: bool = False
    schedule: str = "0 */4 * * *"
    github_token: str | None = None
    gitleaks_path: str = "gitleaks"
    search_queries: list[str] = Field(default_factory=lambda: ["credential_patterns", "domain_matches"])


class BreachMonitorRunnerConfig(BaseModel):
    enabled: bool = False
    schedule: str = "0 6 * * *"
    sources: list[str] = Field(default_factory=lambda: ["hibp"])
    hibp_api_key: str | None = None
    dehashed_api_key: str | None = None
    dehashed_email: str | None = None
```

- [ ] **Step 4: Update config.yaml.example**

Append to the runners section in `config.yaml.example`:

```yaml
      paste_monitor:
        enabled: true
        schedule: "*/5 * * * *"
        sources: [pastebin]
        pastebin_api_key: "${PASTEBIN_KEY}"
        max_pastes_per_run: 100
      github_scan:
        enabled: true
        schedule: "0 */4 * * *"
        github_token: "${GITHUB_TOKEN}"
        gitleaks_path: gitleaks
        search_queries: [credential_patterns, domain_matches]
      breach_monitor:
        enabled: true
        schedule: "0 6 * * *"
        sources: [hibp, dehashed]
        hibp_api_key: "${HIBP_API_KEY}"
        dehashed_api_key: "${DEHASHED_KEY}"
        dehashed_email: "${DEHASHED_EMAIL}"
```

- [ ] **Step 5: Update registry test**

Edit `tests/test_runners.py` — update the registry assertion:

```python
def test_runner_registry_has_all_runners():
    assert set(RUNNER_REGISTRY.keys()) == {
        "subfinder", "asnmap", "certstream", "crtsh", "dnstwist",
        "paste_monitor", "github_scan", "breach_monitor",
    }
```

- [ ] **Step 6: Write config validation tests for new runners**

Add to `tests/test_config.py`:

```python
def test_valid_paste_monitor_config(tmp_path: Path):
    cfg = make_yaml(tmp_path, {
        "targets": [{
            "id": "t",
            "name": "T",
            "type": "organization",
            "enabled": True,
            "match_rules": {},
            "runners": {"paste_monitor": {"enabled": True, "schedule": "*/5 * * * *"}},
        }]
    })
    config = load_config(cfg)
    assert config.targets[0].runners["paste_monitor"]["enabled"] is True


def test_valid_github_scan_config(tmp_path: Path):
    cfg = make_yaml(tmp_path, {
        "targets": [{
            "id": "t",
            "name": "T",
            "type": "organization",
            "enabled": True,
            "match_rules": {},
            "runners": {"github_scan": {"enabled": True, "schedule": "0 */4 * * *"}},
        }]
    })
    config = load_config(cfg)
    assert config.targets[0].runners["github_scan"]["enabled"] is True


def test_valid_breach_monitor_config(tmp_path: Path):
    cfg = make_yaml(tmp_path, {
        "targets": [{
            "id": "t",
            "name": "T",
            "type": "organization",
            "enabled": True,
            "match_rules": {},
            "runners": {"breach_monitor": {"enabled": True, "schedule": "0 6 * * *"}},
        }]
    })
    config = load_config(cfg)
    assert config.targets[0].runners["breach_monitor"]["enabled"] is True


def test_rejects_unknown_cron_new_runners(tmp_path: Path):
    cfg = make_yaml(tmp_path, {
        "targets": [{
            "id": "t",
            "name": "T",
            "type": "organization",
            "enabled": True,
            "match_rules": {},
            "runners": {"paste_monitor": {"enabled": True, "schedule": "invalid-cron"}},
        }]
    })
    with pytest.raises(ValueError, match="Invalid cron"):
        load_config(cfg)
```

- [ ] **Step 7: Run all registration and config tests**

Run: `uv run pytest tests/test_runners.py tests/test_config.py -v`
Expected: All registry tests pass (8 runners), all config tests pass

- [ ] **Step 8: Run a full test suite to check for regressions**

Run: `uv run pytest -v 2>&1 | tail -30`
Expected: All existing tests still pass; new tests pass

- [ ] **Step 9: Commit**

```bash
git add src/easm/runners/__init__.py src/easm/parse/__init__.py src/easm/config.py config.yaml.example tests/test_runners.py tests/test_config.py
git commit -m "feat: register paste_monitor, github_scan, breach_monitor runners + parsers in config"
```

---

## Task 9: Full Integration Verification

- [ ] **Step 1: Lint all new files**

Run: `uv run ruff check src/easm/runners/paste_monitor_runner.py src/easm/runners/github_scan_runner.py src/easm/runners/breach_monitor_runner.py src/easm/parse/paste_monitor_parser.py src/easm/parse/github_scan_parser.py src/easm/parse/breach_monitor_parser.py src/easm/keyword_engine.py`
Expected: No lint errors

- [ ] **Step 2: Type check new files**

Run: `uv run mypy src/easm/keyword_engine.py src/easm/runners/paste_monitor_runner.py src/easm/runners/github_scan_runner.py src/easm/runners/breach_monitor_runner.py`
Expected: No type errors (may need `# type: ignore` on httpx mocks in tests)

- [ ] **Step 3: Run all tests**

Run: `uv run pytest -x -v`
Expected: All tests pass (runners, parsers, config, scheduler, API, pivot)

- [ ] **Step 4: Commit final verification**

```bash
git add -A && git commit -m "chore: lint and typecheck fixes for phase 1 monitors"
```

---

## Summary

| Task | Files Created | Files Modified | Tests |
|------|--------------|----------------|-------|
| 1. KeywordEngine | `keyword_engine.py` | — | 9 |
| 2. PasteMonitorRunner | `runners/paste_monitor_runner.py` | `tests/test_runners.py` | 5 + 1 |
| 3. PasteMonitorParser | `parse/paste_monitor_parser.py` | — | 5 |
| 4. GithubScanRunner | `runners/github_scan_runner.py` | `tests/test_runners.py` | 5 + 1 |
| 5. GithubScanParser | `parse/github_scan_parser.py` | — | 5 |
| 6. BreachMonitorRunner | `runners/breach_monitor_runner.py` | `tests/test_runners.py` | 6 + 1 |
| 7. BreachMonitorParser | `parse/breach_monitor_parser.py` | — | 4 |
| 8. Registration + Config | — | `runners/__init__.py`, `parse/__init__.py`, `config.py`, `config.yaml.example` | 5 |
| **Total** | **9 new files** | **5 modified** | **40+ tests** |
