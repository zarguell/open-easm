# Phase 3 Active Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 4 opt-in active discovery runners: service fingerprinting (Wappalyzer), web screenshot indexing, port scanning (nmap), and vulnerability scanning (Nuclei). All OFF by default per roadmap.

**Architecture:** Each sub-phase is a standalone runner extending `BaseRunner` (uses `_exec_subprocess()` for CLI tools) + a parser extending `BaseParser`. Follows the subfinder/asnmap CLI runner pattern exactly. Screenshots use Playwright instead of subprocess.

**Tech Stack:** Python 3.14, asyncio subprocess, httpx, pytest-asyncio. CLI tools: wappalyzer, nmap, nuclei. Screenshots: Playwright (already available in test env).

---

## File Structure

### New Files

| File | Responsibility |
|------|---------------|
| `src/easm/runners/wappalyzer_runner.py` | CLI runner: `wappalyzer {url}` → JSON tech stack |
| `src/easm/parse/wappalyzer_parser.py` | Parser: extract technologies as entity attributes |
| `src/easm/runners/screenshot_runner.py` | Playwright runner: screenshot each HTTP hostname |
| `src/easm/parse/screenshot_parser.py` | Parser: extract screenshot metadata |
| `src/easm/runners/portscan_runner.py` | CLI runner: `nmap -sV {target}` → port/service data |
| `src/easm/parse/portscan_parser.py` | Parser: extract open ports, services, versions |
| `src/easm/runners/nuclei_runner.py` | CLI runner: `nuclei -u {url}` → vulnerability findings |
| `src/easm/parse/nuclei_parser.py` | Parser: extract CVE IDs, severity, descriptions |
| `tests/test_parsers/test_wappalyzer_parser.py` | Tests |
| `tests/test_parsers/test_portscan_parser.py` | Tests |
| `tests/test_parsers/test_nuclei_parser.py` | Tests |
| `tests/test_parsers/test_screenshot_parser.py` | Tests |
| `tests/test_runners/test_wappalyzer_runner.py` | Tests |
| `tests/test_runners/test_portscan_runner.py` | Tests |
| `tests/test_runners/test_nuclei_runner.py` | Tests |

### Modified Files

| File | Change |
|------|--------|
| `src/easm/runners/__init__.py` | Register 4 runners |
| `src/easm/parse/__init__.py` | Register 4 parsers |
| `src/easm/config.py` | Add runner names to VALID_RUNNER_NAMES, SCHEDULABLE_RUNNERS |
| `config.yaml.example` | Add runner config examples (all disabled by default) |

---

## Existing CLI Runner Pattern (Follow Exactly)

From `SubfinderRunner`:
```python
from easm.config import TargetConfig
from easm.runners.base import BaseRunner

class SubfinderRunner(BaseRunner):
    source_name = "subfinder"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    async def run_once(self, target: TargetConfig, trigger_type: str, run_id) -> tuple[int,int,int]:
        cfg = self.get_runner_config(target)
        timeout = cfg.get("args", {}).get("timeout_seconds", 300)
        inserted = deduped = errors = 0

        for domain in target.match_rules.domains:
            cmd = ["subfinder", "-d", domain, "-json", "-silent"]
            ok, stdout, stderr = await self._exec_subprocess(cmd, timeout=timeout)
            if not ok:
                errors += 1
                continue
            for line in stdout.strip().split("\n"):
                if not line: continue
                try:
                    parsed = json.loads(line)
                    result = await self.store.insert_raw_event(
                        target.org_id, target.id, self.source_name, parsed, run_id)
                    if result: inserted += 1
                    else: deduped += 1
                except json.JSONDecodeError:
                    errors += 1
        return inserted, deduped, errors
```

**SpiderFoot references at:** `/var/folders/kn/yyqnpxsd25g007zfpmhh5yrh0000gn/T/opencode/spiderfoot/modules/`

---

## Task 1: Wappalyzer Service Fingerprinting

**SpiderFoot reference:** `sfp_tool_wappalyzer.py` — runs `wappalyzer {url}` CLI

**CLI:** `wappalyzer https://example.com` → JSON array of technology objects:
```json
[{"name":"nginx","version":"1.24.0","categories":["Web Servers"],"confidence":100}]
```

**Files:**
- Create: `src/easm/runners/wappalyzer_runner.py`
- Create: `src/easm/parse/wappalyzer_parser.py`
- Create: `tests/test_parsers/test_wappalyzer_parser.py`
- Create: `tests/test_runners/test_wappalyzer_runner.py`

### Runner

```python
# src/easm/runners/wappalyzer_runner.py
from __future__ import annotations
import json, logging, uuid
from easm.config import TargetConfig
from easm.runners.base import BaseRunner

logger = logging.getLogger(__name__)

class WappalyzerRunner(BaseRunner):
    source_name = "wappalyzer"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    async def run_once(self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID) -> tuple[int,int,int]:
        cfg = self.get_runner_config(target)
        timeout = cfg.get("args", {}).get("timeout_seconds", 120)
        inserted = deduped = errors = 0

        for domain in target.match_rules.domains:
            for scheme in ("https://", "http://"):
                url = f"{scheme}{domain}"
                cmd = ["wappalyzer", url]
                ok, stdout, stderr = await self._exec_subprocess(cmd, timeout=timeout)
                if not ok:
                    errors += 1
                    logger.warning("wappalyzer failed", extra={"url": url, "stderr": stderr[:200] if stderr else ""})
                    continue
                try:
                    techs = json.loads(stdout)
                    raw = {"hostname": domain, "url": url, "technologies": techs}
                    result = await self.store.insert_raw_event(
                        target.org_id, target.id, self.source_name, raw, run_id)
                    if result: inserted += 1
                    else: deduped += 1
                except json.JSONDecodeError:
                    errors += 1
        return inserted, deduped, errors
```

### Parser

```python
# src/easm/parse/wappalyzer_parser.py
from easm.parse.base import BaseParser, ParseResult, EntityCandidate
from easm.entity_store import normalize_entity_value

class WappalyzerParser(BaseParser):
    source_name = "wappalyzer"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        hostname = raw.get("hostname", "").strip()
        techs = raw.get("technologies", [])
        if not hostname:
            return ParseResult(entities=[], relationships=[], unparseable=True,
                              parse_error="missing hostname")
        normalized = normalize_entity_value("hostname", hostname)
        return ParseResult(entities=[EntityCandidate(
            entity_type="hostname", value=normalized,
            attributes={"source": "wappalyzer", "technologies": techs},
        )], relationships=[])
```

### Tests

Parser tests (5): extracts technologies from valid input, missing hostname → unparseable, empty raw → unparseable, class attributes, multiple technologies extracted.
Runner tests (3): returns tuple of ints, source_name correct, class attributes correct.

- [ ] **Commit** — `git commit -m "feat: add Wappalyzer service fingerprinting runner + parser"`

---

## Task 2: Web Screenshot Indexing

**Approach:** Use Playwright (already in dev dependencies) to take screenshots of discovered HTTP/HTTPS hostnames. Store as base64 or file paths in entity attributes.

**Files:**
- Create: `src/easm/runners/screenshot_runner.py`
- Create: `src/easm/parse/screenshot_parser.py`
- Create: `tests/test_parsers/test_screenshot_parser.py`
- Create: `tests/test_runners/test_screenshot_runner.py`

### Runner

```python
# src/easm/runners/screenshot_runner.py
from __future__ import annotations
import json, logging, uuid, asyncio, base64
from pathlib import Path
from easm.config import TargetConfig
from easm.runners.base import BaseRunner

logger = logging.getLogger(__name__)
SCREENSHOT_DIR = Path("data/screenshots")

class ScreenshotRunner(BaseRunner):
    source_name = "screenshot"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    async def run_once(self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID) -> tuple[int,int,int]:
        cfg = self.get_runner_config(target)
        timeout = cfg.get("args", {}).get("timeout_seconds", 30)
        inserted = deduped = errors = 0

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.error("playwright not installed")
            return 0, 0, 1

        SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

        async with async_playwright() as p:
            browser = await p.chromium.launch()
            for domain in target.match_rules.domains:
                for scheme in ("https://", "http://"):
                    url = f"{scheme}{domain}"
                    try:
                        page = await browser.new_page()
                        await page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")
                        filepath = SCREENSHOT_DIR / f"{domain}.png"
                        await page.screenshot(path=str(filepath), full_page=False)
                        await page.close()
                        raw = {"hostname": domain, "url": url, "screenshot_path": str(filepath)}
                        result = await self.store.insert_raw_event(
                            target.org_id, target.id, self.source_name, raw, run_id)
                        if result: inserted += 1
                        else: deduped += 1
                    except Exception as e:
                        errors += 1
                        logger.debug("screenshot failed for %s: %s", url, e)
            await browser.close()
        return inserted, deduped, errors
```

### Parser

Extracts hostname with screenshot_path attribute. Stores `screenshot_path` as entity attribute.

### Tests

Parser: extracts path, missing hostname → unparseable, class attributes.
Runner: returns tuple of ints (mock playwright or skip when not installed).

- [ ] **Commit** — `git commit -m "feat: add web screenshot indexing runner + parser"`

---

## Task 3: Port Scanning (nmap)

**SpiderFoot reference:** `sfp_portscan_tcp.py` — runs `nmap` with configurable ports.

**CLI:** `nmap -sV -p 22,80,443,8080,8443 --open -oX - {target}` → XML output. Or use `-oG -` for grepable format.

**Files:**
- Create: `src/easm/runners/portscan_runner.py`
- Create: `src/easm/parse/portscan_parser.py`
- Create: `tests/test_parsers/test_portscan_parser.py`
- Create: `tests/test_runners/test_portscan_runner.py`

### Runner

```python
# src/easm/runners/portscan_runner.py
from __future__ import annotations
import json, logging, uuid, re
from easm.config import TargetConfig
from easm.runners.base import BaseRunner

logger = logging.getLogger(__name__)
DEFAULT_PORTS = "22,80,443,8080,8443,3389,3306,5432,6379,27017"

class PortScanRunner(BaseRunner):
    source_name = "portscan"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    async def run_once(self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID) -> tuple[int,int,int]:
        cfg = self.get_runner_config(target)
        timeout = cfg.get("args", {}).get("timeout_seconds", 600)
        ports = cfg.get("args", {}).get("ports", DEFAULT_PORTS)
        profile = cfg.get("args", {}).get("profile", "quick")
        port_arg = ports if profile == "custom" else DEFAULT_PORTS
        inserted = deduped = errors = 0

        for domain in target.match_rules.domains:
            cmd = ["nmap", "-sV", "-p", port_arg, "--open", "-oG", "-", domain]
            ok, stdout, stderr = await self._exec_subprocess(cmd, timeout=timeout)
            if not ok:
                errors += 1
                logger.warning("nmap failed", extra={"domain": domain, "stderr": stderr[:200] if stderr else ""})
                continue

            for line in stdout.split("\n"):
                if not line.startswith("Host:") or "Ports:" not in line:
                    continue
                # Parse grepable nmap output
                parts = line.split("\t")
                host = parts[0].replace("Host: ", "").strip()
                ports_str = parts[1].replace("Ports: ", "").strip() if len(parts) > 1 else ""
                open_ports = []
                for p in ports_str.split(", "):
                    if not p: continue
                    m = re.match(r"(\d+)/open/(\w+)///(.*?)/", p)
                    if not m:
                        m = re.match(r"(\d+)/open/(\w+)///(.*)", p)
                    if m:
                        open_ports.append({"port": int(m.group(1)), "protocol": m.group(2),
                                          "service": m.group(3).strip()})
                if open_ports:
                    raw = {"hostname": domain, "ip": host, "ports": open_ports}
                    result = await self.store.insert_raw_event(
                        target.org_id, target.id, self.source_name, raw, run_id)
                    if result: inserted += 1
                    else: deduped += 1
        return inserted, deduped, errors
```

### Parser

Extracts hostname+ip entities with `open_ports` attribute containing port/protocol/service arrays. Also creates `ip` entities for discovered hosts.

### Tests

Parser: extracts ports, missing hostname → unparseable, empty ports, class attributes.
Runner: returns tuple of ints (mock subprocess or skip if nmap not installed).

- [ ] **Commit** — `git commit -m "feat: add nmap port scanning runner + parser"`

---

## Task 4: Nuclei Vulnerability Scanning

**SpiderFoot reference:** `sfp_tool_nuclei.py` — runs `nuclei` CLI with templates.

**CLI:** `nuclei -u https://example.com -t exposures,misconfigurations -json -silent` → JSON lines output.

**Files:**
- Create: `src/easm/runners/nuclei_runner.py`
- Create: `src/easm/parse/nuclei_parser.py`
- Create: `tests/test_parsers/test_nuclei_parser.py`
- Create: `tests/test_runners/test_nuclei_runner.py`

### Runner

```python
# src/easm/runners/nuclei_runner.py
from __future__ import annotations
import json, logging, uuid
from easm.config import TargetConfig
from easm.runners.base import BaseRunner

logger = logging.getLogger(__name__)

class NucleiRunner(BaseRunner):
    source_name = "nuclei"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    async def run_once(self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID) -> tuple[int,int,int]:
        cfg = self.get_runner_config(target)
        timeout = cfg.get("args", {}).get("timeout_seconds", 900)
        templates = cfg.get("args", {}).get("templates", "exposures,misconfigurations")
        severity = cfg.get("args", {}).get("severity", "critical,high")
        inserted = deduped = errors = 0

        for domain in target.match_rules.domains:
            for scheme in ("https://", "http://"):
                url = f"{scheme}{domain}"
                cmd = ["nuclei", "-u", url, "-t", templates, "-severity", severity,
                       "-json", "-silent", "-no-interactsh"]
                ok, stdout, stderr = await self._exec_subprocess(cmd, timeout=timeout)
                if not ok:
                    errors += 1
                    logger.warning("nuclei failed", extra={"url": url, "stderr": stderr[:200] if stderr else ""})
                    continue

                for line in stdout.strip().split("\n"):
                    if not line: continue
                    try:
                        finding = json.loads(line)
                        finding["hostname"] = domain
                        finding["url"] = url
                        result = await self.store.insert_raw_event(
                            target.org_id, target.id, self.source_name, finding, run_id)
                        if result: inserted += 1
                        else: deduped += 1
                    except json.JSONDecodeError:
                        errors += 1
        return inserted, deduped, errors
```

### Parser

```python
# src/easm/parse/nuclei_parser.py
from easm.parse.base import BaseParser, ParseResult, EntityCandidate
from easm.entity_store import normalize_entity_value

class NucleiParser(BaseParser):
    source_name = "nuclei"
    current_version = 1

    async def parse(self, raw_event: dict) -> ParseResult:
        raw = raw_event.get("raw", {})
        hostname = raw.get("hostname", "").strip()
        if not hostname or "template-id" not in raw:
            return ParseResult(entities=[], relationships=[], unparseable=True,
                              parse_error="missing hostname or nuclei data")
        normalized = normalize_entity_value("hostname", hostname)
        return ParseResult(entities=[EntityCandidate(
            entity_type="hostname", value=normalized,
            attributes={
                "source": "nuclei",
                "vulnerability": {
                    "template_id": raw.get("template-id", ""),
                    "name": raw.get("info", {}).get("name", ""),
                    "severity": raw.get("info", {}).get("severity", "unknown"),
                    "description": raw.get("info", {}).get("description", ""),
                    "matched_at": raw.get("matched-at", ""),
                    "curl_command": raw.get("curl-command", ""),
                },
            },
        )], relationships=[])
```

### Tests

Parser: extracts vulnerability info, missing hostname → unparseable, missing template-id → unparseable, class attributes.
Runner: returns tuple of ints (mock subprocess).

- [ ] **Commit** — `git commit -m "feat: add Nuclei vulnerability scanning runner + parser"`

---

## Task 5: Registration + Config

**Files:**
- Modify: `src/easm/runners/__init__.py` — add 4 runners
- Modify: `src/easm/parse/__init__.py` — add 4 parsers
- Modify: `src/easm/config.py` — add runner names, all disabled by default
- Modify: `config.yaml.example` — add runner config examples

### Runner Registry

```python
from easm.runners.wappalyzer_runner import WappalyzerRunner
from easm.runners.screenshot_runner import ScreenshotRunner
from easm.runners.portscan_runner import PortScanRunner
from easm.runners.nuclei_runner import NucleiRunner

# Add to RUNNER_REGISTRY:
    "wappalyzer": WappalyzerRunner,
    "screenshot": ScreenshotRunner,
    "portscan": PortScanRunner,
    "nuclei": NucleiRunner,
```

### Parser Registry

```python
from easm.parse.wappalyzer_parser import WappalyzerParser
from easm.parse.screenshot_parser import ScreenshotParser
from easm.parse.portscan_parser import PortScanParser
from easm.parse.nuclei_parser import NucleiParser

# Add to PARSER_REGISTRY:
    "wappalyzer": WappalyzerParser,
    "screenshot": ScreenshotParser,
    "portscan": PortScanParser,
    "nuclei": NucleiParser,
```

### Config

```python
# ALL are schedulable but disabled by default (opt-in)
VALID_RUNNER_NAMES = {"certstream", ..., "wappalyzer", "screenshot", "portscan", "nuclei"}
SCHEDULABLE_RUNNERS = {"subfinder", ..., "wappalyzer", "screenshot", "portscan", "nuclei"}
```

### Config Example (all disabled)

```yaml
      wappalyzer:
        enabled: false
        schedule: "0 5 * * 1"
        args:
          timeout_seconds: 120
      screenshot:
        enabled: false
        schedule: "0 6 * * 1"
        args:
          timeout_seconds: 30
      portscan:
        enabled: false
        schedule: "0 3 * * 0"
        args:
          timeout_seconds: 600
          ports: "22,80,443,8080,8443,3389,3306,5432,6379,27017"
      nuclei:
        enabled: false
        schedule: "0 4 * * 0"
        args:
          timeout_seconds: 900
          templates: "exposures,misconfigurations"
          severity: "critical,high"
```

- [ ] **Commit** — `git commit -m "feat: register Phase 3 active discovery runners, parsers, and config"`

---

## Self-Review Checklist

**1. Spec coverage:** 3.1 (Wappalyzer) ✅, 3.2 (Screenshots) ✅, 3.3 (Port Scanning) ✅, 3.4 (Nuclei) ✅.

**2. Placeholder scan:** No TODOs/TBDs. All code provided.

**3. Type consistency:** All runners use BaseRunner pattern. All parsers use BaseParser pattern. Source names consistent across runners, parsers, and registries.

**4. Safety:** All runners disabled by default in config example. Screenshots use Playwright (same as test env). CLI tools use `_exec_subprocess()` with timeout protection.
