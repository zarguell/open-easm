# Simplification Cascade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan phase-by-phase. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate ~3,000 lines of duplicated code across 40+ files by applying the unifying insight that runners, pivot handlers, stores, and API routes all follow identical patterns that differ only in data, not in structure.

**Architecture:** Transform class-heavy subsystems into data-driven registries backed by generic execution engines. The key insight: "Every runner is the same pipeline with different parameters." Same for pivot handlers (same function shape), stores (same CRUD pattern), and API routes (same filter/paginate pattern).

**Tech Stack:** Python 3.14, FastAPI, asyncpg, Pydantic, APScheduler, pytest, ruff, mypy

**Cascade Summary:**

| Phase | Cascade | What | Files Eliminated | Lines Cut |
|-------|---------|------|-----------------|-----------|
| 1 | C0 | Dead code removal | 5 | ~133 |
| 2 | C4 | Config model collapse | 0* | ~160 |
| 3 | C1 | Runner unification | 16 | ~1,500 |
| 4 | C2 | Pivot handler unification | 17 | ~400 |
| 5 | C5 | Store consolidation | 3 | ~306 |
| 6 | C6+C7+C8 | API cleanup | 1 | ~230 |
| 7 | C3 | Runner+Parser collapse (optional) | 35 | ~1,860 |

**Total (without C3):** **42 files, ~2,730 lines eliminated.**
**Total (with C3):** **77 files, ~4,590 lines eliminated.**

---

## Phase 1: Dead Code Removal (C0)

**Files to delete:**
- `src/easm/keywords.py` — dead duplicate of `keyword_engine.py`, zero imports from it
- `src/easm/gc.py` — never wired up in `main.py`, zero consumers
- `ui/src/types/` — empty directory
- `src/easm/pivot/__init__.py` — single re-export line of `PIVOT_HANDLER_REGISTRY`

**Files to modify:**
- `src/easm/pivot/worker.py` — update import from `easm.pivot` to `easm.pivot.handlers`
- `src/easm/backfill.py` — update import from `easm.pivot` to `easm.pivot.handlers`

### Task 1.1: Delete dead Python modules and verify

- [ ] **Step 1: Delete `keywords.py`**

```bash
rm src/easm/keywords.py
```

- [ ] **Step 2: Delete `gc.py`**

```bash
rm src/easm/gc.py
```

- [ ] **Step 3: Verify no imports reference deleted files**

```bash
rg "from easm.keywords|import easm.keywords|from easm.gc|import easm.gc" src/
```
Expected: zero results (confirm no code depends on these).

- [ ] **Step 4: Run ruff to confirm no lint errors**

```bash
uv run ruff check src/
```
Expected: PASS, or only pre-existing warnings unrelated to deletions.

### Task 1.2: Remove `pivot/__init__.py` re-export indirection

- [ ] **Step 1: Find all consumers of `from easm.pivot import PIVOT_HANDLER_REGISTRY`**

```bash
rg "from easm.pivot import|from easm.pivot\." src/
```

- [ ] **Step 2: Update `src/easm/pivot/worker.py`**

Replace:
```python
from easm.pivot import PIVOT_HANDLER_REGISTRY
```
With:
```python
from easm.pivot.handlers import PIVOT_HANDLER_REGISTRY
```

- [ ] **Step 3: Update `src/easm/backfill.py`**

Replace:
```python
from easm.pivot import PIVOT_HANDLER_REGISTRY
```
With:
```python
from easm.pivot.handlers import PIVOT_HANDLER_REGISTRY
```

Wait — check if `backfill.py` actually imports from `easm.pivot`. If it imports from `easm.pivot.resolver` directly, no change needed.

Let's verify: `grep "from easm.pivot" src/easm/backfill.py`
Expected: `from easm.pivot.resolver import PivotResolver` — this is fine, not affected.

- [ ] **Step 4: Delete the re-export file**

```bash
rm src/easm/pivot/__init__.py
```

- [ ] **Step 5: Verify**

```bash
uv run ruff check src/
uv run python -c "from easm.pivot.handlers import PIVOT_HANDLER_REGISTRY; print(len(PIVOT_HANDLER_REGISTRY))"
```
Expected: prints the number of registered handlers.

### Task 1.3: Remove empty `ui/src/types/` directory

- [ ] **Step 1: Delete empty directory**

```bash
rmdir ui/src/types/
```

### Task 1.4: Commit Phase 1

```bash
git add -A
git commit -m "chore: remove dead code (keywords.py, gc.py, empty types/, pivot __init__ re-export)"
```

---

## Phase 2: Config Model Normalization (C4)

**Goal:** Replace 8 typed per-runner config classes with one generic `RunnerConfig`. Normalize all runner config to `dict[str, Any]` at config load time so consumers never need `isinstance(cfg, dict)` checks.

**Files to modify:**
- `src/easm/config.py` — remove per-runner configs, simplify to `RunnerConfig`
- `src/easm/runners/base.py` — remove `get_runner_config` method (or simplify)
- `src/easm/scheduler.py` — remove `isinstance(runner_cfg, dict)` checks

**What stays:** `CertStreamFilters`, `AllowedPivot`, `PivotConfig`, `MatchRules`, `TargetConfig`, `KeywordPattern`, `SaasProviderConfig`, `AlertsConfig`, `Config` (root).

**What goes:** `CertStreamRunnerConfig`, `ScheduledRunnerArgs`, `SubfinderRunnerArgs`, `AsnmapRunnerArgs`, `SubfinderRunnerConfig`, `AsnmapRunnerConfig`, `CrtShRunnerConfig`, `DnstwistRunnerConfig`, `PasteMonitorRunnerConfig`, `GithubScanRunnerConfig`, `BreachMonitorRunnerConfig`, `CoverageConfig`.

### Task 2.1: Replace per-runner config classes with generic `RunnerConfig`

- [ ] **Step 1: Read current `config.py` to understand all per-runner config field variations**

The kept classes must be a superset of all fields from deleted classes. Here's the union of all fields:

| Field | Used By | Type |
|-------|---------|------|
| `enabled: bool` | all | `False` |
| `schedule: str` | all schedulable | `"0 0 * * *"` |
| `mode: str` | certstream | `"realtime"` |
| `filters: dict` | certstream | `CertStreamFilters` |
| `args: dict` | asnmap, subfinder, etc. | varies |
| `sources: list[str]` | paste_monitor, breach_monitor | `[]` |
| `pastebin_api_key: str \| None` | paste_monitor | `None` |
| `max_pastes_per_run: int` | paste_monitor | `100` |
| `github_token: str \| None` | github_scan | `None` |
| `gitleaks_path: str` | github_scan | `"gitleaks"` |
| `search_queries: list[str]` | github_scan | `[]` |
| `hibp_api_key: str \| None` | breach_monitor | `None` |
| `dehashed_api_key: str \| None` | breach_monitor | `None` |
| `dehashed_email: str \| None` | breach_monitor | `None` |

Strategy: Keep `RunnerConfig` with all optional fields (all default to `None`/`False`/`[]`). The Pydantic validation that was in per-class validators moves to `model_validator` on `TargetConfig`.

- [ ] **Step 2: Write the new simplified config model**

Replace the runner config section in `src/easm/config.py` (everything from line 25 through line 127) with:

```python
VALID_RUNNER_NAMES = {
    "certstream", "subfinder", "asnmap", "crtsh", "dnstwist",
    "cloud_enum", "paste_monitor", "gist_monitor", "stackoverflow_monitor", "discord_monitor",
    "github_scan", "breach_monitor",
    "commoncrawl", "searchengine",
    "wappalyzer", "screenshot", "portscan", "nuclei",
}
SCHEDULABLE_RUNNERS = {
    "subfinder", "asnmap", "crtsh", "dnstwist", "cloud_enum",
    "paste_monitor", "gist_monitor", "stackoverflow_monitor", "discord_monitor",
    "github_scan", "breach_monitor",
    "commoncrawl", "searchengine",
    "wappalyzer", "screenshot", "portscan", "nuclei",
}


class CertStreamFilters(BaseModel):
    include_common_name: bool = True
    include_san_dns_names: bool = True
    match_mode: str = "suffix"


class RunnerConfig(BaseModel):
    """Generic runner configuration. All fields optional with sensible defaults."""
    enabled: bool = False
    schedule: str | None = None
    mode: str | None = None
    filters: CertStreamFilters | None = None
    args: dict[str, Any] = Field(default_factory=dict)
    sources: list[str] = Field(default_factory=list)
    pastebin_api_key: str | None = None
    max_pastes_per_run: int = 100
    github_token: str | None = None
    gitleaks_path: str = "gitleaks"
    search_queries: list[str] = Field(default_factory=list)
    hibp_api_key: str | None = None
    dehashed_api_key: str | None = None
    dehashed_email: str | None = None

    @field_validator("schedule")
    @classmethod
    def schedule_must_be_valid_cron(cls, v: str | None) -> str | None:
        if v is None:
            return None
        import re
        _cron_field = r"(\*(\/\d+)?|[0-5]?\d)"
        _cron_hour = r"(\*(\/\d+)?|1?\d|2[0-3])"
        _cron_day = r"(\*(\/\d+)?|[1-3]?\d)"
        _cron_month = r"(\*(\/\d+)?|1?\d|1[0-2])"
        _cron_dow = r"(\*(\/\d+)?|[0-7])"
        cr = re.compile(
            rf"^{_cron_field}\s+{_cron_hour}\s+{_cron_day}\s+{_cron_month}\s+{_cron_dow}$"
        )
        if not cr.match(v):
            raise ValueError(f"Invalid cron expression: {v}")
        return v
```

Also remove: `CoverageConfig` (if unused outside config) — check first.

- [ ] **Step 3: Add a model_validator to TargetConfig that normalizes runner configs to dicts**

Add this to `TargetConfig`:

```python
@model_validator(mode="after")
def normalize_runners(self) -> TargetConfig:
    """Normalize all runner configs to RunnerConfig instances."""
    normalized: dict[str, Any] = {}
    for name, cfg in self.runners.items():
        if isinstance(cfg, dict):
            normalized[name] = RunnerConfig.model_validate(cfg)
        elif isinstance(cfg, RunnerConfig):
            normalized[name] = cfg
        else:
            raise ValueError(f"Unknown runner config type for {name}: {type(cfg)}")
    # Use object.__setattr__ to bypass frozen validation
    object.__setattr__(self, "runners", normalized)
    return self
```

- [ ] **Step 4: Remove the now-unnecessary validate_runners validator from Config**

The cron validation is now in `RunnerConfig.schedule_must_be_valid_cron`. Remove the `validate_runners` method from `Config`.

- [ ] **Step 5: Update `load_config` to handle mixed typed/dict configs**

Keep `load_config` as-is — it already handles `dict` passthrough. But now with the normalization in TargetConfig, the downstream consumers always get `RunnerConfig` instances or can call `.model_dump()`.

### Task 2.2: Remove `isinstance(cfg, dict)` checks from all consumer code

Now that `Config.targets[].runners[name]` is always a `RunnerConfig` instance, we can replace every:

```python
cfg_dict = runner_cfg if isinstance(runner_cfg, dict) else runner_cfg.model_dump()
```

With simply:

```python
cfg_dict = runner_cfg.model_dump()
```

Files to update:
- `src/easm/runners/base.py` — `get_runner_config()` method
- `src/easm/scheduler.py` — `setup_jobs()` and `add_jobs_for_target()` methods
- `src/easm/api/routes/targets.py` — `list_targets()` and `get_target()` routes

- [ ] **Step 1: Simplify `BaseRunner.get_runner_config()`**

Replace the current method (lines 31-35 of `base.py`):

```python
def get_runner_config(self, target: Any) -> dict[str, Any]:
    runner_raw = target.runners.get(self.source_name, {})
    if isinstance(runner_raw, dict):
        return runner_raw
    return runner_raw.model_dump() if hasattr(runner_raw, "model_dump") else {}
```

With:

```python
def get_runner_config(self, target: Any) -> dict[str, Any]:
    cfg = target.runners.get(self.source_name)
    if cfg is None:
        return {}
    return cfg.model_dump() if hasattr(cfg, "model_dump") else {}
```

- [ ] **Step 2: Simplify `scheduler.py` `setup_jobs()` and `add_jobs_for_target()`**

Replace:
```python
cfg_dict = runner_cfg if isinstance(runner_cfg, dict) else runner_cfg.model_dump()
```
With:
```python
cfg_dict = runner_cfg.model_dump()
```
In both methods.

- [ ] **Step 3: Simplify `api/routes/targets.py`**

Replace:
```python
cfg_dict = cfg if isinstance(cfg, dict) else cfg.model_dump()
```
With:
```python
cfg_dict = cfg.model_dump()
```
In both `list_targets()` and `get_target()`.

- [ ] **Step 4: Run tests and type check**

```bash
uv run ruff check src/
uv run mypy src/
uv run pytest tests/ -x -q
```
Expected: All pass or only pre-existing failures.

- [ ] **Step 5: Commit Phase 2**

```bash
git add -A
git commit -m "refactor: collapse per-runner config classes into generic RunnerConfig, normalize at load boundary"
```

---

## Phase 3: Runner Unification (C1)

**Goal:** Eliminate 16 of 18 runner class files. Replace with a declarative registry + generic execution engine.

**Strategic approach:** Runners fall into three categories:

| Category | Runners | Approach |
|----------|---------|----------|
| **Standard (subprocess+JSON)** | asnmap, subfinder, dnstwist, nuclei, wappalyzer | Declarative `SubprocessRunnerDef` in registry, no per-file code |
| **Standard (HTTP+JSON)** | crtsh, commoncrawl | Declarative `HttpRunnerDef` in registry, no per-file code |
| **Custom** | portscan, screenshot, paste_monitor, github_scan, breach_monitor, cloud_bucket, discord_monitor, gist_monitor, stackoverflow_monitor, searchengine, certstream | Keep minimal `run_once` function per runner, registered in registry |

**New files to create:**
- `src/easm/runners/registry.py` — all `RunnerDef` entries
- `src/easm/runners/engine.py` — generic lifecycle + execution engine

**Files to keep (rewritten to minimal functions):**
- `src/easm/runners/portscan_runner.py` → rename to `portscan.py`
- `src/easm/runners/screenshot_runner.py` → rename to `screenshot.py`
- `src/easm/runners/paste_monitor_runner.py` → rename to `paste_monitor.py`
- `src/easm/runners/github_scan_runner.py` → rename to `github_scan.py`
- `src/easm/runners/breach_monitor_runner.py` → rename to `breach_monitor.py`
- `src/easm/runners/cloud_bucket_runner.py` → rename to `cloud_bucket.py`
- `src/easm/runners/discord_monitor_runner.py` → rename to `discord_monitor.py`
- `src/easm/runners/gist_monitor_runner.py` → rename to `gist_monitor.py`
- `src/easm/runners/stackoverflow_monitor_runner.py` → rename to `stackoverflow_monitor.py`
- `src/easm/runners/searchengine_runner.py` → rename to `searchengine.py`
- `src/easm/runners/certstream_runner.py` → rename to `certstream.py`

**Files to delete:**
- `src/easm/runners/asnmap_runner.py`
- `src/easm/runners/subfinder_runner.py`
- `src/easm/runners/dnstwist_runner.py`
- `src/easm/runners/nuclei_runner.py`
- `src/easm/runners/wappalyzer_runner.py`
- `src/easm/runners/crtsh_runner.py`
- `src/easm/runners/commoncrawl_runner.py`
- `src/easm/runners/base.py` (absorbed into engine.py)

**Files to modify:**
- `src/easm/runners/__init__.py` — replaced with registry export
- `src/easm/main.py` — update imports
- `src/easm/scheduler.py` — update to use new system

### Task 3.1: Create the generic execution engine

**File:** `src/easm/runners/engine.py`

This replaces `BaseRunner.execute()` and `BaseRunner._exec_subprocess()`.

```python
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx

from easm.models import RunStatus
from easm.store import Store

logger = logging.getLogger(__name__)


async def exec_subprocess(
    cmd: list[str], *, timeout: int = 300, logger_fn=None
) -> tuple[bool, str, str]:
    """Execute a subprocess command. Returns (success, stdout, stderr)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return False, "", f"binary not found: {cmd[0]}"
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return False, "", "timeout"
    stdout_text = stdout.decode(errors="replace")
    stderr_text = stderr.decode(errors="replace")
    if logger_fn:
        for line in stdout_text.splitlines():
            logger_fn(f"[stdout] {line}")
        for line in stderr_text.splitlines():
            logger_fn(f"[stderr] {line}")
    if proc.returncode != 0:
        return False, stdout_text, stderr_text
    return True, stdout_text, ""


async def execute_runner(
    source_name: str,
    run_fn,
    target: Any,
    store: Store,
    trigger_type: str,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> uuid.UUID:
    """Standard runner lifecycle wrapper.
    
    Handles: create_run, mark_started, try/except, mark_finished,
    compute_counters. The `run_fn` only needs to do discovery work
    and return (inserted, deduped, errors).
    """
    log_lines: list[str] = []

    def _log(msg: str) -> None:
        log_lines.append(msg)

    run_id = await store.create_run(
        target.id, source_name, trigger_type, org_id=target.org_id
    )
    start = datetime.now(UTC)
    await store.mark_run_started(run_id, start)

    inserted = 0
    deduped = 0
    errors = 0
    error_message: str | None = None

    try:
        inserted, deduped, errors = await run_fn(
            target, store, trigger_type, run_id, _log, http_client
        )
        status = RunStatus.COMPLETED.value
    except Exception as e:
        status = RunStatus.FAILED.value
        error_message = str(e)
        errors += 1
        logger.exception(
            "runner failed",
            extra={
                "run_id": str(run_id),
                "target_id": target.id,
                "source": source_name,
            },
        )

    end = datetime.now(UTC)
    duration_ms = int((end - start).total_seconds() * 1000)
    log_text = "\n".join(log_lines) if log_lines else None
    await store.mark_run_finished(
        run_id, status, end, duration_ms,
        inserted, deduped, errors,
        error_message=error_message, logs=log_text,
    )

    # Compute run counters
    try:
        run_data = await store.get_run(run_id)
        session_id = run_data.get("discovery_session_id") if run_data else None
        if session_id:
            new_count = await store.pool.fetchval(
                "SELECT COUNT(*) FROM entities WHERE discovery_session_id = $1 AND is_first_discovery = TRUE",
                uuid.UUID(session_id),
            )
            total_count = await store.pool.fetchval(
                "SELECT COUNT(*) FROM entities WHERE discovery_session_id = $1",
                uuid.UUID(session_id),
            )
            await store.pool.execute(
                "UPDATE runs SET new_entity_count = $1, total_entity_count = $2 WHERE id = $3",
                new_count or 0, total_count or 0, run_id,
            )
    except Exception:
        logger.exception("failed to compute run counters", extra={"run_id": str(run_id)})

    logger.info(
        "run finished",
        extra={
            "run_id": str(run_id),
            "target_id": target.id,
            "source": source_name,
            "status": status,
            "duration_ms": duration_ms,
            "inserted": inserted,
            "deduped": deduped,
            "errors": errors,
        },
    )
    return run_id


async def standard_subprocess_run(
    target: Any,
    store: Store,
    trigger_type: str,
    run_id: uuid.UUID,
    log: Any,
    http_client: httpx.AsyncClient | None,
    *,
    source_name: str,
    binary: str,
    args_template: list[str],
    iterate_over: str,
    timeout: int = 300,
    transform_fn=None,
) -> tuple[int, int, int]:
    """Generic subprocess-based runner.
    
    iterate_over: "domains" | "asns" | "domains_x2" (http+https)
    args_template: list with "{value}" placeholder, e.g. ["-d", "{value}", "-json"]
    """
    inserted = deduped = errors = 0
    values = _get_iter_values(target, iterate_over)

    for value in values:
        cmd = [binary] + [arg.replace("{value}", value) for arg in args_template]
        ok, stdout, stderr = await exec_subprocess(cmd, timeout=timeout, logger_fn=log)
        if not ok:
            errors += 1
            log(f"[error] {binary} failed: {stderr[:200]}")
            continue

        for line in stdout.strip().split("\n"):
            if not line:
                continue
            try:
                parsed = json.loads(line)
                if transform_fn:
                    parsed = transform_fn(parsed, value)
                result = await store.insert_raw_event(
                    target.org_id, target.id, source_name, parsed, run_id,
                )
                if result:
                    inserted += 1
                else:
                    deduped += 1
            except json.JSONDecodeError:
                errors += 1

    return inserted, deduped, errors


async def standard_http_run(
    target: Any,
    store: Store,
    trigger_type: str,
    run_id: uuid.UUID,
    log: Any,
    http_client: httpx.AsyncClient | None,
    *,
    source_name: str,
    url_template: str,
    iterate_over: str,
    timeout: int = 30,
    transform_fn=None,
) -> tuple[int, int, int]:
    """Generic HTTP-based runner.
    
    url_template: str with "{value}" placeholder, e.g. "https://crt.sh/?q=%.{value}&output=json"
    """
    client = http_client or httpx.AsyncClient(timeout=float(timeout))
    inserted = deduped = errors = 0
    values = _get_iter_values(target, iterate_over)

    try:
        for value in values:
            url = url_template.replace("{value}", value)
            try:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                errors += 1
                log(f"[error] HTTP {url}: {e}")
                continue

            items = data if isinstance(data, list) else [data]
            for item in items:
                if transform_fn:
                    item = transform_fn(item, value)
                result = await store.insert_raw_event(
                    target.org_id, target.id, source_name, item, run_id,
                )
                if result:
                    inserted += 1
                else:
                    deduped += 1
    finally:
        if not http_client:
            await client.aclose()

    return inserted, deduped, errors


def _get_iter_values(target: Any, iterate_over: str) -> list[str]:
    """Get the list of values to iterate over for a runner."""
    if iterate_over == "domains":
        return list(target.match_rules.domains)
    elif iterate_over == "asns":
        return list(target.match_rules.asns)
    elif iterate_over == "domains_x2":
        result = []
        for domain in target.match_rules.domains:
            result.append(f"https://{domain}")
            result.append(f"http://{domain}")
        return result
    return []
```

### Task 3.2: Create the runner registry

**File:** `src/easm/runners/registry.py`

```python
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

RunFn = Callable[..., Any]  # (target, store, trigger_type, run_id, log, http_client) -> (int, int, int)


@dataclass
class RunnerDef:
    source_name: str
    run_fn: RunFn
    supports_schedule: bool = True
    supports_manual_trigger: bool = True
    is_continuous: bool = False


# Deferred imports to avoid circular dependencies
def _make_registry() -> dict[str, RunnerDef]:
    from functools import partial

    from easm.runners.engine import standard_subprocess_run, standard_http_run

    registry: dict[str, RunnerDef] = {}

    # === Standard subprocess runners (no per-file code needed) ===

    registry["asnmap"] = RunnerDef(
        source_name="asnmap",
        run_fn=partial(
            standard_subprocess_run,
            source_name="asnmap",
            binary="asnmap",
            args_template=["-a", "{value}", "-json"],
            iterate_over="asns",
            timeout=300,
        ),
        supports_schedule=True,
    )

    registry["subfinder"] = RunnerDef(
        source_name="subfinder",
        run_fn=partial(
            standard_subprocess_run,
            source_name="subfinder",
            binary="subfinder",
            args_template=["-d", "{value}", "-json", "-silent", "-nW", "-all"],
            iterate_over="domains",
            timeout=300,
        ),
        supports_schedule=True,
    )

    registry["dnstwist"] = RunnerDef(
        source_name="dnstwist",
        run_fn=partial(
            standard_subprocess_run,
            source_name="dnstwist",
            binary="dnstwist",
            args_template=["--format=json", "{value}"],
            iterate_over="domains",
            timeout=120,
            transform_fn=lambda parsed, value: {
                "domain": parsed.get("domain", ""),
                "original_domain": value,
                "type": parsed.get("fuzzer", ""),
                "dns": parsed.get("dns", {}),
                "registered": parsed.get("registered", False),
            },
        ),
        supports_schedule=True,
    )

    registry["nuclei"] = RunnerDef(
        source_name="nuclei",
        run_fn=partial(
            standard_subprocess_run,
            source_name="nuclei",
            binary="nuclei",
            args_template=["-u", "{value}", "-t", "exposures,misconfigurations",
                           "-severity", "critical,high", "-json", "-silent", "-no-interactsh"],
            iterate_over="domains_x2",
            timeout=900,
            transform_fn=lambda parsed, value: {**parsed, "hostname": value.split("://")[1], "url": value},
        ),
        supports_schedule=True,
    )

    registry["wappalyzer"] = RunnerDef(
        source_name="wappalyzer",
        run_fn=partial(
            standard_subprocess_run,
            source_name="wappalyzer",
            binary="wappalyzer",
            args_template=["{value}"],
            iterate_over="domains_x2",
            timeout=120,
            transform_fn=lambda parsed, value: {
                "hostname": value.split("://")[1],
                "url": value,
                "technologies": parsed if isinstance(parsed, list) else [parsed],
            },
        ),
        supports_schedule=True,
    )

    # === Standard HTTP runners ===

    registry["crtsh"] = RunnerDef(
        source_name="crtsh",
        run_fn=partial(
            standard_http_run,
            source_name="crtsh",
            url_template="https://crt.sh/?q=%.{value}&output=json",
            iterate_over="domains",
            timeout=30,
            transform_fn=lambda cert, value: {
                "name_value": cert.get("name_value", ""),
                "issuer_name_id": cert.get("issuer_name_id", ""),
                "not_before": cert.get("not_before", ""),
                "not_after": cert.get("not_after", ""),
                "serial_number": cert.get("serial_number", ""),
                "fingerprint": cert.get("fingerprint", ""),
            },
        ),
        supports_schedule=True,
    )

    registry["commoncrawl"] = RunnerDef(
        source_name="commoncrawl",
        run_fn=partial(
            standard_http_run,
            source_name="commoncrawl",
            url_template="http://index.commoncrawl.org/CC-MAIN-2025-13-index?url=*.{value}&output=json",
            iterate_over="domains",
            timeout=30,
            transform_fn=lambda record, value: {
                "url": record.get("url", ""),
                "domain": value,
                "source": "commoncrawl",
            },
        ),
        supports_schedule=True,
    )

    # === Custom runners (imported from minimal per-file modules) ===
    # These are imported lazily below

    return registry


# Build the standard portion of the registry immediately
_RUNNER_REGISTRY: dict[str, RunnerDef] | None = None


def get_runner_registry() -> dict[str, RunnerDef]:
    global _RUNNER_REGISTRY
    if _RUNNER_REGISTRY is None:
        _RUNNER_REGISTRY = _make_registry()
    return _RUNNER_REGISTRY
```

### Task 3.3: Rewrite custom runners as standalone run_once functions

For each custom runner, remove the class wrapper and keep just the `run_once` logic as a standalone async function.

**File:** `src/easm/runners/portscan.py` (was `portscan_runner.py`)

```python
from __future__ import annotations

import logging
import re
import uuid
from typing import Any

from easm.store import Store

logger = logging.getLogger(__name__)
DEFAULT_PORTS = "22,80,443,8080,8443,3389,3306,5432,6379,27017"


async def run_portscan(
    target: Any, store: Store, trigger_type: str, run_id: uuid.UUID,
    log: Any, http_client: Any,
) -> tuple[int, int, int]:
    from easm.runners.engine import exec_subprocess

    cfg = target.runners.get("portscan")
    cfg_dict = cfg.model_dump() if hasattr(cfg, "model_dump") else (cfg or {})
    args = cfg_dict.get("args", {})
    timeout = args.get("timeout_seconds", 600)
    ports = args.get("ports", DEFAULT_PORTS)
    profile = args.get("profile", "quick")
    port_arg = ports if profile == "custom" else DEFAULT_PORTS
    inserted = deduped = errors = 0

    for domain in target.match_rules.domains:
        cmd = ["nmap", "-sV", "-p", port_arg, "--open", "-oG", "-", domain]
        ok, stdout, stderr = await exec_subprocess(cmd, timeout=timeout, logger_fn=log)
        if not ok:
            errors += 1
            log(f"[error] nmap failed: {stderr[:200]}")
            continue

        for line in stdout.split("\n"):
            if not line.startswith("Host:") or "Ports:" not in line:
                continue
            parts = line.split("\t")
            host = parts[0].replace("Host: ", "").strip()
            if " (" in host:
                host = host.split(" (")[0].strip()
            ports_str = parts[1].replace("Ports: ", "").strip() if len(parts) > 1 else ""
            open_ports = []
            for p in ports_str.split(", "):
                if not p:
                    continue
                m = re.match(r"(\d+)/open/(\w+)///(.*?)/", p)
                if not m:
                    m = re.match(r"(\d+)/open/(\w+)///(.*)", p)
                if m:
                    open_ports.append({
                        "port": int(m.group(1)),
                        "protocol": m.group(2),
                        "service": m.group(3).strip(),
                    })
            if open_ports:
                raw = {"hostname": domain, "ip": host, "ports": open_ports}
                result = await store.insert_raw_event(
                    target.org_id, target.id, "portscan", raw, run_id,
                )
                if result:
                    inserted += 1
                else:
                    deduped += 1
    return inserted, deduped, errors
```

**File:** `src/easm/runners/screenshot.py` (was `screenshot_runner.py`)

Similar extraction — keep the `run_once` body, remove the class.

**File:** `src/easm/runners/github_scan.py` (was `github_scan_runner.py`)

Similar extraction.

**File:** `src/easm/runners/paste_monitor.py` (was `paste_monitor_runner.py`)

Similar extraction.

**File:** `src/easm/runners/certstream.py` (was `certstream_runner.py`)

Extract `run_once` and the `_run` method. Keep the WebSocket logic.

(And similarly for breach_monitor, cloud_bucket, discord_monitor, gist_monitor, stackoverflow_monitor, searchengine.)

### Task 3.4: Update runner __init__.py

**File:** `src/easm/runners/__init__.py`

Replace entire file:

```python
from __future__ import annotations

from easm.runners.registry import RunnerDef, get_runner_registry

# Lazy import for custom runners to avoid circular deps
_CUSTOM_IMPORTS = {
    "portscan": "easm.runners.portscan",
    "screenshot": "easm.runners.screenshot",
    "paste_monitor": "easm.runners.paste_monitor",
    "github_scan": "easm.runners.github_scan",
    "breach_monitor": "easm.runners.breach_monitor",
    "cloud_bucket": "easm.runners.cloud_bucket",
    "discord_monitor": "easm.runners.discord_monitor",
    "gist_monitor": "easm.runners.gist_monitor",
    "stackoverflow_monitor": "easm.runners.stackoverflow_monitor",
    "searchengine": "easm.runners.searchengine",
    "certstream": "easm.runners.certstream",
}


def _ensure_custom_runners_loaded():
    """Lazily import custom runner modules so they can register themselves."""
    import importlib
    registry = get_runner_registry()
    for name, module_path in _CUSTOM_IMPORTS.items():
        if name not in registry:
            importlib.import_module(module_path)


def get_all_runners() -> dict[str, RunnerDef]:
    _ensure_custom_runners_loaded()
    return get_runner_registry()


__all__ = ["RunnerDef", "get_all_runners", "get_runner_registry"]
```

Update each custom runner file to register itself at import time:

```python
# At bottom of portscan.py:
from easm.runners.registry import RunnerDef, get_runner_registry

def _register():
    registry = get_runner_registry()
    registry["portscan"] = RunnerDef(
        source_name="portscan",
        run_fn=run_portscan,
        supports_schedule=True,
    )

_register()
```

### Task 3.5: Update scheduler.py to use new runner system

**File:** `src/easm/scheduler.py`

Replace `self._runner_registry` usage with the new registry:

```python
# In Scheduler class:
def __init__(self) -> None:
    self._scheduler = AsyncIOScheduler()

# Remove register_runner method - no longer needed

def setup_jobs(self, config: Any, store: Any) -> None:
    from easm.runners import get_all_runners
    runner_registry = get_all_runners()
    for target in config.targets:
        if not target.enabled:
            continue
        for runner_name, runner_cfg in target.runners.items():
            cfg_dict = runner_cfg.model_dump()  # Always RunnerConfig now
            if not cfg_dict.get("enabled", False):
                continue
            if runner_name not in runner_registry:
                logger.warning("unknown runner %s for target %s", runner_name, target.id)
                continue

            runner_def = runner_registry[runner_name]
            if runner_def.supports_schedule:
                schedule = cfg_dict.get("schedule", "0 0 * * *")
                job_id = f"{target.id}-{runner_name}"
                existing = self._scheduler.get_job(job_id)
                if existing is None:
                    from easm.runners.engine import execute_runner
                    import httpx

                    async def run_job(target=target, name=runner_name, defn=runner_def):
                        http_client = httpx.AsyncClient(timeout=30.0)
                        try:
                            await execute_runner(
                                defn.source_name, defn.run_fn, target, store,
                                "scheduled", http_client=http_client,
                            )
                        finally:
                            await http_client.aclose()

                    self._scheduler.add_job(
                        run_job, "cron",
                        id=job_id,
                        **self._parse_cron(schedule),
                        replace_existing=True,
                    )
                    logger.info("scheduled job", extra={
                        "job_id": job_id, "schedule": schedule, "target_id": target.id,
                    })
```

### Task 3.6: Update main.py imports

**File:** `src/easm/main.py`

Update runner-related imports and the trigger_runner/manual run code to use the new system.

```python
# Replace old imports
from easm.runners import RUNNER_REGISTRY
# With:
from easm.runners import get_all_runners

# Update runner registration
runner_registry = get_all_runners()
for runner_name, runner_def in runner_registry.items():
    scheduler.register_runner(runner_name, runner_def)  # This needs adapting
```

### Task 3.7: Update api/routes/runs.py trigger endpoint

The `/api/runs/{target_id}/{runner_name}` POST endpoint needs to use the new engine.

```python
from easm.runners import get_all_runners
from easm.runners.engine import execute_runner
import httpx

# In trigger_runner:
runner_def = get_all_runners().get(runner_name)
if not runner_def:
    raise HTTPException(404, f"Runner {runner_name} not found")

http_client = httpx.AsyncClient(timeout=30.0)
run_id = await execute_runner(
    runner_def.source_name, runner_def.run_fn, target, store,
    "manual", http_client=http_client,
)
await http_client.aclose()
```

### Task 3.8: Delete the old runner files

```bash
rm src/easm/runners/asnmap_runner.py
rm src/easm/runners/subfinder_runner.py
rm src/easm/runners/dnstwist_runner.py
rm src/easm/runners/nuclei_runner.py
rm src/easm/runners/wappalyzer_runner.py
rm src/easm/runners/crtsh_runner.py
rm src/easm/runners/commoncrawl_runner.py
rm src/easm/runners/base.py
```

### Task 3.9: Run full test suite

```bash
uv run ruff check src/
uv run mypy src/
uv run pytest tests/ -x -q
```

### Task 3.10: Commit Phase 3

```bash
git add -A
git commit -m "refactor: collapse 18 runner classes into declarative registry + generic engine"
```

---

## Phase 4: Pivot Handler Unification (C2)

**Goal:** Eliminate 18 handler ABC subclasses. Replace with a registry of pure functions.

### Task 4.1: Convert handlers to pure functions in a single module

**File:** `src/easm/pivot/handlers.py` (new, replaces `handlers/` directory)

Collect all handler logic into one file with a function registry:

```python
from __future__ import annotations

from typing import Any

# --- Handler Functions ---

async def dns_resolve(job: dict, pool) -> list[dict[str, Any]]:
    import dns.resolver
    hostname = job["entity_value"]
    results = []
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
    import dns.reversename, dns.resolver
    ip = job["entity_value"]
    results = []
    try:
        addr = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(addr, "PTR")
        for rdata in answers:
            results.append({"ip": ip, "hostname": str(rdata).rstrip(".")})
    except Exception:
        pass
    return results


async def crtsh_search(job: dict, pool) -> list[dict[str, Any]]:
    import httpx
    domain = job["entity_value"]
    results = []
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
            if resp.status_code == 200:
                for cert in resp.json():
                    results.append({
                        "domain": domain,
                        "name_value": cert.get("name_value", ""),
                        "fingerprint": cert.get("fingerprint", ""),
                        "not_before": cert.get("not_before", ""),
                        "not_after": cert.get("not_after", ""),
                    })
    except Exception:
        pass
    return results


# ... all other handler functions ...


# --- Registry ---

PIVOT_HANDLER_REGISTRY: dict[str, Any] = {
    "dns_resolve": dns_resolve,
    "reverse_dns": reverse_dns,
    "crtsh_search": crtsh_search,
    "domain_extract": domain_extract,
    "geoip_enrich": geoip_enrich,
    "dns_mail_records": dns_mail_records,
    "tls_cert_grab": tls_cert_grab,
    "subdomain_enum": subdomain_enum,
    "subdomain_takeover": subdomain_takeover,
    "passive_dns": passive_dns,
    "abuseipdb_enrich": abuseipdb_enrich,
    "greynoise_enrich": greynoise_enrich,
    "urlscan_enrich": urlscan_enrich,
    "censys_enrich": censys_enrich,
    "shodan_enrich": shodan_enrich,
    "rdap_lookup": rdap_lookup,
    "domain_rdap": domain_rdap,
    "reverse_whois": reverse_whois,
}
```

### Task 4.2: Update imports in worker.py and resolver.py

- `src/easm/pivot/worker.py`: Change `from easm.pivot.handlers import PIVOT_HANDLER_REGISTRY` to `from easm.pivot.handlers import PIVOT_HANDLER_REGISTRY`
- Remove the old `handlers/` directory and `handlers/base.py`

### Task 4.3: Delete old handler files

```bash
rm -rf src/easm/pivot/handlers/
```

### Task 4.4: Run tests and commit

```bash
uv run ruff check src/
uv run mypy src/
uv run pytest tests/ -x -q
git add -A
git commit -m "refactor: collapse 18 pivot handler classes into pure function registry"
```

---

## Phase 5: Store Consolidation (C5)

**Goal:** Merge `entity_store.py`, `pivot_store.py`, and `correlation/findings_store.py` into `store.py`.

### Task 5.1: Move entity_store functions into Store class

Add to `Store` class in `src/easm/store.py`:

```python
# --- Entity methods (from entity_store.py) ---

async def upsert_entity(
    self, org_id: str, target_id: str, entity_type: str, entity_value: str,
    new_attributes: dict, raw_event_id: uuid.UUID,
    discovery_session_id: uuid.UUID | None = None,
    discovery_run_id: uuid.UUID | None = None,
    discovery_pivot_id: uuid.UUID | None = None,
) -> tuple[uuid.UUID, bool]:
    """Upsert an entity. Returns (entity_id, is_new)."""
    import hashlib
    from easm.models import EntityType
    # ... (copy existing upsert_entity logic, replacing pool with self.pool)

async def upsert_relationship(
    self, org_id: str, target_id: str,
    source_entity_id: uuid.UUID, target_entity_id: uuid.UUID,
    relationship_type: str, source: str,
    discovery_session_id: uuid.UUID | None = None,
    discovery_run_id: uuid.UUID | None = None,
    discovery_pivot_id: uuid.UUID | None = None,
) -> uuid.UUID | None:
    """Upsert a relationship. Returns relationship_id or None."""
    # ... (copy existing upsert_relationship logic)

def normalize_entity_value(self, entity_type: str, value: str) -> str:
    """Normalize entity values for storage."""
    # ... (copy existing normalize_entity_value logic)
```

### Task 5.2: Move pivot_store functions into Store class

Add to `Store`:

```python
# --- Pivot queue methods (from pivot_store.py) ---

async def enqueue_pivot_job(self, org_id, target_id, entity_type, entity_value, ...):
    # ... (same logic, use self.pool)

async def dequeue_pivot_job(self) -> dict | None:
    # ...

async def mark_pivot_completed(self, job_id):
    # ...

async def mark_pivot_failed(self, job_id, error):
    # ...

async def reset_orphaned_pivot_jobs(self):
    # ...
```

### Task 5.3: Move FindingsStore into Store class

Add to `Store`:

```python
# --- Findings methods (from findings_store.py) ---

async def insert_finding(self, ...):
    # ...

async def list_findings(self, ...):
    # ...

async def update_finding(self, ...):
    # ...
```

### Task 5.4: Update all consumers

Search for all imports from deleted modules and replace with `store.method_name()`:

```bash
rg "from easm.entity_store import|from easm.pivot_store import|from easm.correlation.findings_store import" src/
```

Update each:
- `from easm.entity_store import upsert_entity` → `await store.upsert_entity(...)` (needs store instance)
- `from easm.pivot_store import enqueue_pivot_job` → `await store.enqueue_pivot_job(...)`
- `from easm.correlation.findings_store import FindingsStore` → use `store.list_findings(...)`

### Task 5.5: Delete old files

```bash
rm src/easm/entity_store.py
rm src/easm/pivot_store.py
rm src/easm/correlation/findings_store.py
```

### Task 5.6: Run tests and commit

```bash
uv run ruff check src/
uv run mypy src/
uv run pytest tests/ -x -q
git add -A
git commit -m "refactor: consolidate entity_store, pivot_store, findings_store into Store class"
```

---

## Phase 6: API Cleanup (C6 + C7 + C8)

### Task 6.1: Extract pagination utility (C6)

**File:** `src/easm/api/pagination.py` (new)

```python
from __future__ import annotations

from typing import Any


class PaginatedQuery:
    """Builder for cursor-based paginated SQL queries."""

    def __init__(self, table: str, fields: str = "*",
                 order_by: str = "id DESC", cursor_field: str = "id",
                 cursor_cast: str = "::uuid"):
        self.table = table
        self.fields = fields
        self.order_by = order_by
        self.cursor_field = cursor_field
        self.cursor_cast = cursor_cast
        self._conditions: list[str] = []
        self._params: list[Any] = []
        self._idx = 0

    def add_filter(self, column: str, value: Any, cast: str = "") -> PaginatedQuery:
        if value is None:
            return self
        if isinstance(value, str) and not value.strip():
            return self
        self._idx += 1
        self._conditions.append(f"{column} = ${self._idx}{cast}")
        self._params.append(value)
        return self

    def add_cursor(self, cursor: str | None) -> PaginatedQuery:
        if cursor:
            self._idx += 1
            self._conditions.append(
                f"{self.cursor_field} < ${self._idx}{self.cursor_cast}"
            )
            self._params.append(cursor)
        return self

    def build(self, limit: int) -> tuple[str, list[Any]]:
        self._idx += 1
        where = f"WHERE {' AND '.join(self._conditions)}" if self._conditions else ""
        query = (
            f"SELECT {self.fields} FROM {self.table} "
            f"{where} "
            f"ORDER BY {self.order_by} "
            f"LIMIT ${self._idx}"
        )
        self._params.append(limit + 1)
        return query, self._params
```

### Task 6.2: Refactor API routes to use PaginatedQuery

Update `entities.py`, `events.py`, `runs.py`, `pivot_queue.py`, `findings.py` to use `PaginatedQuery` instead of inline condition building.

Example for `entities.py`:

```python
from easm.api.pagination import PaginatedQuery

@router.get("/entities")
async def list_entities(...):
    pq = PaginatedQuery("entities",
        fields="id, org_id, target_id, entity_type, entity_value, attributes, first_seen_at, last_seen_at, is_first_discovery")
    pq.add_cursor(cursor)
    pq.add_filter("target_id", target_id)
    pq.add_filter("entity_type", entity_type)
    pq.add_filter("first_seen_at", first_seen_since, cast="::timestamptz")
    pq.add_filter("last_seen_at", last_seen_before, cast="::timestamptz")
    query, params = pq.build(limit)
    # ... execute query
```

### Task 6.3: Deduplicate scheduler methods (C7)

In `src/easm/scheduler.py`, extract common logic:

```python
def _schedule_runner_for_target(self, target, runner_name, cfg_dict, store):
    """Schedule a single runner for a target. Shared by setup_jobs and add_jobs_for_target."""
    from easm.runners import get_all_runners
    runner_registry = get_all_runners()
    
    if runner_name not in runner_registry:
        logger.warning("unknown runner %s for target %s", runner_name, target.id)
        return
    
    runner_def = runner_registry[runner_name]
    if not runner_def.supports_schedule:
        return
    
    schedule = cfg_dict.get("schedule", "0 0 * * *")
    job_id = f"{target.id}-{runner_name}"
    if self._scheduler.get_job(job_id):
        return
    
    # ... create job and add to scheduler
```

Then `setup_jobs` and `add_jobs_for_target` both call `_schedule_runner_for_target`.

### Task 6.4: Merge Findings/Alerts routes (C8)

- Move `GET /api/alerts/feed` logic into `findings.py` as `GET /api/findings?acknowledged=false`
- Move `PATCH /api/alerts/feed/{id}` into `findings.py` as `PATCH /api/findings/{id}/acknowledge`
- Delete `alerts.py` (but keep alert rules endpoints in config or a new location if needed)
- Update UI `api/alerts.ts` to call `/api/findings` instead

### Task 6.5: Run tests and commit

```bash
uv run ruff check src/
uv run mypy src/
uv run pytest tests/ -x -q
git add -A
git commit -m "refactor: extract pagination utility, deduplicate scheduler, merge findings/alerts routes"
```

---

## Phase 7 (Optional): Runner + Parser Collapse (C3)

**⚠️ HIGH RISK — Evaluate separately.** This eliminates the two-phase pipeline but loses the raw event audit trail.

### Decision Checklist Before Proceeding:

- [ ] Is the `raw_events` audit trail used for debugging/replay?
- [ ] Does anyone currently query `raw_events` directly (API endpoint exists at `/api/events`)?
- [ ] Is the 90-day GC window sufficient for audit needs?
- [ ] Are there compliance requirements for keeping raw discovery data?

If answers are all "no" or "not needed", proceed.

### Task 7.1: Attach output schema to RunnerDef

Add an `output_schema` field to `RunnerDef` that describes how to transform runner output into entities/relationships directly:

```python
@dataclass
class EntityOutputSchema:
    entity_type: str
    value_field: str  # or a callable
    attributes: dict[str, str] = field(default_factory=dict)  # or callable

@dataclass 
class RunnerDef:
    # ... existing fields ...
    output_schema: list[EntityOutputSchema] = field(default_factory=list)
```

### Task 7.2: Modify engine to produce entities directly

In `standard_subprocess_run` and `standard_http_run`, after parsing output, also produce entities via `store.upsert_entity()` if `output_schema` is defined.

### Task 7.3: Remove backfill worker, parsers, raw_events polling

- Remove `backfill.py`
- Remove `parse/` directory (34 files)
- Add migration to drop `raw_events` table (or keep it for backward compat)

### Task 7.4: Run full integration tests

```bash
uv run pytest tests/ -x -v
```

---

## Verification Checklist (After All Phases)

```bash
# Lint
uv run ruff check src/

# Type check
uv run mypy src/

# Run all tests
uv run pytest tests/ -x -v

# Start the app and verify key endpoints
# (manual check or integration test)
curl http://localhost:8000/api/healthz
curl http://localhost:8000/api/targets
curl http://localhost:8000/api/entities?limit=5
```

---

## Rollback Strategy

Each phase is independently committable. If a phase introduces bugs:

```bash
git revert <phase-commit-hash>
```

The phases are ordered to minimize cross-phase dependencies:
- Phase 1-2 are pure cleanup (safe to revert independently)
- Phase 3 depends on Phase 2's config changes
- Phase 4 is independent
- Phase 5 depends on Phase 3-4 completing (import paths change)
- Phase 6 depends on Phase 5 (unified Store)
- Phase 7 is completely optional and depends on Phase 3
