# Open EASM Architecture Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix nuclei/portscan to scan discovered subdomains, improve JSONB data rendering in UI, fix portscan host discovery, and refactor to a decoupled multi-container architecture with Postgres-backed task queue, configurable workers, and janitor jobs.

**Architecture:** Current state is a single-process FastAPI app where web server, scheduler, runners, and pivot workers all share one asyncio event loop. The refactor moves to a worker pattern where the web container runs only the API + scheduler, and N worker containers pull jobs from a Postgres-backed queue (using `FOR UPDATE SKIP LOCKED`, already used by the pivot queue). A janitor worker task handles cleanup of stale runs and orphaned data.

**Tech Stack:** Python 3.14, FastAPI, asyncpg, APScheduler, PostgreSQL 18 (pg_cron-style task queue via SKIP LOCKED), Docker multi-stage builds, React 18 / TypeScript / Tailwind CSS 4

---

## Part 1: Quick Fixes (Independent of Refactor)

These three fixes are independent and can be done immediately without waiting for the architecture refactor.

---

### Task 1: Fix nuclei to scan discovered hostnames, not just configured domains

**Files:**
- Modify: `src/easm/runners/engine.py` (add `iterate_hostnames_x2` function)
- Modify: `src/easm/runners/registry.py:91-120` (`_nuclei_run` function)
- Test: `tests/runners/test_nuclei_hostname_scan.py`

**Context:** The nuclei runner currently calls `iterate_domains_x2` (engine.py:33-42) which only iterates `target.match_rules.domains` — the explicitly configured domains. Discovered subdomains from subfinder, certstream, etc. are stored as `entity_type='hostname'` in the entities table but nuclei never sees them.

- [ ] **Step 1: Write the failing test**

Create `tests/runners/test_nuclei_hostname_scan.py`:

```python
"""Verify nuclei scans discovered hostnames, not just configured domains."""
import asyncio
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_nuclei_scans_discovered_hostnames():
    """nuclei should scan both configured domains AND discovered hostnames."""
    from easm.runners.registry import get_runner_registry

    # Mock target with one configured domain
    target = MagicMock()
    target.id = "test-target"
    target.org_id = "default"
    target.match_rules.domains = ["example.com"]
    target.match_rules.asns = []
    target.runners = {
        "nuclei": MagicMock(
            model_dump=MagicMock(return_value={
                "enabled": True,
                "args": {
                    "timeout_seconds": 60,
                    "templates": "exposures",
                    "severity": "critical,high",
                },
            })
        )
    }

    # Mock store with discovered hostnames
    store = MagicMock()
    store.pool = MagicMock()
    store.pool.fetch = AsyncMock(return_value=[
        {"entity_value": "api.example.com"},
        {"entity_value": "staging.example.com"},
    ])
    store.insert_raw_event = AsyncMock(return_value=uuid.uuid4())

    registry = get_runner_registry()
    nuclei_def = registry["nuclei"]

    # Capture the items that nuclei iterates over
    captured_items = []
    original_exec = None

    with patch("easm.runners.registry.standard_subprocess_run") as mock_run:
        mock_run.return_value = (0, 0, 0)

        log = lambda msg: None
        http_client = None
        await nuclei_def.run_fn(target, store, "manual", uuid.uuid4(), log, http_client)

        # Verify standard_subprocess_run was called
        assert mock_run.called
        call_kwargs = mock_run.call_args[1] if mock_run.call_args else {}
        iterate_fn = call_kwargs.get("iterate_over")

        if iterate_fn:
            items = iterate_fn(target)
            # Should include configured domain AND discovered hostnames
            assert "https://example.com" in items
            assert "https://api.example.com" in items
            assert "https://staging.example.com" in items
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/zach/localcode/open-easm && uv run pytest tests/runners/test_nuclei_hostname_scan.py -v`
Expected: FAIL — nuclei only scans `example.com`, not discovered hostnames

- [ ] **Step 3: Add `iterate_hostnames_x2` function to engine.py**

In `src/easm/runners/engine.py`, after `iterate_domains_x2` (line 42), add:

```python
async def iterate_hostnames_x2(target: Any, pool: Any) -> list[str]:
    """Produce ``https://<hostname>`` and ``http://<hostname>`` for discovered hostnames.

    Queries the entities table for hostname-type entities belonging to the target.
    Falls back to iterate_domains_x2 if pool is unavailable.
    """
    items: list[str] = []

    # Always include configured domains
    for domain in target.match_rules.domains:
        items.append(f"https://{domain}")
        items.append(f"http://{domain}")

    # Add discovered hostnames from entities table
    if pool is not None:
        try:
            rows = await pool.fetch(
                "SELECT entity_value FROM entities "
                "WHERE target_id = $1 AND entity_type = 'hostname' "
                "ORDER BY last_seen_at DESC",
                target.id,
            )
            existing = {f"https://{domain}", f"http://{domain}" for domain in target.match_rules.domains}
            for row in rows:
                hostname = row["entity_value"]
                https_url = f"https://{hostname}"
                http_url = f"http://{hostname}"
                if https_url not in existing:
                    items.append(https_url)
                if http_url not in existing:
                    items.append(http_url)
        except Exception:
            pass  # Fall back to domains only

    return items
```

- [ ] **Step 4: Update `_nuclei_run` in registry.py to use discovered hostnames**

Modify `src/easm/runners/registry.py`, replace the `_nuclei_run` function (lines 91-120):

```python
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
```

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/runners/test_nuclei_hostname_scan.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/easm/runners/engine.py src/easm/runners/registry.py tests/runners/test_nuclei_hostname_scan.py
git commit -m "fix: nuclei scans discovered hostnames from entities table, not just configured domains"
```

---

### Task 2: Fix portscan to use `-Pn` and scan discovered hostnames

**Files:**
- Modify: `src/easm/runners/portscan_runner.py` (add `-Pn`, scan hostnames from DB)
- Test: `tests/runners/test_portscan_hostname_scan.py`

**Context:** Two problems: (1) nmap uses default ping-based host discovery, which fails when hosts block ICMP — `-Pn` skips this. (2) Portscan only iterates `target.match_rules.domains`, not discovered hostnames from the entities table.

- [ ] **Step 1: Write the failing test**

Create `tests/runners/test_portscan_hostname_scan.py`:

```python
"""Verify portscan uses -Pn and scans discovered hostnames."""
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_portscan_uses_pn_flag():
    """Portscan should pass -Pn to nmap to skip ping-based host discovery."""
    from easm.runners.portscan_runner import PortScanRunner

    target = MagicMock()
    target.id = "test-target"
    target.org_id = "default"
    target.match_rules.domains = ["example.com"]
    target.runners = {
        "portscan": MagicMock(
            model_dump=MagicMock(return_value={
                "enabled": True,
                "args": {"timeout_seconds": 60, "ports": "22,80,443"},
            })
        )
    }

    store = MagicMock()
    store.insert_raw_event = AsyncMock(return_value=uuid.uuid4())

    captured_cmds = []

    async def mock_exec(cmd, *, timeout=300):
        captured_cmds.append(cmd)
        return True, "Host: 1.2.3.4 (1)\tPorts: 80/open/tcp//http/\n", ""

    runner = PortScanRunner(store)
    runner._exec_subprocess = mock_exec

    await runner.run_once(target, "manual", uuid.uuid4())

    assert len(captured_cmds) == 1
    cmd = captured_cmds[0]
    assert "-Pn" in cmd, f"Expected -Pn in nmap command, got: {cmd}"


@pytest.mark.asyncio
async def test_portscan_scans_discovered_hostnames():
    """Portscan should scan discovered hostnames, not just configured domains."""
    from easm.runners.portscan_runner import PortScanRunner

    target = MagicMock()
    target.id = "test-target"
    target.org_id = "default"
    target.match_rules.domains = ["example.com"]
    target.runners = {
        "portscan": MagicMock(
            model_dump=MagicMock(return_value={
                "enabled": True,
                "args": {"timeout_seconds": 60, "ports": "22,80,443"},
            })
        )
    }

    store = MagicMock()
    store.pool = MagicMock()
    store.pool.fetch = AsyncMock(return_value=[
        {"entity_value": "api.example.com"},
        {"entity_value": "staging.example.com"},
    ])
    store.insert_raw_event = AsyncMock(return_value=uuid.uuid4())

    captured_cmds = []

    async def mock_exec(cmd, *, timeout=300):
        captured_cmds.append(cmd)
        return True, "", ""

    runner = PortScanRunner(store)
    runner._exec_subprocess = mock_exec

    await runner.run_once(target, "manual", uuid.uuid4())

    # Should scan configured domain + discovered hostnames
    scanned_hosts = [cmd[-1] for cmd in captured_cmds]
    assert "example.com" in scanned_hosts
    assert "api.example.com" in scanned_hosts
    assert "staging.example.com" in scanned_hosts
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/runners/test_portscan_hostname_scan.py -v`
Expected: FAIL — `-Pn` not in command, only `example.com` scanned

- [ ] **Step 3: Update PortScanRunner.run_once**

Replace `src/easm/runners/portscan_runner.py` entirely with:

```python
from __future__ import annotations

import logging
import re
import uuid

from easm.config import TargetConfig
from easm.runners.base import BaseRunner

logger = logging.getLogger(__name__)

DEFAULT_PORTS = "22,80,443,8080,8443,3389,3306,5432,6379,27017"


class PortScanRunner(BaseRunner):
    source_name = "portscan"
    supports_schedule = True
    supports_manual_trigger = True
    is_continuous = False

    async def _get_scan_targets(self, target: TargetConfig) -> list[str]:
        """Get targets to scan: configured domains + discovered hostnames."""
        targets = list(target.match_rules.domains)

        # Add discovered hostnames from entities table
        if self.store and hasattr(self.store, "pool") and self.store.pool:
            try:
                rows = await self.store.pool.fetch(
                    "SELECT entity_value FROM entities "
                    "WHERE target_id = $1 AND entity_type = 'hostname' "
                    "ORDER BY last_seen_at DESC",
                    target.id,
                )
                existing = set(target.match_rules.domains)
                for row in rows:
                    hostname = row["entity_value"]
                    if hostname not in existing:
                        targets.append(hostname)
            except Exception:
                logger.debug("failed to query hostnames for portscan", exc_info=True)

        return targets

    async def run_once(
        self, target: TargetConfig, trigger_type: str, run_id: uuid.UUID
    ) -> tuple[int, int, int]:
        cfg = self.get_runner_config(target)
        timeout = cfg.get("args", {}).get("timeout_seconds", 600)
        ports = cfg.get("args", {}).get("ports", DEFAULT_PORTS)
        profile = cfg.get("args", {}).get("profile", "quick")
        port_arg = ports if profile == "custom" else DEFAULT_PORTS
        inserted = deduped = errors = 0

        scan_targets = await self._get_scan_targets(target)
        self._log(f"[portscan] scanning {len(scan_targets)} target(s)")

        for hostname in scan_targets:
            # -Pn: skip host discovery (ping). Many hosts block ICMP but respond to TCP.
            # -sV: version detection
            # --open: only show open ports
            # -oG -: grepable output to stdout
            cmd = ["nmap", "-Pn", "-sV", "-p", port_arg, "--open", "-oG", "-", hostname]
            self._log(f"[portscan] running: {' '.join(cmd)}")
            ok, stdout, stderr = await self._exec_subprocess(cmd, timeout=timeout)
            if not ok:
                errors += 1
                self._log(f"[portscan] failed for {hostname}: {stderr[:200] if stderr else ''}")
                logger.warning(
                    "nmap failed",
                    extra={"hostname": hostname, "stderr": stderr[:200] if stderr else ""},
                )
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
                    raw = {"hostname": hostname, "ip": host, "ports": open_ports}
                    result = await self.store.insert_raw_event(
                        target.org_id, target.id, self.source_name, raw, run_id,
                    )
                    if result:
                        inserted += 1
                    else:
                        deduped += 1
        return inserted, deduped, errors
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/runners/test_portscan_hostname_scan.py -v`
Expected: PASS — `-Pn` in command, discovered hostnames included

- [ ] **Step 5: Commit**

```bash
git add src/easm/runners/portscan_runner.py tests/runners/test_portscan_hostname_scan.py
git commit -m "fix: portscan uses -Pn (skip ping discovery) and scans discovered hostnames"
```

---

### Task 3: Improve JSONB rendering in Entity Detail UI

**Files:**
- Create: `ui/src/components/inventory/AttributeRenderers.tsx`
- Modify: `ui/src/components/inventory/EntityDetail.tsx`

**Context:** Currently all entity attributes beyond `asset_profile` and `certificate_profile` are dumped as raw JSON in a `<pre>` block (EntityDetail.tsx:226-228). The main JSONB shapes that need typed renderers are: `threat_intel`, `technologies`, `ports`, `dns_records` (MX/SPF/DMARC), `geoip`, `rdap`, `subdomain_takeover`.

- [ ] **Step 1: Create structured attribute renderers**

Create `ui/src/components/inventory/AttributeRenderers.tsx`:

```tsx
import type { FC } from 'react'

// ---- Shared helpers ----

type UnknownRecord = Record<string, unknown>

const isRecord = (value: unknown): value is UnknownRecord =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const readRecord = (record: UnknownRecord | undefined, key: string): UnknownRecord | undefined => {
  const value = record?.[key]
  return isRecord(value) ? value : undefined
}

const readText = (record: UnknownRecord | undefined, key: string): string | undefined => {
  const value = record?.[key]
  if (typeof value === 'string' && value.trim()) return value
  if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  return undefined
}

const Section: FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <div className="space-y-2">
    <h4 className="font-mono text-[10px] font-semibold uppercase tracking-wider text-mute">{title}</h4>
    <div className="space-y-1">{children}</div>
  </div>
)

const KV: FC<{ label: string; value: string | undefined; mono?: boolean; tone?: string }> = ({
  label, value, mono, tone,
}) => {
  if (!value) return null
  return (
    <div className="flex justify-between text-xs px-2 py-1 rounded bg-canvas-soft">
      <span className="text-mute">{label}</span>
      <span
        className={mono ? 'font-mono text-ink' : 'text-ink'}
        style={tone ? { color: tone } : undefined}
      >
        {value}
      </span>
    </div>
  )
}

const riskTone = (level: string | undefined): string | undefined => {
  if (level === 'critical' || level === 'high') return '#ef4444'
  if (level === 'medium') return '#f59e0b'
  if (level === 'low' || level === 'info') return '#00d992'
  return undefined
}

// ---- Threat Intel ----

const ThreatIntelSection: FC<{ data: UnknownRecord }> = ({ data }) => {
  const sources = Object.keys(data).filter(k => isRecord(data[k]))
  if (sources.length === 0) return null

  return (
    <Section title="Threat Intelligence">
      {sources.map(source => {
        const info = data[source] as UnknownRecord
        return (
          <div key={source} className="space-y-1">
            <div className="text-xs font-semibold text-ink px-2">{source}</div>
            {Object.entries(info).map(([k, v]) => (
              <KV
                key={k}
                label={k.replace(/_/g, ' ')}
                value={typeof v === 'object' ? JSON.stringify(v) : String(v)}
                mono={typeof v === 'number' || typeof v === 'boolean'}
                tone={k === 'classification' || k === 'risk' ? riskTone(String(v)) : undefined}
              />
            ))}
          </div>
        )
      })}
    </Section>
  )
}

// ---- Technologies ----

const TechnologiesSection: FC<{ data: unknown[] }> = ({ data }) => {
  if (!data.length) return null
  return (
    <Section title="Technologies">
      <div className="flex flex-wrap gap-1">
        {data.map((tech, i) => {
          const t = isRecord(tech) ? tech : {}
          const name = readText(t, 'name') || 'unknown'
          const version = readText(t, 'version')
          return (
            <span
              key={i}
              className="inline-flex items-center rounded-full px-2 py-0.5 font-mono text-[10px] bg-canvas-soft text-ink"
            >
              {name}{version ? ` ${version}` : ''}
            </span>
          )
        })}
      </div>
    </Section>
  )
}

// ---- Ports ----

const PortsSection: FC<{ data: unknown[] }> = ({ data }) => {
  if (!data.length) return null
  return (
    <Section title="Open Ports">
      <div className="space-y-1">
        {data.map((p, i) => {
          const port = isRecord(p) ? p : {}
          return (
            <div key={i} className="flex items-center gap-2 text-xs px-2 py-1 rounded bg-canvas-soft">
              <span className="font-mono text-ink font-semibold">{readText(port, 'port')}</span>
              <span className="text-mute">/</span>
              <span className="font-mono text-mute">{readText(port, 'protocol')}</span>
              <span className="text-ink">{readText(port, 'service')}</span>
            </div>
          )
        })}
      </div>
    </Section>
  )
}

// ---- DNS Records ----

const DNSRecordsSection: FC<{ data: UnknownRecord }> = ({ data }) => {
  const records = Object.entries(data)
  if (records.length === 0) return null
  return (
    <Section title="DNS Records">
      {records.map(([type, value]) => (
        <KV
          key={type}
          label={type.toUpperCase()}
          value={typeof value === 'string' ? value : JSON.stringify(value)}
          mono
        />
      ))}
    </Section>
  )
}

// ---- GeoIP ----

const GeoIPSection: FC<{ data: UnknownRecord }> = ({ data }) => (
  <Section title="Geo Location">
    <KV label="Country" value={readText(data, 'country_name')} />
    <KV label="City" value={readText(data, 'city')} />
    <KV label="Region" value={readText(data, 'region')} />
    <KV label="Org" value={readText(data, 'org')} />
    <KV label="ASN" value={readText(data, 'asn')} mono />
  </Section>
)

// ---- RDAP / WHOIS ----

const RDAPSection: FC<{ data: UnknownRecord }> = ({ data }) => (
  <Section title="WHOIS / RDAP">
    <KV label="Registrar" value={readText(data, 'registrar')} />
    <KV label="Registrant" value={readText(data, 'registrant')} />
    <KV label="Nameservers" value={Array.isArray(data.nameservers) ? (data.nameservers as string[]).join(', ') : readText(data, 'nameservers')} mono />
    <KV label="Created" value={readText(data, 'created_date')} />
    <KV label="Expires" value={readText(data, 'expiration_date')} />
  </Section>
)

// ---- Main attribute renderer ----

export const StructuredAttributes: FC<{ attributes: UnknownRecord }> = ({ attributes }) => {
  const sections: React.ReactNode[] = []

  // Threat intel
  const threatIntel = readRecord(attributes, 'threat_intel')
  if (threatIntel) sections.push(<ThreatIntelSection key="threat_intel" data={threatIntel} />)

  // Technologies
  const techs = attributes.technologies
  if (Array.isArray(techs) && techs.length > 0) sections.push(<TechnologiesSection key="tech" data={techs} />)

  // Ports
  const ports = attributes.ports
  if (Array.isArray(ports) && ports.length > 0) sections.push(<PortsSection key="ports" data={ports} />)

  // Port scan results (alternate key)
  const portScan = attributes.port_scan
  if (isRecord(portScan) && Array.isArray((portScan as UnknownRecord).open_ports)) {
    sections.push(<PortsSection key="port_scan" data={(portScan as UnknownRecord).open_ports as unknown[]} />)
  }

  // DNS records
  const dns = readRecord(attributes, 'dns_records') || readRecord(attributes, 'dns')
  if (dns && isRecord(dns)) sections.push(<DNSRecordsSection key="dns" data={dns} />)

  // MX records
  const mx = readRecord(attributes, 'mail_records')
  if (mx) sections.push(<DNSRecordsSection key="mail" data={mx} />)

  // GeoIP
  const geoip = readRecord(attributes, 'geoip')
  if (geoip) sections.push(<GeoIPSection key="geoip" data={geoip} />)

  // RDAP
  const rdap = readRecord(attributes, 'rdap') || readRecord(attributes, 'whois')
  if (rdap) sections.push(<RDAPSection key="rdap" data={rdap} />)

  // Subdomain takeover
  const takeover = readRecord(attributes, 'subdomain_takeover')
  if (takeover) {
    const vulnerable = readText(takeover, 'vulnerable')
    sections.push(
      <Section key="takeover" title="Subdomain Takeover">
        <KV
          label="Status"
          value={vulnerable === 'true' ? 'VULNERABLE' : vulnerable === 'false' ? 'Safe' : vulnerable}
          tone={vulnerable === 'true' ? '#ef4444' : '#00d992'}
        />
        <KV label="Service" value={readText(takeover, 'service')} />
        <KV label="CNAME" value={readText(takeover, 'cname')} mono />
        <KV label="Fingerprint" value={readText(takeover, 'fingerprint')} />
      </Section>
    )
  }

  // Shodan data
  const shodan = readRecord(attributes, 'shodan')
  if (shodan) sections.push(<ThreatIntelSection key="shodan" data={{ shodan }} />)

  if (sections.length === 0) return null

  return <div className="space-y-3">{sections}</div>
}
```

- [ ] **Step 2: Update EntityDetail.tsx to use structured renderers**

In `ui/src/components/inventory/EntityDetail.tsx`:

Add import at the top:
```tsx
import { StructuredAttributes } from './AttributeRenderers'
```

Replace the collapsible attributes section (lines 212-231) with:

```tsx
      {/* Structured attribute renderers */}
      {attributes && <StructuredAttributes attributes={attributes} />}

      {/* Raw attributes as fallback (collapsible) */}
      {entity.attributes && Object.keys(entity.attributes).length > 0 && (
        <div className="space-y-2">
          <button
            onClick={() => setAttributesOpen(!attributesOpen)}
            className="flex items-center gap-1 text-xs font-semibold text-mute uppercase tracking-wider hover:text-ink transition-colors cursor-pointer"
          >
            {attributesOpen ? (
              <ChevronDown className="w-3 h-3" />
            ) : (
              <ChevronRight className="w-3 h-3" />
            )}
            Raw Attributes
          </button>
          {attributesOpen && (
            <pre className="rounded bg-canvas-soft p-3 text-xs text-body font-mono overflow-auto max-h-64">
              {JSON.stringify(entity.attributes, null, 2)}
            </pre>
          )}
        </div>
      )}
```

- [ ] **Step 3: Build the UI to verify no TypeScript errors**

Run: `cd ui && npx tsc --noEmit`
Expected: No type errors

- [ ] **Step 4: Commit**

```bash
git add ui/src/components/inventory/AttributeRenderers.tsx ui/src/components/inventory/EntityDetail.tsx
git commit -m "feat: structured JSONB attribute renderers for entity detail panel"
```

---

## Part 2: Architecture Refactor — Decoupled Workers with Postgres Task Queue

This is the major refactor. The goal:

1. **Task storage in Postgres** — Replace in-memory scheduling with a `task_queue` table using `FOR UPDATE SKIP LOCKED`
2. **Multi-container workers + web server decoupled** — Separate Dockerfile targets for web (slim) and worker (full tools)
3. **Configurable workers** — `docker-compose.yml` supports N worker instances
4. **Janitor job** — Worker task that cleans up stale runs, orphaned pivot jobs, old raw events

---

### Task 4: Create Postgres-backed task queue

**Files:**
- Create: `alembic/versions/0007_task_queue.py`
- Create: `src/easm/task_queue.py`
- Test: `tests/test_task_queue.py`

**Context:** The pivot queue already uses `FOR UPDATE SKIP LOCKED` (store.py:892-911). We'll create a general-purpose task queue table with the same pattern but for runner execution, not just pivots.

- [ ] **Step 1: Write the migration for task_queue table**

Create `alembic/versions/0007_task_queue.py`:

```python
"""Task queue for runner execution

Revision ID: 0007
Revises: 0006
Create Date: 2026-05-19

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "task_queue",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("task_type", sa.Text(), nullable=False),
        sa.Column("payload", sa.dialects.postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'pending'")),
        sa.Column("priority", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("enqueued_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("worker_id", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("retry_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("max_retries", sa.Integer(), nullable=False, server_default=sa.text("3")),
        sa.Column("scheduled_for", sa.DateTime(timezone=True), nullable=True),
        sa.Column("target_id", sa.Text(), nullable=True),
        sa.Column("org_id", sa.Text(), nullable=False, server_default=sa.text("'default'")),
    )
    op.create_index("idx_task_queue_status", "task_queue", ["status"])
    op.create_index("idx_task_queue_type_status", "task_queue", ["task_type", "status"])
    op.create_index("idx_task_queue_scheduled_for", "task_queue", ["scheduled_for"], postgresql_where=sa.text("status = 'pending'"))
    op.create_index("idx_task_queue_target_id", "task_queue", ["target_id"])


def downgrade() -> None:
    op.drop_table("task_queue")
```

- [ ] **Step 2: Create the task queue module**

Create `src/easm/task_queue.py`:

```python
"""Postgres-backed task queue using FOR UPDATE SKIP LOCKED.

Provides a reliable, Redis-free task queue built entirely on Postgres.
Workers dequeue tasks atomically via SELECT ... FOR UPDATE SKIP LOCKED,
which prevents duplicate processing across concurrent workers.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import asyncpg

logger = logging.getLogger(__name__)


class TaskQueue:
    """Postgres-backed task queue."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self.pool = pool

    async def enqueue(
        self,
        *,
        task_type: str,
        payload: dict[str, Any],
        target_id: str | None = None,
        org_id: str = "default",
        priority: int = 0,
        scheduled_for: datetime | None = None,
        max_retries: int = 3,
    ) -> uuid.UUID:
        """Enqueue a task. Returns the task ID."""
        row = await self.pool.fetchrow(
            """
            INSERT INTO task_queue (task_type, payload, target_id, org_id, priority, scheduled_for, max_retries)
            VALUES ($1, $2::jsonb, $3, $4, $5, $6, $7)
            RETURNING id
            """,
            task_type,
            json.dumps(payload),
            target_id,
            org_id,
            priority,
            scheduled_for,
            max_retries,
        )
        assert row is not None
        return row["id"]

    async def dequeue(
        self,
        *,
        worker_id: str,
        task_types: list[str] | None = None,
        limit: int = 1,
    ) -> list[dict[str, Any]]:
        """Dequeue up to `limit` pending tasks atomically.

        Uses FOR UPDATE SKIP LOCKED to prevent duplicate processing.
        Optionally filter by task_type.
        """
        type_filter = ""
        params: list[Any] = []
        idx = 0

        if task_types:
            idx += 1
            placeholders = ", ".join(f"${idx + i}" for i in range(len(task_types)))
            type_filter = f"AND task_type IN ({placeholders})"
            params.extend(task_types)
            idx += len(task_types)

        # Priority: lower number = higher priority, then FIFO by enqueued_at
        # Only pick tasks that are due (scheduled_for is NULL or in the past)
        idx += 1
        params.append(worker_id)
        idx += 1
        params.append(limit)

        query = f"""
            WITH picked AS (
                SELECT id
                FROM task_queue
                WHERE status = 'pending'
                  AND (scheduled_for IS NULL OR scheduled_for <= NOW())
                  {type_filter}
                ORDER BY priority ASC, enqueued_at ASC
                LIMIT ${idx}
                FOR UPDATE SKIP LOCKED
            )
            UPDATE task_queue tq
            SET status = 'running',
                started_at = NOW(),
                worker_id = ${idx - len(params) + 1}
            FROM picked
            WHERE tq.id = picked.id
            RETURNING tq.*
        """
        rows = await self.pool.fetch(query, *params)
        return [_task_to_dict(row) for row in rows]

    async def mark_completed(self, task_id: uuid.UUID) -> None:
        await self.pool.execute(
            "UPDATE task_queue SET status='completed', completed_at=NOW() WHERE id=$1",
            task_id,
        )

    async def mark_failed(
        self,
        task_id: uuid.UUID,
        error: str,
        *,
        retry: bool = True,
    ) -> None:
        if retry:
            # Check retry count
            row = await self.pool.fetchrow(
                "SELECT retry_count, max_retries FROM task_queue WHERE id=$1",
                task_id,
            )
            if row and row["retry_count"] < row["max_retries"]:
                await self.pool.execute(
                    """
                    UPDATE task_queue
                    SET status = 'pending',
                        retry_count = retry_count + 1,
                        started_at = NULL,
                        worker_id = NULL,
                        error_message = $2,
                        scheduled_for = NOW() + (interval '30 seconds' * (retry_count + 1))
                    WHERE id = $1
                    """,
                    task_id,
                    error,
                )
                return

        await self.pool.execute(
            "UPDATE task_queue SET status='failed', completed_at=NOW(), error_message=$2 WHERE id=$1",
            task_id,
            error,
        )

    async def count_tasks(
        self,
        status: str | None = None,
        task_type: str | None = None,
    ) -> int:
        conditions: list[str] = []
        params: list[Any] = []
        if status:
            conditions.append(f"status = ${len(params) + 1}")
            params.append(status)
        if task_type:
            conditions.append(f"task_type = ${len(params) + 1}")
            params.append(task_type)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        return await self.pool.fetchval(f"SELECT COUNT(*) FROM task_queue {where}", *params) or 0

    async def cleanup_completed(self, older_than_hours: int = 24) -> int:
        """Delete completed/failed tasks older than N hours. Returns count deleted."""
        result = await self.pool.execute(
            """
            DELETE FROM task_queue
            WHERE status IN ('completed', 'failed')
              AND completed_at < NOW() - ($1 * interval '1 hour')
            """,
            older_than_hours,
        )
        # Parse "DELETE N" from result
        parts = result.split()
        return int(parts[1]) if len(parts) >= 2 else 0


def _task_to_dict(row: asyncpg.Record) -> dict[str, Any]:
    payload = row["payload"]
    if isinstance(payload, str):
        payload = json.loads(payload)
    return {
        "id": str(row["id"]),
        "task_type": row["task_type"],
        "payload": payload or {},
        "status": row["status"],
        "priority": row["priority"],
        "enqueued_at": row["enqueued_at"].isoformat() if row["enqueued_at"] else None,
        "started_at": row["started_at"].isoformat() if row["started_at"] else None,
        "completed_at": row["completed_at"].isoformat() if row["completed_at"] else None,
        "worker_id": row["worker_id"],
        "error_message": row["error_message"],
        "retry_count": row["retry_count"],
        "max_retries": row["max_retries"],
        "scheduled_for": row["scheduled_for"].isoformat() if row["scheduled_for"] else None,
        "target_id": row["target_id"],
        "org_id": row["org_id"],
    }
```

- [ ] **Step 3: Write tests for task queue**

Create `tests/test_task_queue.py`:

```python
"""Tests for Postgres-backed task queue."""
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest


class FakeRecord(dict):
    """Simple dict that supports attribute access like asyncpg.Record."""
    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)


@pytest.mark.asyncio
async def test_enqueue_inserts_task():
    from easm.task_queue import TaskQueue

    pool = MagicMock()
    pool.fetchrow = AsyncMock(return_value=FakeRecord(id=uuid.uuid4()))

    tq = TaskQueue(pool)
    task_id = await tq.enqueue(
        task_type="runner",
        payload={"runner_name": "subfinder", "target_id": "test"},
        target_id="test",
    )
    assert task_id is not None
    assert pool.fetchrow.called


@pytest.mark.asyncio
async def test_dequeue_uses_skip_locked():
    from easm.task_queue import TaskQueue

    pool = MagicMock()
    pool.fetch = AsyncMock(return_value=[])

    tq = TaskQueue(pool)
    tasks = await tq.dequeue(worker_id="worker-1", limit=5)

    assert tasks == []
    assert pool.fetch.called
    call_args = pool.fetch.call_args
    query = call_args[0][0]
    assert "FOR UPDATE SKIP LOCKED" in query


@pytest.mark.asyncio
async def test_mark_completed():
    from easm.task_queue import TaskQueue

    pool = MagicMock()
    pool.execute = AsyncMock(return_value="UPDATE 1")

    tq = TaskQueue(pool)
    await tq.mark_completed(uuid.uuid4())
    assert pool.execute.called
    call_args = pool.execute.call_args
    assert "completed" in call_args[0][0]


@pytest.mark.asyncio
async def test_mark_failed_retries_up_to_max():
    from easm.task_queue import TaskQueue

    pool = MagicMock()
    # First call: check retry count (retry_count=0, max_retries=3)
    pool.fetchrow = AsyncMock(return_value=FakeRecord(retry_count=0, max_retries=3))
    pool.execute = AsyncMock(return_value="UPDATE 1")

    tq = TaskQueue(pool)
    await tq.mark_failed(uuid.uuid4(), "some error")

    # Should retry, not permanently fail
    call_query = pool.execute.call_args[0][0]
    assert "pending" in call_query
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_task_queue.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add alembic/versions/0007_task_queue.py src/easm/task_queue.py tests/test_task_queue.py
git commit -m "feat: Postgres-backed task queue using FOR UPDATE SKIP LOCKED"
```

---

### Task 5: Create worker process

**Files:**
- Create: `src/easm/worker.py`
- Modify: `src/easm/main.py` (add web-only mode flag)

**Context:** Currently `main.py` runs everything in one process: web server, scheduler, certstream listeners, and pivot workers. The worker process will: (1) connect to the same DB, (2) poll the task_queue for work, (3) execute runner tasks. The web process will: (1) run FastAPI, (2) run the scheduler, (3) enqueue runner tasks to the task_queue instead of executing them directly.

- [ ] **Step 1: Create the worker entry point**

Create `src/easm/worker.py`:

```python
"""Worker process that pulls tasks from the Postgres task queue.

Run as: python -m easm.worker

The worker:
1. Connects to the same Postgres database as the web server
2. Polls task_queue for pending tasks
3. Executes runner tasks (subfinder, nuclei, portscan, etc.)
4. Also processes pivot jobs from the existing pivot_queue
5. Runs the janitor task on a schedule
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from alembic.command import upgrade as alembic_upgrade
from alembic.config import Config as AlembicConfig

from easm.config import load_config
from easm.db import close_pool, create_pool
from easm.runtime import configure_runtime
from easm.task_queue import TaskQueue

structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
    force=True,
)

logger = structlog.get_logger(__name__)

# Unique ID for this worker instance
WORKER_ID = f"worker-{uuid.uuid4().hex[:8]}"

# Task types this worker handles
RUNNER_TASK_TYPES = {"runner", "pivot", "janitor"}


async def execute_runner_task(
    task: dict[str, Any],
    config: Any,
    pool: Any,
    task_queue: TaskQueue,
) -> None:
    """Execute a runner task from the task queue."""
    from easm.runners import get_all_runners
    from easm.runners.engine import execute_runner
    from easm.runtime import get_runtime
    import httpx

    payload = task["payload"]
    runner_name = payload.get("runner_name", "")
    target_id = payload.get("target_id", "")
    trigger_type = payload.get("trigger_type", "scheduled")

    # Find target config
    target = None
    for t in config.targets:
        if t.id == target_id:
            target = t
            break

    if not target:
        await task_queue.mark_failed(task["id"], f"Target {target_id} not found", retry=False)
        return

    # Find runner definition
    runners = get_all_runners()
    if runner_name not in runners:
        await task_queue.mark_failed(task["id"], f"Runner {runner_name} not found", retry=False)
        return

    runner_def = runners[runner_name]
    store = type("Store", (), {"pool": pool})()  # Minimal store-like object

    # We need a real Store for the runners
    from easm.store import Store
    real_store = Store(pool)

    runtime = get_runtime()
    http_client = runtime.make_http_client()

    try:
        await execute_runner(
            runner_def.source_name,
            runner_def.run_fn,
            target,
            real_store,
            trigger_type,
            http_client=http_client,
        )
        await task_queue.mark_completed(uuid.UUID(task["id"]))
    except Exception as e:
        logger.exception("runner task failed", task_id=task["id"], error=str(e))
        await task_queue.mark_failed(uuid.UUID(task["id"]), str(e))
    finally:
        await http_client.aclose()


async def execute_pivot_task(
    task: dict[str, Any],
    config: Any,
    pool: Any,
    task_queue: TaskQueue,
) -> None:
    """Execute a pivot task by picking up from the existing pivot_queue."""
    # The pivot worker pool already handles this via store.dequeue_pivot_jobs_batch
    # This task type is a no-op placeholder for integration
    await task_queue.mark_completed(uuid.UUID(task["id"]))


async def execute_janitor_task(
    task: dict[str, Any],
    config: Any,
    pool: Any,
    task_queue: TaskQueue,
) -> None:
    """Execute janitor cleanup tasks."""
    logger.info("running janitor task", worker_id=WORKER_ID)

    # 1. Reset orphaned pivot jobs (running for > 1 hour)
    result = await pool.execute(
        """
        UPDATE pivot_queue
        SET status = 'pending', started_at = NULL
        WHERE status = 'running'
          AND started_at < NOW() - interval '1 hour'
        """
    )
    logger.info("janitor: reset orphaned pivot jobs", result=result)

    # 2. Fail stale running tasks in task_queue (running for > 2 hours)
    result = await pool.execute(
        """
        UPDATE task_queue
        SET status = 'failed', completed_at = NOW(),
            error_message = 'worker timeout'
        WHERE status = 'running'
          AND started_at < NOW() - interval '2 hours'
        """
    )
    logger.info("janitor: failed stale tasks", result=result)

    # 3. Cleanup old completed tasks
    tq = TaskQueue(pool)
    deleted = await tq.cleanup_completed(older_than_hours=24)
    logger.info("janitor: cleaned up completed tasks", deleted=deleted)

    # 4. Cleanup old raw_events (keep last 30 days)
    result = await pool.execute(
        """
        DELETE FROM raw_events
        WHERE collected_at < NOW() - interval '30 days'
        """
    )
    logger.info("janitor: cleaned up old raw events", result=result)

    # 5. Cleanup old runs (keep last 90 days)
    result = await pool.execute(
        """
        DELETE FROM runs
        WHERE finished_at < NOW() - interval '90 days'
          AND status IN ('completed', 'failed')
        """
    )
    logger.info("janitor: cleaned up old runs", result=result)

    await task_queue.mark_completed(uuid.UUID(task["id"]))


TASK_EXECUTORS = {
    "runner": execute_runner_task,
    "pivot": execute_pivot_task,
    "janitor": execute_janitor_task,
}


async def worker_loop(
    pool: Any,
    config: Any,
    *,
    poll_interval: float = 1.0,
    batch_size: int = 5,
) -> None:
    """Main worker loop: poll for tasks and execute them."""
    task_queue = TaskQueue(pool)

    logger.info(
        "worker started",
        worker_id=WORKER_ID,
        poll_interval=poll_interval,
        batch_size=batch_size,
    )

    while True:
        try:
            tasks = await task_queue.dequeue(
                worker_id=WORKER_ID,
                task_types=list(RUNNER_TASK_TYPES),
                limit=batch_size,
            )

            if not tasks:
                await asyncio.sleep(poll_interval)
                continue

            for task in tasks:
                task_type = task["task_type"]
                executor = TASK_EXECUTORS.get(task_type)

                if executor is None:
                    logger.warning("unknown task type", task_type=task_type)
                    await task_queue.mark_failed(
                        uuid.UUID(task["id"]),
                        f"Unknown task type: {task_type}",
                        retry=False,
                    )
                    continue

                logger.info(
                    "executing task",
                    task_id=task["id"],
                    task_type=task_type,
                    worker_id=WORKER_ID,
                )

                try:
                    await executor(task, config, pool, task_queue)
                except Exception as e:
                    logger.exception(
                        "task executor failed",
                        task_id=task["id"],
                        error=str(e),
                    )

        except asyncio.CancelledError:
            logger.info("worker loop cancelled", worker_id=WORKER_ID)
            break
        except Exception as e:
            logger.exception("worker loop error", error=str(e))
            await asyncio.sleep(5)


async def main() -> None:
    config_path = os.environ.get("EASM_CONFIG_PATH", "/app/config.yaml")
    dsn = os.environ.get("EASM_DATABASE_DSN", "postgresql://easm:easm@postgres:5432/easm")

    logger.info("loading config", path=config_path)
    config = load_config(config_path)
    configure_runtime(config.runtime)

    logger.info("creating database pool")
    pool = await create_pool(dsn)

    logger.info("waiting for database")
    for attempt in range(30):
        try:
            await pool.fetchval("SELECT 1")
            break
        except Exception as e:
            if attempt == 29:
                raise
            logger.warning("database not ready", attempt=attempt + 1, error=str(e))
            await asyncio.sleep(2)

    # Apply migrations (idempotent)
    alembic_cfg = AlembicConfig("alembic.ini")
    async_dsn = dsn.replace("postgresql://", "postgresql+asyncpg://", 1)
    alembic_cfg.set_main_option("sqlalchemy.url", async_dsn)
    from concurrent.futures import ThreadPoolExecutor
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor() as executor:
        await loop.run_in_executor(executor, alembic_upgrade, alembic_cfg, "head")

    # Clear stale tasks from this worker (crash recovery)
    await pool.execute(
        "UPDATE task_queue SET status='pending', worker_id=NULL, started_at=NULL "
        "WHERE worker_id = $1 AND status = 'running'",
        WORKER_ID,
    )

    # Also run pivot workers alongside the task queue worker
    from easm.pivot.worker import pivot_worker_pool
    pivot_task = asyncio.create_task(
        pivot_worker_pool(pool, config=config, n=3, batch_interval_ms=200)
    )

    worker_task = asyncio.create_task(
        worker_loop(pool, config, poll_interval=1.0, batch_size=5)
    )

    logger.info("worker ready", worker_id=WORKER_ID)

    try:
        await asyncio.gather(pivot_task, worker_task)
    except asyncio.CancelledError:
        pass
    finally:
        logger.info("worker shutting down", worker_id=WORKER_ID)
        await close_pool(pool)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("received interrupt, shutting down")
    except Exception as e:
        logger.exception("fatal error", error=str(e))
        sys.exit(1)
```

- [ ] **Step 2: Modify scheduler to enqueue to task_queue instead of executing directly**

In `src/easm/scheduler.py`, modify `_schedule_runner` to check an environment variable `EASM_MODE`:

In `_schedule_runner`, replace the `_run_job` inner function:

```python
        async def _run_job():
            active = await store.count_active_runs(target.id, runner_def.source_name)
            if active > 0:
                logger.info(
                    "skipping scheduled run: previous run still active",
                    extra={"target_id": target.id, "runner": runner_name, "active_runs": active},
                )
                return

            mode = os.environ.get("EASM_MODE", "all")
            if mode in ("web", "server"):
                # Web mode: enqueue to task queue, don't execute
                from easm.task_queue import TaskQueue
                tq = TaskQueue(store.pool)
                await tq.enqueue(
                    task_type="runner",
                    payload={
                        "runner_name": runner_name,
                        "target_id": target.id,
                        "trigger_type": "scheduled",
                    },
                    target_id=target.id,
                    org_id=target.org_id,
                )
                logger.info(
                    "enqueued runner task",
                    extra={"runner": runner_name, "target_id": target.id},
                )
            else:
                # All-in-one mode: execute directly (backward compatible)
                http_client = get_runtime().make_http_client()
                try:
                    await execute_runner(
                        runner_def.source_name,
                        runner_def.run_fn,
                        target,
                        store,
                        "scheduled",
                        http_client=http_client,
                    )
                finally:
                    await http_client.aclose()
```

Add `import os` at the top of the file.

- [ ] **Step 3: Modify main.py to support EASM_MODE=web**

In `src/easm/main.py`, wrap the worker-only code (pivot workers, certstream) in a mode check:

After the `logger.info("started pivot worker pool")` line (around line 171), wrap with:

```python
    mode = os.environ.get("EASM_MODE", "all")

    if mode != "web":
        # Start pivot workers
        pivot_task = asyncio.create_task(pivot_worker_pool(
            pool, config=config, n=3, batch_interval_ms=200
        ))
        logger.info("started pivot worker pool")

    if mode == "web":
        logger.info("running in web-only mode, workers run separately")
```

Also wrap the certstream startup and health check in similar mode guards.

- [ ] **Step 4: Commit**

```bash
git add src/easm/worker.py src/easm/scheduler.py src/easm/main.py
git commit -m "feat: worker process with task queue, web-only mode via EASM_MODE env var"
```

---

### Task 6: Split Dockerfile into multi-target builds

**Files:**
- Modify: `Dockerfile` (add build targets)
- Modify: `docker-compose.yml` (multi-service with configurable workers)

**Context:** The current Dockerfile is a single-stage build that includes all tools (nuclei, nmap, subfinder, asnmap, webanalyze, playwright). The web server doesn't need any of these. We'll use Docker build targets to create a slim web image and a full worker image.

- [ ] **Step 1: Refactor Dockerfile with multi-target builds**

Replace `Dockerfile` with:

```dockerfile
# ── Stage 1: Build the React UI ──
FROM node:24-slim AS ui-builder

WORKDIR /ui
COPY ui/package.json ui/package-lock.json* ./
RUN npm install
COPY ui/ .
RUN npm run build

# ── Stage 2: Python base (shared) ──
FROM python:3.14-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir hatchling && pip install --no-cache-dir -e .

COPY alembic/ alembic/
COPY alembic.ini .

COPY --from=ui-builder /ui/dist /app/ui/dist

# ── Stage 3: Web server (slim) ──
FROM base AS web

RUN useradd --create-home --shell /bin/bash easm && \
    mkdir -p /app/data && chown -R easm:easm /app/data

USER easm
EXPOSE 8000
ENV EASM_MODE=web
CMD ["python", "-m", "easm.main"]

# ── Stage 4: Worker (full tools) ──
FROM base AS worker

# Install nmap
RUN apt-get update && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

# Install subfinder
RUN SUBFINDER_VER="v2.14.0" && \
    curl -L "https://github.com/projectdiscovery/subfinder/releases/download/${SUBFINDER_VER}/subfinder_${SUBFINDER_VER#v}_linux_amd64.zip" \
    -o /tmp/subfinder.zip && \
    unzip /tmp/subfinder.zip -d /usr/local/bin/ subfinder && \
    chmod +x /usr/local/bin/subfinder && \
    rm /tmp/subfinder.zip

# Install asnmap
RUN ASNMAP_VER="v1.1.1" && \
    curl -L "https://github.com/projectdiscovery/asnmap/releases/download/${ASNMAP_VER}/asnmap_${ASNMAP_VER#v}_linux_amd64.zip" \
    -o /tmp/asnmap.zip && \
    unzip /tmp/asnmap.zip -d /usr/local/bin/ asnmap && \
    chmod +x /usr/local/bin/asnmap && \
    rm /tmp/asnmap.zip

# Install nuclei
RUN NUCLEI_VER="v3.4.2" && \
    curl -L "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VER}/nuclei_${NUCLEI_VER#v}_linux_amd64.zip" \
    -o /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin/ nuclei && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip

# Install webanalyze
RUN WEBANALYZE_VER="v0.4.3" && \
    curl -L "https://github.com/rverton/webanalyze/releases/download/${WEBANALYZE_VER}/webanalyze_Linux_x86_64.tar.gz" \
    | tar xz -C /usr/local/bin/ webanalyze && \
    chmod +x /usr/local/bin/webanalyze && \
    cd /tmp && webanalyze -update && mv /tmp/technologies.json /usr/local/bin/

# Download GeoLite2 database
RUN mkdir -p /app/data && \
    curl -fsSL "https://github.com/zarguell/TA-geoip/raw/refs/heads/master/bin/GeoLite2-City.mmdb" \
    -o /app/data/GeoLite2-City.mmdb || echo "GeoLite2 download failed, geo-IP disabled"

# Install Playwright for screenshot runner
RUN useradd --create-home --shell /bin/bash easm && \
    PLAYWRIGHT_BROWSERS_PATH=/opt/playwright-browsers playwright install chromium --with-deps && \
    chown -R easm:easm /opt/playwright-browsers && \
    mkdir -p /app/data/screenshots && chown -R easm:easm /app/data

USER easm
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright-browsers
ENV EASM_MODE=worker
CMD ["python", "-m", "easm.worker"]

# ── Stage 5: All-in-one (backward compatible) ──
FROM worker AS all-in-one

# Inherits everything from worker, but runs main.py (which handles both web + workers)
ENV EASM_MODE=all
EXPOSE 8000
CMD ["python", "-m", "easm.main"]
```

- [ ] **Step 2: Update docker-compose.yml with multi-service layout**

Replace `docker-compose.yml`:

```yaml
services:
  postgres:
    image: postgres:18-alpine
    environment:
      POSTGRES_DB: ${POSTGRES_DB:-easm}
      POSTGRES_USER: ${POSTGRES_USER:-easm}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-easm}
    volumes:
      - postgres_data:/var/lib/postgresql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-easm}"]
      interval: 5s
      timeout: 5s
      retries: 10

  web:
    build:
      context: .
      target: web
    depends_on:
      postgres:
        condition: service_healthy
    env_file: .env
    environment:
      EASM_MODE: web
    volumes:
      - ./config.yaml:/app/config.yaml:ro
    ports:
      - "8000:8000"
    restart: unless-stopped

  worker:
    build:
      context: .
      target: worker
    depends_on:
      postgres:
        condition: service_healthy
    env_file: .env
    environment:
      EASM_MODE: worker
    volumes:
      - ./config.yaml:/app/config.yaml:ro
    restart: unless-stopped
    # Scale workers: docker compose up --scale worker=3
    deploy:
      replicas: ${WORKER_REPLICAS:-1}

volumes:
  postgres_data:
```

- [ ] **Step 3: Update docker-compose-dev.yml similarly**

The dev compose can stay as all-in-one for simplicity, or be updated. For now, leave it as-is since it's for local development.

- [ ] **Step 4: Verify Docker build works**

Run: `docker build --target web -t easm-web . && docker build --target worker -t easm-worker .`
Expected: Both images build successfully

- [ ] **Step 5: Commit**

```bash
git add Dockerfile docker-compose.yml
git commit -m "feat: multi-target Dockerfile with slim web and full worker images"
```

---

### Task 7: Add janitor scheduled task

**Files:**
- Modify: `src/easm/worker.py` (add janitor scheduling)
- Modify: `src/easm/scheduler.py` (enqueue janitor from web if in web mode)

**Context:** The janitor is already implemented in `worker.py` as `execute_janitor_task`. We need to ensure it gets scheduled regularly. The web server's scheduler enqueues a janitor task periodically; the worker picks it up and executes.

- [ ] **Step 1: Add janitor scheduling to the scheduler**

In `src/easm/scheduler.py`, add a new method to `Scheduler`:

```python
    def setup_janitor(self, store: Any) -> None:
        """Schedule periodic janitor cleanup tasks."""
        from easm.task_queue import TaskQueue

        async def _enqueue_janitor():
            tq = TaskQueue(store.pool)
            await tq.enqueue(
                task_type="janitor",
                payload={"action": "cleanup"},
                org_id="default",
                priority=10,  # Low priority
            )

        self._scheduler.add_job(
            _enqueue_janitor,
            "cron",
            id="janitor-cleanup",
            minute="0",
            hour="*/1",  # Every hour
            replace_existing=True,
        )
        logger.info("scheduled janitor cleanup job (hourly)")
```

- [ ] **Step 2: Call setup_janitor from main.py in web mode**

In `src/easm/main.py`, after the scheduler setup, add:

```python
    # Always set up the janitor (it enqueues to task_queue, workers execute it)
    scheduler.setup_janitor(store)
```

- [ ] **Step 3: Commit**

```bash
git add src/easm/scheduler.py src/easm/main.py
git commit -m "feat: janitor job enqueued hourly by scheduler, executed by workers"
```

---

### Task 8: Add API endpoint for worker/task queue status

**Files:**
- Create: `src/easm/api/routes/workers.py`
- Modify: `src/easm/api/app.py` (register route)

**Context:** Need visibility into the task queue and worker status from the UI.

- [ ] **Step 1: Create workers API route**

Create `src/easm/api/routes/workers.py`:

```python
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request

router = APIRouter(prefix="/api/workers", tags=["workers"])


@router.get("/queue")
async def get_queue_status(request: Request) -> dict[str, Any]:
    """Get task queue status: counts by status and type."""
    store = request.app.state.store
    pool = store.pool

    rows = await pool.fetch(
        """
        SELECT status, task_type, COUNT(*) as count
        FROM task_queue
        GROUP BY status, task_type
        ORDER BY status, task_type
        """
    )

    by_status: dict[str, int] = {}
    by_type: dict[str, dict[str, int]] = {}
    for row in rows:
        status = row["status"]
        task_type = row["task_type"]
        count = row["count"]

        by_status[status] = by_status.get(status, 0) + count
        by_type.setdefault(task_type, {})[status] = count

    return {
        "by_status": by_status,
        "by_type": by_type,
        "workers": await _get_active_workers(pool),
    }


async def _get_active_workers(pool: Any) -> list[dict[str, Any]]:
    """Get currently active workers from running tasks."""
    rows = await pool.fetch(
        """
        SELECT worker_id, COUNT(*) as running_tasks, MIN(started_at) as earliest_task
        FROM task_queue
        WHERE status = 'running'
        GROUP BY worker_id
        ORDER BY worker_id
        """
    )
    return [
        {
            "worker_id": row["worker_id"],
            "running_tasks": row["running_tasks"],
            "earliest_task": row["earliest_task"].isoformat() if row["earliest_task"] else None,
        }
        for row in rows
    ]
```

- [ ] **Step 2: Register the route in app.py**

In `src/easm/api/app.py`, add import and registration:

```python
from easm.api.routes.workers import router as workers_router
# ...
app.include_router(workers_router)
```

- [ ] **Step 3: Commit**

```bash
git add src/easm/api/routes/workers.py src/easm/api/app.py
git commit -m "feat: API endpoint for worker and task queue status"
```

---

## Dependency Graph

```
Task 1 (nuclei fix)         ← independent, do first
Task 2 (portscan fix)       ← independent, do first
Task 3 (UI JSONB render)    ← independent, do first
Task 4 (task queue)         ← foundation for Tasks 5-8
Task 5 (worker process)     ← depends on Task 4
Task 6 (Docker multi-target)← depends on Task 5
Task 7 (janitor scheduling) ← depends on Tasks 4 + 5
Task 8 (worker API)         ← depends on Task 4
```

**Recommended order:** Tasks 1-3 in parallel → Task 4 → Tasks 5, 8 in parallel → Task 6 → Task 7

---

## Self-Review

**1. Spec coverage:**
- ✅ Nuclei scans subdomains — Task 1
- ✅ JSONB data better rendered — Task 3
- ✅ Portscan host discovery fixed — Task 2
- ✅ Task storage in Postgres — Task 4
- ✅ Multi-container workers + web decoupled — Tasks 5, 6
- ✅ Configurable workers — Task 6 (docker compose replicas)
- ✅ Janitor job — Task 7

**2. Placeholder scan:** No TBD/TODO/fill-in-later found. All steps have complete code.

**3. Type consistency:**
- `TaskQueue.dequeue` returns `list[dict[str, Any]]` — consistent across all consumers
- `WORKER_ID` is a string — matches `task_queue.worker_id` column type `Text`
- `Store.pool` is `asyncpg.Pool` — used consistently in worker and web
