from __future__ import annotations

import asyncio
import json
import logging
import random
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Awaitable, Callable

import httpx
import tldextract

from easm.models import RunStatus
from easm.runtime import get_runtime

if TYPE_CHECKING:
    from easm.store import Store

logger = logging.getLogger(__name__)


def get_runner_config(target: Any, source_name: str) -> dict[str, Any]:
    """Get runner-specific config dict from a target's runners config.

    Mirrors ``BaseRunner.get_runner_config()``.
    """
    cfg = target.runners.get(source_name) if hasattr(target, "runners") else None
    if cfg is None:
        return {}
    return cfg.model_dump() if hasattr(cfg, "model_dump") else {}


def iterate_domains_x2(target: Any) -> list[str]:
    """Produce ``https://<domain>`` and ``http://<domain>`` for every domain.

    Used by nuclei and wappalyzer which scan both schemes.
    """
    items: list[str] = []
    for domain in target.match_rules.domains:
        items.append(f"https://{domain}")
        items.append(f"http://{domain}")
    return items


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
            existing: set[str] = set()
            for domain in target.match_rules.domains:
                existing.add(f"https://{domain}")
                existing.add(f"http://{domain}")
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


# ---------------------------------------------------------------------------
# Subprocess execution
# ---------------------------------------------------------------------------

async def exec_subprocess(
    cmd: list[str],
    *,
    timeout: int = 300,
    logger_fn: Callable[[str], None] | None = None,
) -> tuple[bool, str, str]:
    """Execute a subprocess and return ``(ok, stdout, stderr)``.

    Mirrors ``BaseRunner._exec_subprocess()`` exactly.
    ``logger_fn`` is called for each stdout/stderr line to allow log
    collection by the caller.
    """
    if logger_fn is None:
        logger_fn = lambda _: None
    runtime = get_runtime()
    if runtime.is_simulation or not runtime.config.allow_subprocess:
        return await runtime.exec_subprocess(cmd, timeout=timeout, logger_fn=logger_fn)
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
        logger_fn("[stderr] timeout")
        return False, "", "timeout"
    stdout_text = stdout.decode(errors="replace")
    stderr_text = stderr.decode(errors="replace")
    for line in stdout_text.splitlines():
        logger_fn(f"[stdout] {line}")
    for line in stderr_text.splitlines():
        logger_fn(f"[stderr] {line}")
    if proc.returncode != 0:
        return False, stdout_text, stderr_text
    return True, stdout_text, ""


# ---------------------------------------------------------------------------
# Seed entity helpers
# ---------------------------------------------------------------------------

async def _ensure_seed_entities(
    store: "Store",
    target: Any,
    org_id: str,
    run_id: uuid.UUID,
) -> dict[tuple[str, str], uuid.UUID]:
    """Pre-create seed entities (configured domains/ASNs) for a target.

    Returns a mapping of (entity_type, entity_value) -> entity_id for
    all seed entities, so that discovered entities can reference them
    as parents.
    """
    seed_map: dict[tuple[str, str], uuid.UUID] = {}

    if not hasattr(target, "match_rules"):
        return seed_map

    # Ensure domain seeds exist
    for domain in (target.match_rules.domains or []):
        try:
            eid, _ = await store.upsert_entity(
                org_id, target.id, "domain", domain, {},
                discovery_run_id=run_id,
                parent_entity_id=None,  # seeds have no parent
            )
            seed_map[("domain", domain)] = eid
        except Exception:
            logger.debug("failed to create seed domain entity: %s", domain, exc_info=True)

    # Ensure ASN seeds exist
    for asn in (target.match_rules.asns or []):
        try:
            eid, _ = await store.upsert_entity(
                org_id, target.id, "asn", asn, {},
                discovery_run_id=run_id,
                parent_entity_id=None,  # seeds have no parent
            )
            seed_map[("asn", asn)] = eid
        except Exception:
            logger.debug("failed to create seed ASN entity: %s", asn, exc_info=True)

    return seed_map


# ---------------------------------------------------------------------------
# Full run lifecycle (mirrors BaseRunner.execute)
# ---------------------------------------------------------------------------

async def execute_runner(
    source_name: str,
    run_fn: Callable[..., Awaitable[tuple[int, int, int]]],
    target: Any,
    store: Store,
    trigger_type: str,
    *,
    http_client: httpx.AsyncClient | None = None,
) -> uuid.UUID:
    """Execute a runner's full lifecycle and return the ``run_id``.

    This mirrors ``BaseRunner.execute()``:
    * create a run record
    * mark it started
    * call ``run_fn(target, store, trigger_type, run_id, log, http_client)``
    * handle exceptions
    * mark the run finished with counters
    * compute ``new_entity_count`` / ``total_entity_count``
    """
    log_lines: list[str] = []

    def log(msg: str) -> None:
        log_lines.append(msg)

    run_id = await store.create_run(
        target.id, source_name, trigger_type, org_id=target.org_id,
    )

    seed_map: dict[tuple[str, str], uuid.UUID] = {}
    try:
        seed_map = await _ensure_seed_entities(store, target, target.org_id, run_id)
    except Exception:
        logger.debug("seed entity pre-creation failed", exc_info=True)

    target._seed_map = seed_map

    start = datetime.now(UTC)
    await store.mark_run_started(run_id, start)

    inserted = deduped = errors = 0
    error_message: str | None = None

    try:
        inserted, deduped, errors = await run_fn(
            target, store, trigger_type, run_id, log, http_client,
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
        run_id,
        status,
        end,
        duration_ms,
        inserted,
        deduped,
        errors,
        error_message=error_message,
        logs=log_text,
    )

    # Compute run counters ------------------------------------------------
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
                new_count or 0,
                total_count or 0,
                run_id,
            )
    except Exception:
        logger.exception(
            "failed to compute run counters", extra={"run_id": str(run_id)},
        )

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


async def _ingest_entities(
    store: Store,
    output_schema: Any,
    raw: dict,
    run_id: uuid.UUID,
    org_id: str,
    target_id: str,
    target: Any | None = None,
    pool: Any | None = None,
    raw_event_id: uuid.UUID | None = None,
    seed_map: dict[tuple[str, str], uuid.UUID] | None = None,
) -> None:
    ingest_pool = pool or getattr(store, "pool", None)
    _effective_seed_map = seed_map or (getattr(target, "_seed_map", None) if target else None)
    try:
        entities, relationships = output_schema(raw)
    except Exception:
        logger.exception("output_schema failed", extra={"run_id": str(run_id)})
        return
    discovery_session_id = None
    try:
        run_data = await store.get_run(run_id)
        discovery_session_id = run_data.get("discovery_session_id") if run_data else None
    except Exception:
        logger.debug("failed to load discovery session for run", exc_info=True)

    def _resolve_parent(ec_type: str, ec_value: str, ec_attrs: dict) -> uuid.UUID | None:
        if not _effective_seed_map:
            return None

        if ec_type == "domain":
            if ("domain", ec_value) in _effective_seed_map:
                return None
            return None

        if ec_type == "asn":
            return None

        if ec_type == "hostname":
            ext = tldextract.extract(ec_value)
            registered_domain = f"{ext.domain}.{ext.suffix}"
            parent_id = _effective_seed_map.get(("domain", registered_domain))
            if parent_id:
                return parent_id
            for (etype, eval_), eid in _effective_seed_map.items():
                if etype == "domain" and ec_value.endswith("." + eval_):
                    return eid
            return None

        if ec_type == "certificate":
            san = ec_attrs.get("san_dns_names", [])
            cn = ec_attrs.get("common_name", "")
            candidates: list[str] = []
            if cn:
                candidates.append(cn)
            if isinstance(san, list):
                candidates.extend(san)
            for d in candidates:
                ext = tldextract.extract(d)
                rd = f"{ext.domain}.{ext.suffix}"
                parent_id = _effective_seed_map.get(("domain", rd))
                if parent_id:
                    return parent_id
                for (etype, eval_), eid in _effective_seed_map.items():
                    if etype == "domain" and d.endswith("." + eval_):
                        return eid
            return None

        return None

    for ec in entities:
        try:
            _parent_id = _resolve_parent(ec.entity_type, ec.value, ec.attributes)
            entity_id, is_new = await store.upsert_entity(
                org_id, target_id, ec.entity_type, ec.value,
                ec.attributes, raw_event_id=raw_event_id,
                discovery_session_id=discovery_session_id,
                discovery_run_id=run_id,
                parent_entity_id=_parent_id,
            )
            try:
                source = ec.attributes.get("source") or "unknown"
                target_domains = (
                    list(target.match_rules.domains)
                    if target is not None and hasattr(target, "match_rules")
                    else []
                )
                target_asns = (
                    list(target.match_rules.asns)
                    if target is not None and hasattr(target, "match_rules")
                    else []
                )
                await store.apply_asset_profile_for_entity(
                    org_id=org_id,
                    target_id=target_id,
                    entity_id=entity_id,
                    entity_type=ec.entity_type,
                    entity_value=ec.value,
                    source=source,
                    raw_event_id=raw_event_id,
                    target_domains=target_domains,
                    target_asns=target_asns,
                    summary=f"{source} observed {ec.entity_type} {ec.value}",
                )
            except Exception:
                logger.debug("asset profile update failed", exc_info=True)
            if is_new and target is not None and ingest_pool is not None:
                try:
                    from easm.classify import classify_entity
                    classification = classify_entity(
                        ec.entity_type, ec.value,
                        target_domains=(
                            list(target.match_rules.domains)
                            if hasattr(target, "match_rules")
                            else None
                        ),
                        saas_rules=(
                            target.saas_providers
                            if hasattr(target, "saas_providers")
                            else None
                        ),
                    )
                    if classification.classification != "org-owned":
                        await ingest_pool.execute(
                            "UPDATE entities SET attributes "
                            "= attributes || $1::jsonb WHERE id = $2",
                            json.dumps(classification.to_dict()),
                            entity_id,
                        )
                except Exception:
                    logger.debug("classification failed for %s", ec.value, exc_info=True)

                try:
                    from easm.pivot.resolver import PivotResolver
                    resolver = PivotResolver(ingest_pool)
                    await resolver.check_and_enqueue(
                        target, ec.entity_type, ec.value, entity_id,
                        depth=1,
                        discovery_session_id=discovery_session_id,
                    )
                except Exception:
                    logger.debug(
                        "pivot enqueue failed for %s/%s",
                        ec.entity_type, ec.value,
                        exc_info=True,
                    )
        except Exception:
            logger.exception("entity upsert failed")
    for rc in relationships:
        try:
            await store.upsert_relationship_by_value(
                org_id, target_id,
                rc.source_type, rc.source_value,
                rc.target_type, rc.target_value,
                rc.relationship_type, rc.relationship_source,
                evidence_raw_event_id=raw_event_id,
            )
        except Exception:
            logger.exception("relationship upsert failed")


# ---------------------------------------------------------------------------
# Generic subprocess runner
# ---------------------------------------------------------------------------

async def standard_subprocess_run(
    target: Any,
    store: Store,
    trigger_type: str,  # noqa: ARG001 (part of the run_fn signature contract)
    run_id: uuid.UUID,
    log: Callable[[str], None],
    http_client: httpx.AsyncClient | None,  # noqa: ARG001 (subprocess runners don't use HTTP)
    *,
    source_name: str,
    binary: str,
    args_template: list[str],
    iterate_over: Callable[[Any], list[str]],
    timeout: int = 300,
    transform_fn: Callable[[dict, str], dict | None] | None = None,
    output_schema: Any | None = None,
    pool: Any | None = None,
) -> tuple[int, int, int]:
    """Generic subprocess runner for tools that output JSON-lines on stdout.

    For each item returned by ``iterate_over(target)``:
    1. Build ``[binary, *args_template]`` with ``[item]`` placeholders replaced
    2. ``exec_subprocess``
    3. Parse each stdout line as JSON
    4. Apply ``transform_fn(parsed, item)`` if given
    5. ``store.insert_raw_event``

    Returns ``(inserted, deduped, errors)``.
    """
    inserted = deduped = errors = 0
    items = iterate_over(target)
    log(f"[runner] {source_name}: iterating over {len(items)} item(s)")
    first_error: str | None = None

    for item in items:
        cmd = [binary] + [arg.replace("[item]", item) for arg in args_template]
        log(f"[runner] {source_name}: running {' '.join(cmd)}")

        ok, stdout, stderr = await exec_subprocess(cmd, timeout=timeout, logger_fn=log)
        if not ok:
            errors += 1
            err_msg = stderr[:200] if stderr else "unknown error"
            if first_error is None:
                first_error = f"{binary} failed for {item}: {err_msg}"
            logger.warning(
                "%s error for %s", binary, item,
                extra={
                    "item": item,
                    "target_id": target.id,
                    "stderr": stderr[:200] if stderr else "",
                },
            )
            continue

        if not stdout.strip():
            logger.warning(
                "%s produced no output for %s", binary, item,
                extra={"item": item, "target_id": target.id},
            )
            continue

        for line in stdout.strip().split("\n"):
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                errors += 1
                continue

            raw = transform_fn(parsed, item) if transform_fn else parsed
            if raw is None:
                continue

            raw_event_id = await store.insert_raw_event(
                target.org_id, target.id, source_name, raw, run_id,
            )
            if raw_event_id is not None:
                inserted += 1
                if output_schema:
                    await _ingest_entities(store, output_schema, raw, run_id,
                                          target.org_id, target.id, target=target,
                                          pool=pool or getattr(store, "pool", None),
                                          raw_event_id=raw_event_id)
            else:
                deduped += 1

    if errors > 0 and inserted == 0 and first_error:
        raise RuntimeError(first_error)

    return inserted, deduped, errors


# ---------------------------------------------------------------------------
# Generic HTTP runner
# ---------------------------------------------------------------------------

async def standard_http_run(
    target: Any,
    store: Store,
    trigger_type: str,  # noqa: ARG001
    run_id: uuid.UUID,
    log: Callable[[str], None],
    http_client: httpx.AsyncClient | None,
    *,
    source_name: str,
    url_template: str,
    iterate_over: Callable[[Any], list[str]],
    timeout: float = 30.0,
    transform_fn: Callable[[dict, str], dict | None] | None = None,
    output_schema: Any | None = None,
    max_retries: int = 0,
    retry_statuses: tuple[int, ...] = (),
    inter_delay: float = 0.0,
    max_concurrent: int = 1,
    pool: Any | None = None,
) -> tuple[int, int, int]:
    """Generic HTTP runner with optional retry, rate-limiting, and concurrency.

    For each item returned by ``iterate_over(target)``:
    1. Build URL by replacing ``[item]`` in ``url_template``
    2. Fetch with retry logic (``max_retries`` total attempts)
    3. Parse response as JSON array, single JSON object, or NDJSON
    4. Apply ``transform_fn(record, item)`` if given
    5. ``store.insert_raw_event``
    6. Ingest entities/relationships via ``output_schema`` if provided

    ``retry_statuses`` — HTTP status codes that trigger a retry.
    ``inter_delay`` — seconds to sleep between items (avoids rate-limiting).
    ``max_concurrent`` — max number of in-flight HTTP requests (1 = sequential).

    When ``max_concurrent > 1``, items are fetched concurrently using an
    ``asyncio.Semaphore`` and ``asyncio.gather``.  The ``inter_delay`` is
    ignored in the concurrent path (the semaphore controls pacing).

    When ``http_client`` is ``None`` a temporary client is created and
    closed automatically.
    """
    own_client = http_client is None
    http = http_client or httpx.AsyncClient(timeout=timeout)
    inserted = deduped = errors = 0

    try:
        if max_concurrent > 1:
            # --- Concurrent path ---
            sem = asyncio.Semaphore(max_concurrent)

            async def _process_item(item: str) -> tuple[int, int, int]:
                async with sem:
                    url = url_template.replace("[item]", item)
                    try:
                        resp_text = await _http_fetch_with_retry(
                            http, url, max_retries, retry_statuses, log,
                        )
                    except Exception as exc:
                        logger.warning(
                            "%s error for %s: %s", source_name, item, exc,
                            extra={"item": item, "target_id": target.id},
                        )
                        return 0, 0, 1

                    if resp_text is None:
                        logger.warning(
                            "%s returned no data for %s", source_name, item,
                            extra={"item": item, "target_id": target.id},
                        )
                        return 0, 0, 1

                    ins = ded = 0
                    records = _parse_response_text(resp_text)
                    for record in records:
                        raw = transform_fn(record, item) if transform_fn else record
                        if raw is None:
                            continue
                        raw_event_id = await store.insert_raw_event(
                            target.org_id, target.id, source_name, raw, run_id,
                        )
                        if raw_event_id is not None:
                            ins += 1
                            if output_schema:
                                await _ingest_entities(
                                    store, output_schema, raw, run_id,
                                    target.org_id, target.id,
                                    target=target, pool=pool or store.pool,
                                    raw_event_id=raw_event_id,
                                )
                        else:
                            ded += 1
                    return ins, ded, 0

            items = iterate_over(target)
            results = await asyncio.gather(*[_process_item(i) for i in items])
            for ins, ded, err in results:
                inserted += ins
                deduped += ded
                errors += err
        else:
            # --- Sequential path (original behaviour) ---
            for item in iterate_over(target):
                url = url_template.replace("[item]", item)

                try:
                    resp_text = await _http_fetch_with_retry(
                        http, url, max_retries, retry_statuses, log,
                    )
                except Exception as e:
                    errors += 1
                    logger.warning(
                        "%s error for %s: %s", source_name, item, e,
                        extra={"item": item, "target_id": target.id},
                    )
                    if inter_delay:
                        await asyncio.sleep(inter_delay)
                    continue

                if resp_text is None:
                    errors += 1
                    logger.warning(
                        "%s returned no data for %s", source_name, item,
                        extra={"item": item, "target_id": target.id},
                    )
                    if inter_delay:
                        await asyncio.sleep(inter_delay)
                    continue

                records = _parse_response_text(resp_text)
                for record in records:
                    raw = transform_fn(record, item) if transform_fn else record
                    if raw is None:
                        continue
                    raw_event_id = await store.insert_raw_event(
                        target.org_id, target.id, source_name, raw, run_id,
                    )
                    if raw_event_id is not None:
                        inserted += 1
                        if output_schema:
                            await _ingest_entities(store, output_schema, raw, run_id,
                                                  target.org_id, target.id, target=target,
                                                  pool=pool or getattr(store, "pool", None),
                                                  raw_event_id=raw_event_id)
                    else:
                        deduped += 1

                if inter_delay:
                    await asyncio.sleep(inter_delay)
    finally:
        if own_client:
            await http.aclose()

    return inserted, deduped, errors


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _http_fetch_with_retry(
    http: httpx.AsyncClient,
    url: str,
    max_retries: int,
    retry_statuses: tuple[int, ...],
    log: Callable[[str], None],
) -> str | None:
    """Fetch a URL with exponential backoff for retryable status codes.

    ``max_retries`` is the total number of attempts (1 = no retry).
    Returns the response text on success, or ``None`` on failure.
    """
    for attempt in range(max_retries):
        resp = await http.get(url)
        if resp.status_code == 200:
            return resp.text
        if attempt < max_retries - 1 and resp.status_code in retry_statuses:
            retry_after = resp.headers.get("Retry-After")
            if retry_after:
                try:
                    wait = float(retry_after)
                except ValueError:
                    wait = float(2**attempt) + random.uniform(0, 1)
            else:
                wait = float(2**attempt) + random.uniform(0, 1)
            log(
                f"[http] retry {attempt + 1}/{max_retries - 1} "
                f"after {wait:.1f}s (status {resp.status_code})",
            )
            await asyncio.sleep(wait)
            continue
        # Non-retryable status or final attempt
        return None
    return None


def _parse_response_text(text: str) -> list[dict]:
    """Parse HTTP response body as JSON array, single JSON object, or NDJSON."""
    stripped = text.strip()
    if not stripped:
        return []
    try:
        data = json.loads(stripped)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
        return []
    except json.JSONDecodeError:
        # Try NDJSON (one JSON object per line)
        records: list[dict] = []
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records
