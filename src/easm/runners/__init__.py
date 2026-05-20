from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from easm.runners.registry import RunnerDef, get_runner_registry
from easm.runners.schemas import OUTPUT_SCHEMAS

if TYPE_CHECKING:
    pass

__all__ = [
    "RunnerDef", "get_all_runners", "get_runner_registry",
    "RUNNER_REGISTRY",  # kept for backward compat during migration
]

_legacy_logger = logging.getLogger(__name__)


class _EntityIngestStoreProxy:
    """Wraps a Store so that ``insert_raw_event`` also ingests entities.

    When a legacy runner calls ``store.insert_raw_event(...)`` the proxy
    intercepts the call, forwards it to the real store, and then runs the
    result through ``output_schema`` → ``_ingest_entities`` so that
    discovered entities/relationships appear in the entity graph
    immediately — even for continuous runners like certstream that never
    return from ``run_once``.
    """

    __slots__ = ("_inner", "_output_schema", "_target", "_run_id")

    def __init__(
        self,
        store: Any,
        output_schema: Any,
        target: Any,
        run_id: Any,
    ) -> None:
        object.__setattr__(self, "_inner", store)
        object.__setattr__(self, "_output_schema", output_schema)
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_run_id", run_id)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def insert_raw_event(
        self,
        org_id: str,
        target_id: str,
        source: str,
        raw: dict,
        run_id: Any,
    ) -> Any:
        raw_event_id = await self._inner.insert_raw_event(
            org_id, target_id, source, raw, run_id,
        )
        if raw_event_id is not None:
            try:
                from easm.runners.engine import _ingest_entities

                await _ingest_entities(
                    self._inner,
                    self._output_schema,
                    raw,
                    self._run_id,
                    org_id,
                    target_id,
                    target=self._target,
                    pool=getattr(self._inner, "pool", None),
                    raw_event_id=raw_event_id,
                )
            except Exception:
                _legacy_logger.debug(
                    "inline entity ingestion failed for %s event",
                    source, exc_info=True,
                )
        return raw_event_id


def _make_legacy_adapter(runner_cls: type, output_schema: Any = None) -> Any:
    """Wrap an old BaseRunner subclass as a run_fn for the new engine.

    The engine handles the lifecycle (create_run, mark_started/finished,
    error handling, counter computation). The adapter only needs to call
    the runner's run_once method.

    When *output_schema* is provided the store is wrapped with
    ``_EntityIngestStoreProxy`` so that every ``insert_raw_event`` call
    also feeds the output schema → entity ingestion pipeline.
    """

    async def _adapted_run_fn(
        target: Any,
        store: Any,
        trigger_type: str,
        run_id: Any,
        log: Any,
        http_client: Any,
    ) -> tuple[int, int, int]:
        kwargs: dict[str, Any] = {}
        if hasattr(runner_cls, "is_api_runner") and http_client is not None:
            kwargs["http_client"] = http_client

        # Wire API keys from runner config for searchengine
        source_name = getattr(runner_cls, "source_name", "")
        if source_name == "searchengine":
            runner_cfg = target.runners.get("searchengine")
            if runner_cfg is not None:
                kwargs.setdefault("google_api_key", runner_cfg.google_api_key or "")
                kwargs.setdefault("google_cx", runner_cfg.google_cx or "")
                kwargs.setdefault("bing_api_key", runner_cfg.bing_api_key or "")

        effective_store = store
        if output_schema is not None:
            effective_store = _EntityIngestStoreProxy(
                store, output_schema, target, run_id,
            )

        runner = runner_cls(effective_store, **kwargs)
        return await runner.run_once(target, trigger_type, run_id)

    return _adapted_run_fn


# Legacy class registry — these are adapted to RunnerDef at module load.
# Standard runners (asnmap, subfinder, dnstwist, nuclei, wappalyzer, crtsh,
# commoncrawl) are already in the declarative registry.
_LEGACY_CLASSES: dict[str, type] = {}


def _register_legacy():
    """Import legacy runner classes lazily to avoid circular imports."""
    from easm.runners.base import ApiRunner, BaseRunner  # noqa: F401
    from easm.runners.breach_monitor_runner import BreachMonitorRunner
    from easm.runners.certstream_runner import CertStreamRunner
    from easm.runners.cloud_bucket_runner import CloudBucketRunner
    from easm.runners.gist_monitor_runner import GistMonitorRunner
    from easm.runners.github_scan_runner import GithubScanRunner
    from easm.runners.paste_monitor_runner import PasteMonitorRunner
    from easm.runners.portscan_runner import PortScanRunner
    from easm.runners.screenshot_runner import ScreenshotRunner
    from easm.runners.searchengine_runner import SearchEngineRunner
    from easm.runners.stackoverflow_monitor_runner import StackOverflowMonitorRunner

    _LEGACY_CLASSES.update({
        "breach_monitor": BreachMonitorRunner,
        "certstream": CertStreamRunner,
        "cloud_enum": CloudBucketRunner,
        "gist_monitor": GistMonitorRunner,
        "github_scan": GithubScanRunner,
        "paste_monitor": PasteMonitorRunner,
        "portscan": PortScanRunner,
        "screenshot": ScreenshotRunner,
        "searchengine": SearchEngineRunner,
        "stackoverflow_monitor": StackOverflowMonitorRunner,
    })


# Build legacy RUNNER_REGISTRY for backward compat (scheduler uses it for naming)
# This maps name → class for the OLD runners.
# Standard runners that moved to the declarative registry are NOT here.
RUNNER_REGISTRY: dict[str, type] = {}  # populated on first get_all_runners() call

_combined_cache: dict[str, RunnerDef] | None = None


def get_all_runners() -> dict[str, RunnerDef]:
    """Return unified registry of ALL runners as RunnerDef entries.

    Standard runners (asnmap, subfinder, dnstwist, nuclei, wappalyzer,
    crtsh, commoncrawl) come from the declarative registry.
    Custom/monitor runners are adapted from their legacy classes.
    """
    global _combined_cache
    if _combined_cache is not None:
        return _combined_cache

    # Standard declarative runners
    registry = dict(get_runner_registry())

    # Legacy class-based runners
    if not _LEGACY_CLASSES:
        _register_legacy()

    for name, runner_cls in _LEGACY_CLASSES.items():
        # Populate backward compat registry
        RUNNER_REGISTRY[name] = runner_cls
        # Add adapted entry
        registry[name] = RunnerDef(
            source_name=name,
            run_fn=_make_legacy_adapter(runner_cls, OUTPUT_SCHEMAS.get(name)),
            output_schema=OUTPUT_SCHEMAS.get(name),
            supports_schedule=getattr(runner_cls, "supports_schedule", True),
            supports_manual_trigger=getattr(runner_cls, "supports_manual_trigger", True),
            is_continuous=getattr(runner_cls, "is_continuous", False),
        )

    _combined_cache = registry
    return registry
