from __future__ import annotations

from easm.config import VALID_RUNNER_NAMES
from easm.runners import get_all_runners
from easm.runners.schemas import OUTPUT_SCHEMAS


RAW_ONLY_RUNNERS = {
    "paste_monitor",
    "gist_monitor",
    "stackoverflow_monitor",
    "discord_monitor",
    "github_scan",
    "breach_monitor",
}


def test_all_configured_runner_names_are_registered() -> None:
    registered = set(get_all_runners())
    assert set(VALID_RUNNER_NAMES) <= registered


def test_registered_runner_sources_have_schema_or_raw_only_reason() -> None:
    missing = [
        name
        for name in get_all_runners()
        if name not in OUTPUT_SCHEMAS and name not in RAW_ONLY_RUNNERS
    ]
    assert missing == []


def test_registered_runner_defs_attach_output_schema_metadata() -> None:
    missing = [
        name
        for name, runner_def in get_all_runners().items()
        if name in OUTPUT_SCHEMAS
        and name not in RAW_ONLY_RUNNERS
        and runner_def.output_schema is not OUTPUT_SCHEMAS[name]
    ]
    assert missing == []


def test_raw_only_runners_do_not_have_output_schemas() -> None:
    unexpected = sorted(name for name in RAW_ONLY_RUNNERS if name in OUTPUT_SCHEMAS)
    assert unexpected == []


def test_raw_only_runner_defs_do_not_attach_output_schema_metadata() -> None:
    unexpected = sorted(
        name
        for name, runner_def in get_all_runners().items()
        if name in RAW_ONLY_RUNNERS and runner_def.output_schema is not None
    )
    assert unexpected == []
