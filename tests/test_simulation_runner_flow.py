import asyncio
import uuid
from unittest.mock import AsyncMock

from easm.config import RuntimeConfig, TargetConfig
from easm.runtime import Runtime
from easm.runners.engine import standard_subprocess_run
from easm.runners.schemas import subfinder


def test_simulated_subfinder_ingests_entities_and_calls_pivot_enqueue(
    tmp_path, monkeypatch
):
    runners_dir = tmp_path / "runners"
    runners_dir.mkdir()
    (runners_dir / "subfinder.jsonl").write_text(
        '{"host":"app.example.invalid"}\n',
        encoding="utf-8",
    )
    runtime = Runtime(
        RuntimeConfig(
            mode="simulate",
            fixtures_path=str(tmp_path),
            allow_subprocess=False,
        )
    )
    monkeypatch.setattr("easm.runners.subprocess_runner.get_runtime", lambda: runtime)
    target = TargetConfig(
        id="sim",
        name="Simulation",
        type="organization",
        match_rules={"domains": ["example.invalid"]},
        runners={},
        pivot={
            "enabled": True,
            "max_depth": 2,
            "allowed_pivots": [
                {"from": "hostname", "to": "ip", "via": "dns_resolve"}
            ],
        },
    )
    store = AsyncMock()
    store.pool = AsyncMock()
    store.insert_raw_event.return_value = uuid.uuid4()
    store.upsert_entity.return_value = (uuid.uuid4(), True)
    store.get_run.return_value = {"discovery_session_id": uuid.uuid4()}

    inserted, deduped, errors = asyncio.run(
        standard_subprocess_run(
            target,
            store,
            "manual",
            uuid.uuid4(),
            lambda _: None,
            None,
            source_name="subfinder",
            binary="subfinder",
            args_template=["-d", "[item]", "-json"],
            iterate_over=lambda t: t.match_rules.domains,
            output_schema=subfinder,
        )
    )

    assert (inserted, deduped, errors) == (1, 0, 0)
    store.upsert_entity.assert_awaited()
    store.apply_asset_profile_for_entity.assert_awaited_once()
    profile_call = store.apply_asset_profile_for_entity.await_args.kwargs
    assert profile_call["org_id"] == "default"
    assert profile_call["target_id"] == "sim"
    assert profile_call["entity_type"] == "hostname"
    assert profile_call["entity_value"] == "app.example.invalid"
    assert profile_call["source"] == "subfinder"
    assert profile_call["target_domains"] == ["example.invalid"]
