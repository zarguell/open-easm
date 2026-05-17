import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from easm.runners.engine import standard_http_run


def _make_target(domains=None):
    target = MagicMock()
    target.id = "test-target"
    target.org_id = "default"
    target.match_rules.domains = domains or ["example.com"]
    return target


def _make_store(insert_result=True):
    store = AsyncMock()
    store.insert_raw_event.return_value = insert_result
    return store


def _make_http_client(responses):
    mock_http = AsyncMock(spec=httpx.AsyncClient)
    call_idx = 0

    async def _get(url):
        nonlocal call_idx
        idx = min(call_idx, len(responses) - 1)
        call_idx += 1
        resp = MagicMock()
        resp.status_code = responses[idx][0]
        resp.text = responses[idx][1]
        resp.headers = {}
        return resp

    mock_http.get = _get
    return mock_http


@pytest.mark.asyncio
async def test_sequential_default_max_concurrent():
    inserted, deduped, errors = await standard_http_run(
        _make_target(["a.com", "b.com"]),
        _make_store(),
        "manual",
        uuid.uuid4(),
        lambda msg: None,
        _make_http_client([
            (200, '[{"name": "cert-a"}]'),
            (200, '[{"name": "cert-b"}]'),
        ]),
        source_name="test",
        url_template="https://example.com/[item]",
        iterate_over=lambda t: t.match_rules.domains,
        max_retries=1,
    )
    assert inserted == 2
    assert deduped == 0
    assert errors == 0


@pytest.mark.asyncio
async def test_concurrent_max_concurrent_3():
    inserted, deduped, errors = await standard_http_run(
        _make_target(["a.com", "b.com", "c.com"]),
        _make_store(),
        "manual",
        uuid.uuid4(),
        lambda msg: None,
        _make_http_client([
            (200, '[{"name": "cert-a"}]'),
            (200, '[{"name": "cert-b"}]'),
            (200, '[{"name": "cert-c"}]'),
        ]),
        source_name="test",
        url_template="https://example.com/[item]",
        iterate_over=lambda t: t.match_rules.domains,
        max_retries=1,
        max_concurrent=3,
    )
    assert inserted == 3
    assert deduped == 0
    assert errors == 0


@pytest.mark.asyncio
async def test_concurrent_handles_fetch_error():
    mock_http = AsyncMock(spec=httpx.AsyncClient)
    mock_http.get = AsyncMock(side_effect=httpx.ConnectError("refused"))

    inserted, deduped, errors = await standard_http_run(
        _make_target(["a.com"]),
        _make_store(),
        "manual",
        uuid.uuid4(),
        lambda msg: None,
        mock_http,
        source_name="test",
        url_template="https://example.com/[item]",
        iterate_over=lambda t: t.match_rules.domains,
        max_retries=1,
        max_concurrent=2,
    )
    assert inserted == 0
    assert errors == 1


@pytest.mark.asyncio
async def test_concurrent_handles_null_response():
    mock_http = AsyncMock(spec=httpx.AsyncClient)
    resp = MagicMock()
    resp.status_code = 404
    resp.headers = {}
    mock_http.get = AsyncMock(return_value=resp)

    inserted, deduped, errors = await standard_http_run(
        _make_target(["a.com"]),
        _make_store(),
        "manual",
        uuid.uuid4(),
        lambda msg: None,
        mock_http,
        source_name="test",
        url_template="https://example.com/[item]",
        iterate_over=lambda t: t.match_rules.domains,
        max_retries=1,
        max_concurrent=2,
    )
    assert inserted == 0
    assert errors == 1


@pytest.mark.asyncio
async def test_concurrent_mixed_success_and_failure():
    call_count = 0

    async def _get(url):
        nonlocal call_count
        call_count += 1
        resp = MagicMock()
        if call_count <= 2:
            resp.status_code = 200
            resp.text = '[{"val": "ok"}]'
        else:
            resp.status_code = 500
            resp.headers = {}
        return resp

    mock_http = AsyncMock(spec=httpx.AsyncClient)
    mock_http.get = _get

    inserted, deduped, errors = await standard_http_run(
        _make_target(["a.com", "b.com", "c.com"]),
        _make_store(),
        "manual",
        uuid.uuid4(),
        lambda msg: None,
        mock_http,
        source_name="test",
        url_template="https://example.com/[item]",
        iterate_over=lambda t: t.match_rules.domains,
        max_retries=1,
        max_concurrent=3,
    )
    assert inserted == 2
    assert errors == 1


@pytest.mark.asyncio
async def test_concurrent_with_transform_fn():
    def transform(record, item):
        return {"domain": item, "data": record.get("val")}

    inserted, deduped, errors = await standard_http_run(
        _make_target(["a.com"]),
        _make_store(),
        "manual",
        uuid.uuid4(),
        lambda msg: None,
        _make_http_client([(200, '[{"val": "x"}]')]),
        source_name="test",
        url_template="https://example.com/[item]",
        iterate_over=lambda t: t.match_rules.domains,
        transform_fn=transform,
        max_retries=1,
        max_concurrent=2,
    )
    assert inserted == 1


@pytest.mark.asyncio
async def test_sequential_and_concurrent_produce_same_results():
    json_resp = '[{"n": 1}, {"n": 2}]'
    http_seq = _make_http_client([(200, json_resp)] * 3)
    http_con = _make_http_client([(200, json_resp)] * 3)
    store_seq = _make_store()
    store_con = _make_store()
    target = _make_target(["a.com", "b.com", "c.com"])
    rid_seq = uuid.uuid4()
    rid_con = uuid.uuid4()
    log = lambda msg: None

    ins_seq, ded_seq, err_seq = await standard_http_run(
        target, store_seq, "manual", rid_seq, log, http_seq,
        source_name="test", url_template="https://x/[item]",
        iterate_over=lambda t: t.match_rules.domains,
        max_retries=1,
    )
    ins_con, ded_con, err_con = await standard_http_run(
        target, store_con, "manual", rid_con, log, http_con,
        source_name="test", url_template="https://x/[item]",
        iterate_over=lambda t: t.match_rules.domains,
        max_retries=1,
        max_concurrent=3,
    )

    assert (ins_seq, ded_seq, err_seq) == (ins_con, ded_con, err_con)


@pytest.mark.asyncio
async def test_max_concurrent_1_does_not_use_gather():
    with patch("easm.runners.engine.asyncio.gather") as mock_gather:
        mock_gather.side_effect = AssertionError("gather should not be called")
        await standard_http_run(
            _make_target(["a.com"]),
            _make_store(),
            "manual",
            uuid.uuid4(),
            lambda msg: None,
            _make_http_client([(200, '[{"x": 1}]')]),
            source_name="test",
            url_template="https://example.com/[item]",
            iterate_over=lambda t: t.match_rules.domains,
            max_retries=1,
            max_concurrent=1,
        )
