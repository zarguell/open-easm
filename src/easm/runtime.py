from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Sequence

import httpx

from easm.config import RuntimeConfig


class Runtime:
    def __init__(self, config: RuntimeConfig | None = None):
        self.config = config or RuntimeConfig()

    @property
    def is_simulation(self) -> bool:
        return self.config.mode == "simulate"

    @property
    def fixtures_path(self) -> Path:
        return Path(self.config.fixtures_path)

    async def exec_subprocess(
        self,
        cmd: Sequence[str],
        timeout: int = 300,
        logger_fn: Callable[[str], Any] | None = None,
    ) -> tuple[bool, str, str]:
        if not self.is_simulation:
            if not self.config.allow_subprocess:
                return False, "", "subprocess disabled by runtime policy"
            return False, "", "runtime live subprocess delegation not implemented here"

        if not cmd:
            return False, "", "simulation subprocess command is empty"

        binary = Path(cmd[0]).name
        fixture = self.fixtures_path / "runners" / f"{binary}.jsonl"
        if not fixture.exists():
            return False, "", f"simulation fixture missing: {fixture}"

        text = fixture.read_text(encoding="utf-8")
        if logger_fn:
            for line in text.splitlines():
                logger_fn(f"[simulation stdout] {line}")
        return True, text, ""

    def load_pivot_results(
        self,
        pivot_type: str,
        entity_value: str,
    ) -> list[dict[str, Any]]:
        fixture = self.fixtures_path / "pivots" / f"{pivot_type}.json"
        if not fixture.exists():
            raise FileNotFoundError(f"simulation fixture missing: {fixture}")

        rows = json.loads(fixture.read_text(encoding="utf-8"))
        for row in rows:
            match = row.get("match", {})
            if match.get("entity_value") == entity_value:
                return list(row.get("results", []))
        return []

    async def run_pivot_handler(
        self,
        pivot_type: str,
        job: dict,
        live_handler,
        pool,
        **kwargs,
    ) -> list[dict[str, Any]]:
        if self.is_simulation:
            return self.load_pivot_results(pivot_type, job["entity_value"])
        return await live_handler(job, pool, **kwargs)

    def make_http_client(self) -> httpx.AsyncClient:
        if not self.is_simulation:
            if not self.config.allow_external_network:
                def blocked_handler(request: httpx.Request) -> httpx.Response:
                    return httpx.Response(
                        599,
                        json={
                            "error": "external network disabled by runtime policy",
                            "url": str(request.url),
                        },
                        request=request,
                    )

                return httpx.AsyncClient(
                    transport=httpx.MockTransport(blocked_handler),
                    timeout=30.0,
                )
            return httpx.AsyncClient(timeout=30.0)

        def handler(request: httpx.Request) -> httpx.Response:
            fixture = self._http_fixture_for(request)
            if fixture.exists():
                return httpx.Response(
                    200,
                    content=fixture.read_bytes(),
                    headers={"content-type": "application/json"},
                    request=request,
                )
            return httpx.Response(
                599,
                json={
                    "error": "simulation fixture missing",
                    "url": str(request.url),
                    "fixture": str(fixture),
                },
                request=request,
            )

        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            timeout=30.0,
        )

    def _http_fixture_for(self, request: httpx.Request) -> Path:
        host = request.url.host or "response"
        if host in {"crt.sh", "www.crt.sh"}:
            name = "crtsh"
        else:
            name = host.split(".")[0]
        return self.fixtures_path / "http" / f"{name}.json"


_runtime = Runtime()


def configure_runtime(config: RuntimeConfig) -> Runtime:
    global _runtime
    _runtime = Runtime(config)
    return _runtime


def get_runtime() -> Runtime:
    return _runtime
