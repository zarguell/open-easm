import asyncio

from easm.config import RuntimeConfig
from easm.runtime import Runtime


def test_simulated_subprocess_returns_fixture(tmp_path):
    fixture_dir = tmp_path / "fixtures" / "runners"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "subfinder.jsonl").write_text('{"host":"app.example.invalid"}\n')

    runtime = Runtime(
        RuntimeConfig(
            mode="simulate",
            fixtures_path=str(tmp_path / "fixtures"),
            allow_subprocess=False,
        )
    )

    ok, stdout, stderr = asyncio.run(
        runtime.exec_subprocess(["subfinder", "-d", "example.invalid"])
    )

    assert ok is True
    assert '{"host":"app.example.invalid"}' in stdout
    assert stderr == ""


def test_simulated_subprocess_fails_closed_when_fixture_missing(tmp_path):
    runtime = Runtime(
        RuntimeConfig(
            mode="simulate",
            fixtures_path=str(tmp_path),
            allow_subprocess=False,
        )
    )

    ok, stdout, stderr = asyncio.run(
        runtime.exec_subprocess(["subfinder", "-d", "example.invalid"])
    )

    assert ok is False
    assert stdout == ""
    assert "simulation fixture missing" in stderr
