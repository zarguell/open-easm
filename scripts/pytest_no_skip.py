from __future__ import annotations

import pytest


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    terminal = session.config.pluginmanager.get_plugin("terminalreporter")
    if terminal is None:
        return
    skipped = len(terminal.stats.get("skipped", []))
    xfailed = len(terminal.stats.get("xfailed", []))
    xpassed = len(terminal.stats.get("xpassed", []))
    if skipped or xfailed or xpassed:
        raise pytest.UsageError(
            "Unexpected skipped/xfail/xpass tests in backend gate: "
            f"skipped={skipped}, xfailed={xfailed}, xpassed={xpassed}"
        )
