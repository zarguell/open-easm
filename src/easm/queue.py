from __future__ import annotations

import os

import procrastinate


def _build_connector() -> procrastinate.PsycopgConnector:
    dsn = os.environ.get("EASM_DATABASE_DSN", "")
    if not dsn:
        dsn = "postgresql://easm:easm@localhost:5432/easm"
    return procrastinate.PsycopgConnector(conninfo=dsn)


app = procrastinate.App(
    connector=_build_connector(),
    import_paths=[
        "easm.tasks.runner",
        "easm.tasks.pivot",
        "easm.tasks.janitor",
    ],
    worker_defaults={
        "concurrency": 3,
        "delete_jobs": "successful",
    },
)
