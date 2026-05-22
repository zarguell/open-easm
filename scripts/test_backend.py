from __future__ import annotations

import os
import subprocess
import sys


def run(cmd: list[str]) -> None:
    print(f"+ {' '.join(cmd)}", flush=True)
    subprocess.run(cmd, check=True)


def require_matching_test_dsn() -> None:
    test_dsn = os.environ.get("EASM_TEST_DATABASE_DSN")
    app_dsn = os.environ.get("EASM_DATABASE_DSN")
    if not test_dsn:
        raise SystemExit("EASM_TEST_DATABASE_DSN is required for Docker tests")
    if app_dsn and app_dsn != test_dsn:
        raise SystemExit(
            "EASM_DATABASE_DSN and EASM_TEST_DATABASE_DSN differ; refusing to "
            "migrate one database and test another"
        )


def main() -> None:
    require_matching_test_dsn()
    run(["alembic", "upgrade", "head"])
    run(["python", "-m", "pytest", "-ra", "-q", "-p", "scripts.pytest_no_skip"])


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        sys.exit(exc.returncode)
