import asyncio
import os
from pathlib import Path

import asyncpg
import pytest
import pytest_asyncio


@pytest.fixture
def configs_dir():
    return Path(__file__).parent / "fixtures" / "configs"


@pytest.fixture(autouse=True)
def reset_runtime_policy():
    from easm.config import RuntimeConfig
    from easm.runtime import configure_runtime

    configure_runtime(RuntimeConfig())
    yield
    configure_runtime(RuntimeConfig())


def _test_database_dsn() -> str:
    test_dsn = os.environ.get("EASM_TEST_DATABASE_DSN")
    app_dsn = os.environ.get("EASM_DATABASE_DSN")
    if not test_dsn:
        raise RuntimeError(
            "EASM_TEST_DATABASE_DSN is required for database-backed tests; "
            "refusing to use an application or default database"
        )
    if test_dsn and app_dsn and test_dsn != app_dsn:
        raise RuntimeError(
            "EASM_DATABASE_DSN and EASM_TEST_DATABASE_DSN differ; refusing to "
            "run tests against an ambiguous database"
        )
    return test_dsn


async def _truncate_app_tables(conn) -> None:
    rows = await conn.fetch(
        """
        SELECT quote_ident(tablename) AS table_name
        FROM pg_tables
        WHERE schemaname = 'public'
          AND tablename <> 'alembic_version'
        ORDER BY tablename
        """
    )
    tables = [row["table_name"] for row in rows]
    if tables:
        await conn.execute(f"TRUNCATE TABLE {', '.join(tables)} CASCADE")
    await conn.execute(
        """
        INSERT INTO organizations (id, name)
        VALUES ('default', 'Default Organization')
        ON CONFLICT (id) DO NOTHING
        """
    )


@pytest_asyncio.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def db_pool():
    pool = await asyncpg.create_pool(dsn=_test_database_dsn(), min_size=1, max_size=5)
    async with pool.acquire() as conn:
        await _truncate_app_tables(conn)
    yield pool
    await pool.close()


@pytest_asyncio.fixture
async def scheduler():
    from easm.scheduler import Scheduler

    s = Scheduler()
    yield s
    if s.running:
        await s.shutdown()


@pytest.fixture
def clean_db():
    yield
