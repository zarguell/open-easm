import pytest_asyncio


@pytest_asyncio.fixture(autouse=True)
async def clean_db():
    yield
