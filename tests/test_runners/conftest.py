"""Runner tests use mocked stores — override DB fixtures from root conftest."""

import pytest


@pytest.fixture
def db_pool():
    """No-op: runner tests use mocked stores."""
    return None


@pytest.fixture
def clean_db():
    """No-op: runner tests use mocked stores."""
    yield
