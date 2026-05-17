"""Parser tests are pure unit tests — override DB fixtures from root conftest."""

import pytest


@pytest.fixture
def db_pool():
    """No-op: parser tests don't need a database."""
    return None


@pytest.fixture
def clean_db():
    """No-op: parser tests don't need a database."""
    yield
