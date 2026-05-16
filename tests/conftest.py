import pytest
from pathlib import Path


@pytest.fixture
def configs_dir():
    return Path(__file__).parent / "fixtures" / "configs"
