import pytest

from easm.runners.schemas import shodan


# Override conftest's autouse async clean_db — no DB needed for unit tests.
@pytest.fixture(autouse=True)
def clean_db():
    yield


def test_shodan_stores_cpes():
    raw = {
        "ip": "1.2.3.4",
        "shodan": {
            "ports": [80, 443],
            "vulns": ["CVE-2023-44487"],
            "cpes": ["cpe:/a:apache:http_server:2.4.41"],
            "org": "Example Corp",
            "isp": "Example ISP",
            "asn": "AS12345",
            "country_name": "US",
            "city": "Mountain View",
            "os": "Linux",
            "data": [],
        },
    }
    entities, _ = shodan(raw)
    assert len(entities) == 1
    attrs = entities[0].attributes
    assert "cpes" in attrs, f"cpes missing from attributes: {list(attrs.keys())}"
    assert attrs["cpes"] == ["cpe:/a:apache:http_server:2.4.41"]


def test_shodan_internetdb_stores_cpes():
    raw = {
        "ip": "1.2.3.4",
        "ports": [80, 443],
        "hostnames": ["example.com"],
        "cpes": ["cpe:/a:nginx:nginx:1.24.0"],
        "vulns": ["CVE-2024-1234"],
        "source": "shodan",
    }
    entities, _ = shodan(raw)
    assert len(entities) == 1
    attrs = entities[0].attributes
    assert "cpes" in attrs, f"cpes missing from attributes: {list(attrs.keys())}"
    assert attrs["cpes"] == ["cpe:/a:nginx:nginx:1.24.0"]
