import pytest

from easm.cpe_mapper import tech_to_cpe, compute_cpes_from_entity, nmap_service_to_cpe


@pytest.fixture
def db_pool():
    return None


@pytest.fixture(autouse=True)
def clean_db():
    yield


def test_tech_to_cpe_known():
    cpe = tech_to_cpe("nginx", "1.24.0")
    assert cpe == "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"


def test_tech_to_cpe_case_insensitive():
    cpe = tech_to_cpe("WordPress", "6.4")
    assert cpe == "cpe:2.3:a:wordpress:wordpress:6.4:*:*:*:*:*:*:*"


def test_tech_to_cpe_no_version():
    cpe = tech_to_cpe("nginx", None)
    assert cpe == "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"


def test_tech_to_cpe_strips_v_prefix():
    cpe = tech_to_cpe("php", "v8.2.1")
    assert cpe == "cpe:2.3:a:php:php:8.2.1:*:*:*:*:*:*:*"


def test_tech_to_cpe_unknown():
    cpe = tech_to_cpe("unknown-tech", "1.0")
    assert cpe is None


def test_nmap_service_to_cpe():
    cpe = nmap_service_to_cpe("ssh")
    assert cpe is not None
    assert "openssh" in cpe


def test_compute_cpes_from_wappalyzer():
    attrs = {
        "technologies": [
            {"name": "nginx", "version": "1.24.0"},
            {"name": "WordPress", "version": "6.4"},
            {"name": "unknown", "version": "1.0"},
        ],
    }
    cpes = compute_cpes_from_entity("hostname", attrs)
    assert len(cpes) == 2
    assert "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*" in cpes
    assert "cpe:2.3:a:wordpress:wordpress:6.4:*:*:*:*:*:*:*" in cpes


def test_compute_cpes_from_shodan_pass_through():
    attrs = {"cpes": ["cpe:/a:apache:http_server:2.4.41"]}
    cpes = compute_cpes_from_entity("ip", attrs)
    assert len(cpes) == 1
    assert "cpe:/a:apache:http_server:2.4.41" in cpes


def test_compute_cpes_deduplicates():
    attrs = {
        "technologies": [{"name": "nginx", "version": "1.24.0"}],
        "cpes": ["cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"],
    }
    cpes = compute_cpes_from_entity("hostname", attrs)
    assert len(cpes) == 1
