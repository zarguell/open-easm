import pytest

from easm.runners.schemas import shodan


# Override conftest's autouse async clean_db — no DB needed for unit tests.
@pytest.fixture(autouse=True)
def clean_db():
    yield


def test_subfinder_outputs_hostname_for_subdomain():
    from easm.runners.schemas import subfinder
    entities, relationships = subfinder({"host": "app.example.invalid"})
    assert len(entities) == 1
    assert entities[0].entity_type == "hostname"
    assert entities[0].value == "app.example.invalid"
    assert entities[0].attributes["source"] == "subfinder"


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
    assert len(entities) == 2
    attrs = entities[0].attributes
    assert "cpes" in attrs, f"cpes missing from attributes: {list(attrs.keys())}"
    assert attrs["cpes"] == ["cpe:/a:nginx:nginx:1.24.0"]


def test_tls_cert_schema_adds_certificate_profile_deployment_state():
    from easm.runners.schemas import tls_cert

    entities, rels = tls_cert({
        "hostname": "app.example.invalid",
        "port": 443,
        "cert": {
            "fingerprint_sha256": "ABCDEF",
            "subject_cn": "app.example.invalid",
            "issuer_cn": "Example CA",
            "issuer_org": "Example Org",
            "not_before": "2026-01-01T00:00:00+00:00",
            "not_after": "2026-06-01T00:00:00+00:00",
            "san_dns_names": ["app.example.invalid"],
            "public_key_algorithm": "RSA",
            "public_key_size_bits": 2048,
            "signature_algorithm": "sha256WithRSAEncryption",
            "signature_hash_algorithm": "sha256",
        },
    })

    cert = next(entity for entity in entities if entity.entity_type == "certificate")
    profile = cert.attributes["certificate_profile"]
    assert profile["fingerprint_sha256"] == "abcdef"
    assert profile["deployment"]["state"] == "deployed"
    assert profile["analysis"]["risk"] == "medium"
    assert any(rel.relationship_type == "deployed_on" for rel in rels)


def test_crtsh_schema_adds_ct_only_certificate_profile():
    from easm.runners.schemas import crtsh

    entities, _ = crtsh({
        "name_value": "app.example.invalid",
        "issuer_name_id": "example-ca",
        "not_before": "2026-01-01T00:00:00+00:00",
        "not_after": "2026-06-01T00:00:00+00:00",
        "serial_number": "01",
        "fingerprint": "ABCDEF",
    })

    cert = next(entity for entity in entities if entity.entity_type == "certificate")
    profile = cert.attributes["certificate_profile"]
    assert profile["deployment"]["state"] == "ct_only"
    assert profile["ct"]["seen"] is True
