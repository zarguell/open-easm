import pytest

from easm.entity_store import (
    deep_merge_attributes,
    normalize_entity_value,
)


def test_normalize_entity_value():
    assert normalize_entity_value("domain", "Example.COM.") == "example.com"
    assert normalize_entity_value("asn", "12345") == "AS12345"
    assert normalize_entity_value("asn", "as12345") == "AS12345"
    assert normalize_entity_value("hostname", "App.Prod.Example.COM.") == "app.prod.example.com"
    assert normalize_entity_value("ip", "  1.2.3.4  ") == "1.2.3.4"
    assert normalize_entity_value("org", "  Example Corp  ") == "Example Corp"


def test_deep_merge_attributes():
    existing = {"shodan": [{"observed_at": "2026-05-14", "ports": [80, 443]}]}
    incoming = {"shodan": [{"observed_at": "2026-05-16", "ports": [443]}]}
    result = deep_merge_attributes(existing, incoming)
    assert result["shodan"][0]["observed_at"] == "2026-05-14"
    assert result["shodan"][1]["observed_at"] == "2026-05-16"



