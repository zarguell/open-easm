"""Tests for entity value canonicalization."""

from easm.entity_store import normalize_entity_value


def test_ipv4_canonicalization():
    assert normalize_entity_value("ip", "203.0.113.005") == "203.0.113.5"
    assert normalize_entity_value("ip", "1.2.3.4") == "1.2.3.4"


def test_ip_with_port_stripped():
    assert normalize_entity_value("ip", "1.2.3.4:443") == "1.2.3.4"


def test_ipv6_canonicalized():
    result = normalize_entity_value("ip", "2001:db8::1")
    assert result == "2001:db8::1"


def test_asn_prefix_normalized():
    assert normalize_entity_value("asn", "AS15169") == "AS15169"
    assert normalize_entity_value("asn", "ASN15169") == "AS15169"
    assert normalize_entity_value("asn", "15169") == "AS15169"


def test_wildcard_stripped():
    assert normalize_entity_value("domain", "*.example.com") == "example.com"


def test_quote_stripped():
    assert normalize_entity_value("domain", '"example.com"') == "example.com"
