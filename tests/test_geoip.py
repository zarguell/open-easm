import pytest
from unittest.mock import patch, MagicMock
from easm.geoip import GeoIpLookup, GeoIpResult


def test_geoip_lookup_returns_result():
    mock_reader = MagicMock()
    mock_reader.get.return_value = {
        "city": {"names": {"en": "Mountain View"}},
        "country": {"iso_code": "US", "names": {"en": "United States"}},
        "location": {"latitude": 37.386, "longitude": -122.0838},
    }
    lookup = GeoIpLookup(reader=mock_reader)
    result = lookup.lookup("8.8.8.8")
    assert isinstance(result, GeoIpResult)
    assert result.city == "Mountain View"
    assert result.country_code == "US"
    assert result.country_name == "United States"
    assert result.latitude == 37.386
    assert result.longitude == -122.0838


def test_geoip_lookup_returns_none_for_missing():
    mock_reader = MagicMock()
    mock_reader.get.return_value = None
    lookup = GeoIpLookup(reader=mock_reader)
    result = lookup.lookup("192.0.2.1")
    assert result is None


def test_geoip_result_to_dict():
    result = GeoIpResult(
        city="London",
        country_code="GB",
        country_name="United Kingdom",
        latitude=51.5074,
        longitude=-0.1278,
        asn=None,
        asn_org=None,
    )
    d = result.to_dict()
    assert d["city"] == "London"
    assert d["country_code"] == "GB"
    assert d["latitude"] == 51.5074
    assert d["longitude"] == -0.1278
