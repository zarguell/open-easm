import pytest
from easm.parse.subdomain_takeover_parser import SubdomainTakeoverParser


@pytest.mark.asyncio
async def test_takeover_parser_vulnerable_hostname():
    parser = SubdomainTakeoverParser()
    result = await parser.parse({"raw": {
        "hostname": "test.github.io",
        "takeover_check": {
            "fingerprint_matches": [{"pattern": "github.io", "service": "github_pages"}],
            "takeover_risk": True,
        },
    }})
    assert not result.unparseable
    assert len(result.entities) == 1
    attrs = result.entities[0].attributes
    assert attrs["takeover_risk"] is True
    assert len(attrs["fingerprint_matches"]) == 1


@pytest.mark.asyncio
async def test_takeover_parser_not_vulnerable():
    parser = SubdomainTakeoverParser()
    result = await parser.parse({"raw": {
        "hostname": "safe.example.com",
        "takeover_check": {
            "fingerprint_matches": [],
            "takeover_risk": False,
        },
    }})
    assert not result.unparseable
    assert result.entities[0].attributes["takeover_risk"] is False


@pytest.mark.asyncio
async def test_takeover_parser_missing_hostname():
    parser = SubdomainTakeoverParser()
    result = await parser.parse({"raw": {"takeover_check": {"takeover_risk": False}}})
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_takeover_parser_missing_takeover_data():
    parser = SubdomainTakeoverParser()
    result = await parser.parse({"raw": {"hostname": "test.com"}})
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_takeover_parser_class_attributes():
    assert SubdomainTakeoverParser.source_name == "takeover"
    assert SubdomainTakeoverParser.current_version == 1
