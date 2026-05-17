import pytest
from easm.parse.urlscan_parser import UrlScanParser


@pytest.mark.asyncio
async def test_urlscan_parser_extracts_attributes():
    parser = UrlScanParser()
    event = {
        "raw": {
            "domain": "example.com",
            "urlscan": {
                "total_results": 5,
                "malicious_count": 1,
                "results": [
                    {
                        "page_url": "https://example.com/",
                        "ip": "93.184.216.34",
                        "domain": "example.com",
                        "is_malicious": False,
                        "screenshot_url": "https://urlscan.io/screenshots/abc123.png",
                    },
                    {
                        "page_url": "http://malicious.example.com/",
                        "ip": "203.0.113.5",
                        "domain": "malicious.example.com",
                        "is_malicious": True,
                        "screenshot_url": None,
                    },
                ],
                "malicious_urls": ["http://malicious.example.com/"],
            },
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable
    assert len(result.entities) == 1
    assert result.entities[0].entity_type == "domain"
    assert result.entities[0].value == "example.com"
    attrs = result.entities[0].attributes
    assert attrs["source"] == "urlscan"
    ti = attrs["threat_intel"]["urlscan"]
    assert ti["total_results"] == 5
    assert ti["malicious_count"] == 1
    assert len(ti["malicious_urls"]) == 1


@pytest.mark.asyncio
async def test_urlscan_parser_missing_domain():
    parser = UrlScanParser()
    event = {"raw": {"urlscan": {"total_results": 0}}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_urlscan_parser_missing_urlscan_data():
    parser = UrlScanParser()
    event = {"raw": {"domain": "example.com"}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_urlscan_parser_empty_raw():
    parser = UrlScanParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_urlscan_parser_class_attributes():
    assert UrlScanParser.source_name == "urlscan"
    assert UrlScanParser.current_version == 1
