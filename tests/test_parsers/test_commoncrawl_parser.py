import pytest
from easm.parse.commoncrawl_parser import CommonCrawlParser


@pytest.mark.asyncio
async def test_commoncrawl_parser_extracts_domain():
    parser = CommonCrawlParser()
    result = await parser.parse({"raw": {"url": "https://sub.example.com/path", "domain": "example.com"}})
    assert not result.unparseable
    assert len(result.entities) == 1
    assert result.entities[0].entity_type == "domain"
    assert result.entities[0].attributes["source"] == "commoncrawl"


@pytest.mark.asyncio
async def test_commoncrawl_parser_missing_url():
    parser = CommonCrawlParser()
    result = await parser.parse({"raw": {"domain": "example.com"}})
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_commoncrawl_parser_empty_raw():
    parser = CommonCrawlParser()
    result = await parser.parse({"raw": {}})
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_commoncrawl_parser_class_attributes():
    assert CommonCrawlParser.source_name == "commoncrawl"
    assert CommonCrawlParser.current_version == 1


def test_commoncrawl_extract_subdomain():
    from easm.parse.commoncrawl_parser import CommonCrawlParser
    assert CommonCrawlParser._extract_subdomain("https://sub.example.com/path") == "example.com"
    assert CommonCrawlParser._extract_subdomain("https://example.com/") == "example.com"
    assert CommonCrawlParser._extract_subdomain("http://deep.sub.example.com:8080/x") == "example.com"
