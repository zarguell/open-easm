import pytest
from easm.parse.searchengine_parser import SearchEngineParser


@pytest.mark.asyncio
async def test_searchengine_parser_extracts_subdomain():
    parser = SearchEngineParser()
    result = await parser.parse({"raw": {
        "subdomain": "sub.example.com",
        "source_engine": "duckduckgo",
        "domain": "example.com",
    }})
    assert not result.unparseable
    assert len(result.entities) == 1
    assert result.entities[0].entity_type == "domain"
    assert result.entities[0].attributes["source"] == "searchengine"
    assert result.entities[0].attributes["source_engine"] == "duckduckgo"


@pytest.mark.asyncio
async def test_searchengine_parser_missing_subdomain():
    parser = SearchEngineParser()
    result = await parser.parse({"raw": {"domain": "example.com"}})
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_searchengine_parser_empty_raw():
    parser = SearchEngineParser()
    result = await parser.parse({"raw": {}})
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_searchengine_parser_class_attributes():
    assert SearchEngineParser.source_name == "searchengine"
    assert SearchEngineParser.current_version == 1
