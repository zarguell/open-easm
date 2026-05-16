import pytest
from easm.parse.subfinder_parser import SubfinderParser


@pytest.mark.asyncio
async def test_subfinder_parser_returns_domain():
    parser = SubfinderParser()
    event = {"raw": {"host": "app.example.com"}}
    result = await parser.parse(event)
    assert len(result.entities) == 1
    assert result.entities[0].entity_type == "domain"
    assert result.entities[0].value == "app.example.com"
    assert not result.unparseable


@pytest.mark.asyncio
async def test_subfinder_parser_empty_returns_unparseable():
    parser = SubfinderParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True
    assert result.parse_error == "no host field"


@pytest.mark.asyncio
async def test_subfinder_parser_missing_host_returns_unparseable():
    parser = SubfinderParser()
    event = {"raw": {"something": "else"}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_subfinder_parser_strips_whitespace():
    parser = SubfinderParser()
    event = {"raw": {"host": "  example.com  "}}
    result = await parser.parse(event)
    assert result.entities[0].value == "example.com"


@pytest.mark.asyncio
async def test_subfinder_parser_no_relationships():
    parser = SubfinderParser()
    event = {"raw": {"host": "example.com"}}
    result = await parser.parse(event)
    assert len(result.relationships) == 0


@pytest.mark.asyncio
async def test_subfinder_parser_class_attributes():
    assert SubfinderParser.source_name == "subfinder"
    assert SubfinderParser.current_version == 1
