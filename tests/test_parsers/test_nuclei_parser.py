import pytest
from easm.parse.nuclei_parser import NucleiParser


@pytest.mark.asyncio
async def test_nuclei_parser_extracts_vulnerability():
    parser = NucleiParser()
    event = {
        "raw": {
            "hostname": "example.com",
            "url": "https://example.com",
            "template-id": "CVE-2023-1234",
            "info": {
                "name": "SQL Injection",
                "severity": "critical",
                "description": "A SQL injection vulnerability was found",
            },
            "matched-at": "https://example.com/login",
            "curl-command": "curl -X POST https://example.com/login",
        }
    }
    result = await parser.parse(event)
    assert len(result.entities) == 1
    assert result.entities[0].entity_type == "hostname"
    assert result.entities[0].value == "example.com"
    vuln = result.entities[0].attributes["vulnerability"]
    assert vuln["template_id"] == "CVE-2023-1234"
    assert vuln["name"] == "SQL Injection"
    assert vuln["severity"] == "critical"
    assert not result.unparseable


@pytest.mark.asyncio
async def test_nuclei_parser_missing_hostname_unparseable():
    parser = NucleiParser()
    event = {"raw": {"template-id": "CVE-2023-1234", "info": {"name": "test"}}}
    result = await parser.parse(event)
    assert result.unparseable is True
    assert "missing hostname" in result.parse_error


@pytest.mark.asyncio
async def test_nuclei_parser_missing_template_id_unparseable():
    parser = NucleiParser()
    event = {"raw": {"hostname": "example.com", "info": {"name": "test"}}}
    result = await parser.parse(event)
    assert result.unparseable is True
    assert "nuclei data" in result.parse_error


@pytest.mark.asyncio
async def test_nuclei_parser_class_attributes():
    assert NucleiParser.source_name == "nuclei"
    assert NucleiParser.current_version == 1


@pytest.mark.asyncio
async def test_nuclei_parser_empty_raw_unparseable():
    parser = NucleiParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_nuclei_parser_no_relationships():
    parser = NucleiParser()
    event = {"raw": {"hostname": "example.com", "template-id": "test"}}
    result = await parser.parse(event)
    assert len(result.relationships) == 0


@pytest.mark.asyncio
async def test_nuclei_parser_defaults_for_missing_fields():
    parser = NucleiParser()
    event = {"raw": {"hostname": "example.com", "template-id": "CVE-2023-1"}}
    result = await parser.parse(event)
    vuln = result.entities[0].attributes["vulnerability"]
    assert vuln["name"] == ""
    assert vuln["severity"] == "unknown"
    assert vuln["description"] == ""
    assert vuln["matched_at"] == ""
    assert vuln["curl_command"] == ""
