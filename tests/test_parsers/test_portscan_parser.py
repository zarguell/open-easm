import pytest
from easm.parse.portscan_parser import PortScanParser


@pytest.mark.asyncio
async def test_portscan_parser_extracts_ports():
    parser = PortScanParser()
    event = {
        "raw": {
            "hostname": "example.com",
            "ip": "93.184.216.34",
            "ports": [
                {"port": 80, "protocol": "tcp", "service": "http"},
                {"port": 443, "protocol": "tcp", "service": "https"},
            ],
        }
    }
    result = await parser.parse(event)
    assert len(result.entities) == 2
    assert result.entities[0].entity_type == "hostname"
    assert result.entities[0].value == "example.com"
    assert len(result.entities[0].attributes["open_ports"]) == 2
    assert result.entities[1].entity_type == "ip"
    assert result.entities[1].value == "93.184.216.34"
    assert not result.unparseable


@pytest.mark.asyncio
async def test_portscan_parser_missing_hostname_unparseable():
    parser = PortScanParser()
    event = {"raw": {"ip": "1.2.3.4", "ports": [{"port": 80, "protocol": "tcp", "service": "http"}]}}
    result = await parser.parse(event)
    assert result.unparseable is True
    assert result.parse_error == "missing hostname"


@pytest.mark.asyncio
async def test_portscan_parser_empty_ports_unparseable():
    parser = PortScanParser()
    event = {"raw": {"hostname": "example.com", "ip": "1.2.3.4", "ports": []}}
    result = await parser.parse(event)
    assert result.unparseable is True
    assert result.parse_error == "no open ports"


@pytest.mark.asyncio
async def test_portscan_parser_no_ip_omits_ip_entity():
    parser = PortScanParser()
    event = {
        "raw": {
            "hostname": "example.com",
            "ports": [{"port": 22, "protocol": "tcp", "service": "ssh"}],
        }
    }
    result = await parser.parse(event)
    assert len(result.entities) == 1
    assert result.entities[0].entity_type == "hostname"


@pytest.mark.asyncio
async def test_portscan_parser_class_attributes():
    assert PortScanParser.source_name == "portscan"
    assert PortScanParser.current_version == 1


@pytest.mark.asyncio
async def test_portscan_parser_no_relationships():
    parser = PortScanParser()
    event = {
        "raw": {
            "hostname": "example.com",
            "ip": "1.2.3.4",
            "ports": [{"port": 80, "protocol": "tcp", "service": "http"}],
        }
    }
    result = await parser.parse(event)
    assert len(result.relationships) == 0


@pytest.mark.asyncio
async def test_portscan_parser_empty_raw_unparseable():
    parser = PortScanParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True
