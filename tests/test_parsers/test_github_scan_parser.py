import pytest
from easm.parse.github_scan_parser import GithubScanParser


@pytest.mark.asyncio
async def test_github_scan_parser_gitleaks_finding():
    parser = GithubScanParser()
    event = {
        "raw": {
            "source": "gitleaks",
            "repository": "example/repo",
            "file": "config.env",
            "line": 42,
            "commit": "abc123",
            "secret": "fake_secret",
            "match": "password=s3cret",
            "domain": "example.com",
            "severity": "high",
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable

    findings = [e for e in result.entities if e.entity_type == "finding"]
    assert len(findings) == 1
    assert findings[0].attributes["source"] == "gitleaks"
    assert findings[0].attributes["repository"] == "example/repo"
    assert findings[0].attributes["file_path"] == "config.env"
    assert findings[0].attributes["severity"] == "high"


@pytest.mark.asyncio
async def test_github_scan_parser_github_search_finding():
    parser = GithubScanParser()
    event = {
        "raw": {
            "source": "github_search",
            "repository": "example/repo",
            "file_path": "src/config.py",
            "file_url": "https://github.com/example/repo/src/config.py",
            "query": "org:example.com password",
            "matched_keywords": [
                {"keyword": "acme", "match_type": "exact", "severity": "medium"},
            ],
            "fragments": ["acme password=secret"],
        }
    }
    result = await parser.parse(event)
    assert not result.unparseable

    findings = [e for e in result.entities if e.entity_type == "finding"]
    assert len(findings) == 1
    assert findings[0].attributes["matched_keyword"] == "acme"
    assert findings[0].attributes["severity"] == "medium"


@pytest.mark.asyncio
async def test_github_scan_parser_multiple_keywords():
    parser = GithubScanParser()
    event = {
        "raw": {
            "source": "github_search",
            "repository": "example/repo",
            "file_path": "src/config.py",
            "file_url": "https://github.com/example/repo/src/config.py",
            "matched_keywords": [
                {"keyword": "acme", "match_type": "exact", "severity": "medium"},
                {"keyword": "secret", "match_type": "exact", "severity": "high"},
            ],
        }
    }
    result = await parser.parse(event)
    findings = [e for e in result.entities if e.entity_type == "finding"]
    assert len(findings) == 2


@pytest.mark.asyncio
async def test_github_scan_parser_no_data_returns_unparseable():
    parser = GithubScanParser()
    event = {"raw": {}}
    result = await parser.parse(event)
    assert result.unparseable is True


@pytest.mark.asyncio
async def test_github_scan_parser_class_attributes():
    assert GithubScanParser.source_name == "github_scan"
    assert GithubScanParser.current_version == 1
