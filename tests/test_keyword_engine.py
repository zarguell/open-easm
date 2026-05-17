import pytest
from easm.keyword_engine import KeywordEngine, KeywordMatch
from easm.config import TargetConfig, MatchRules


def _make_target(domains: list[str] | None = None, keywords: list[str] | None = None) -> TargetConfig:
    return TargetConfig(
        id="test-target",
        name="Test Target",
        type="organization",
        match_rules=MatchRules(
            domains=domains or [],
            keywords=keywords or [],
        ),
    )


def test_keyword_engine_exact_match():
    target = _make_target(keywords=["acme corp", "secret project"])
    engine = KeywordEngine(target)
    matches = engine.match("The acme corp API key is exposed")
    assert len(matches) == 1
    assert matches[0].keyword == "acme corp"
    assert matches[0].match_type == "exact"
    assert matches[0].context == "The acme corp API key is exposed"


def test_keyword_engine_multiple_exact_matches():
    target = _make_target(keywords=["acme corp", "secret project"])
    engine = KeywordEngine(target)
    matches = engine.match("acme corp and secret project are both here")
    assert len(matches) == 2
    keywords_found = {m.keyword for m in matches}
    assert keywords_found == {"acme corp", "secret project"}


def test_keyword_engine_domain_match():
    target = _make_target(domains=["example.com", "acme.org"])
    engine = KeywordEngine(target)
    matches = engine.match("Contact us at admin@example.com for support")
    assert len(matches) == 1
    assert matches[0].keyword == "example.com"
    assert matches[0].match_type == "domain"


def test_keyword_engine_no_match_returns_empty():
    target = _make_target(keywords=["nothing"])
    engine = KeywordEngine(target)
    matches = engine.match("completely unrelated text")
    assert matches == []


def test_keyword_engine_case_insensitive_by_default():
    target = _make_target(keywords=["Acme Corp"])
    engine = KeywordEngine(target)
    matches = engine.match("found ACME CORP credentials")
    assert len(matches) == 1


def test_keyword_engine_custom_patterns():
    target = _make_target(keywords=["acme"])
    custom = [
        {"pattern": r"sk-[a-zA-Z0-9]{20,}", "severity": "high", "label": "openai_key"},
        {"pattern": r"ghp_[a-zA-Z0-9]{36}", "severity": "high", "label": "github_token"},
    ]
    engine = KeywordEngine(target, custom_patterns=custom)
    matches = engine.match("sk-projAbCdEf1234567890AbCdEf12 and ghp_abc123def456ghi789jkl012mno345pqr678")
    assert len(matches) == 2
    assert all(m.match_type == "regex" for m in matches)
    assert all(m.severity == "high" for m in matches)


def test_keyword_engine_context_surrounding_text():
    target = _make_target(keywords=["secret"])
    engine = KeywordEngine(target)
    text = "the quick brown fox jumps over the secret door and runs away".ljust(200)
    match = engine.match(text)[0]
    assert "secret" in match.context
    assert len(match.context) <= 200


def test_keyword_engine_with_empty_target():
    target = _make_target()
    engine = KeywordEngine(target)
    matches = engine.match("anything at all")
    assert matches == []


@pytest.mark.asyncio
async def test_keyword_engine_severity_defaults_to_medium():
    target = _make_target(keywords=["test"])
    engine = KeywordEngine(target)
    matches = engine.match("this is a test pattern")
    assert matches[0].severity == "medium"
