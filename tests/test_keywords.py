import pytest
from easm.keywords import KeywordMatch, KeywordEngine


def test_keyword_match_dataclass_defaults():
    match = KeywordMatch(
        keyword="example.com",
        keyword_type="domain",
        matched_text="example.com",
        severity="high",
        context="Found example.com in log",
    )
    assert match.keyword == "example.com"
    assert match.keyword_type == "domain"
    assert match.matched_text == "example.com"
    assert match.severity == "high"
    assert match.context == "Found example.com in log"


def test_keyword_match_with_default_context():
    match = KeywordMatch(
        keyword="secret",
        keyword_type="keyword",
        matched_text="secret",
        severity="medium",
    )
    assert match.context == ""


def test_keyword_engine_requires_target_config():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"], "keywords": ["Example Corp"]},
        runners={},
    )
    engine = KeywordEngine(target)
    assert engine is not None


def test_keyword_engine_empty_target_returns_empty():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("nothing relevant here")
    assert matches == []


def test_keyword_engine_class_attributes():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    assert hasattr(engine, "match")
    assert callable(engine.match)
