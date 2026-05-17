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


# --- Task 2: Domain-based keyword derivation ---


def test_domain_keyword_matches_apex():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Visit https://example.com today!")
    assert len(matches) >= 1
    domain_matches = [m for m in matches if m.keyword_type == "domain"]
    assert any("example.com" in m.matched_text for m in domain_matches)


def test_domain_keyword_matches_subdomain():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Internal server: git.internal.example.com")
    assert len(matches) >= 1
    domain_matches = [m for m in matches if m.keyword_type == "domain"]
    assert any("internal.example.com" in m.matched_text for m in domain_matches)


def test_domain_keyword_no_false_positive():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Visit https://malicious-example.com.phishing.com!")
    domain_matches = [m for m in matches if m.keyword_type == "domain"]
    assert len(domain_matches) == 0


def test_multiple_domains_all_matched():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com", "example.org"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Connect to api.example.com and mail.example.org")
    assert len(matches) >= 2
    matched_texts = {m.matched_text for m in matches}
    assert "api.example.com" in matched_texts
    assert "mail.example.org" in matched_texts


def test_domain_match_severity_is_high():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Found: internal.example.com")
    assert matches[0].severity == "high"
    assert matches[0].keyword_type == "domain"


def test_domain_match_returns_context():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Found: internal.example.com in the codebase")
    assert len(matches) == 1
    assert "internal.example.com" in matches[0].context
