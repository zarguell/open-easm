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


# --- Task 3: Email pattern derivation ---


def test_email_pattern_from_domain():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Contact: admin@example.com")
    email_matches = [m for m in matches if m.keyword_type == "email"]
    assert len(email_matches) >= 1
    assert "admin@example.com" in email_matches[0].matched_text


def test_email_pattern_different_username():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Contact: zach@example.com")
    email_matches = [m for m in matches if m.keyword_type == "email"]
    assert len(email_matches) >= 1
    assert "zach@example.com" in email_matches[0].matched_text


def test_email_pattern_severity_high():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Contact: admin@example.com")
    email_matches = [m for m in matches if m.keyword_type == "email"]
    assert email_matches[0].severity == "high"


def test_email_pattern_no_false_positive():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Contact: admin@example.com.phishing.org")
    email_matches = [m for m in matches if m.keyword_type == "email"]
    assert len(email_matches) == 0


def test_email_and_domain_match_both_returned():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("internal.example.com and admin@example.com found")
    types_found = {m.keyword_type for m in matches}
    assert "domain" in types_found
    assert "email" in types_found


# --- Task 4: Custom regex pattern matching ---


def test_custom_regex_pattern_matches():
    from easm.config import TargetConfig, KeywordPattern
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={
            "domains": ["example.com"],
            "keyword_patterns": [
                {"type": "api_key", "pattern": "AKIA[0-9A-Z]{16}", "severity": "high"},
            ],
        },
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Found key: AKIA1234567890ABCDEF in log")
    regex_matches = [m for m in matches if m.keyword_type == "api_key"]
    assert len(regex_matches) == 1
    assert "AKIA1234567890ABCDEF" in regex_matches[0].matched_text


def test_custom_regex_multiple_matches():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={
            "domains": ["example.com"],
            "keyword_patterns": [
                {"type": "api_key", "pattern": "AKIA[0-9A-Z]{16}", "severity": "high"},
            ],
        },
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Keys: AKIA1111111111111111 and AKIA2222222222222222")
    regex_matches = [m for m in matches if m.keyword_type == "api_key"]
    assert len(regex_matches) == 2


def test_custom_regex_no_match():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={
            "domains": ["example.com"],
            "keyword_patterns": [
                {"type": "api_key", "pattern": "AKIA[0-9A-Z]{16}", "severity": "high"},
            ],
        },
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("No keys here, just example.com")
    regex_matches = [m for m in matches if m.keyword_type == "api_key"]
    assert len(regex_matches) == 0


def test_custom_regex_custom_severity():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={
            "domains": ["example.com"],
            "keyword_patterns": [
                {"type": "hostname", "pattern": "internal\\.example\\.com", "severity": "high"},
                {"type": "debug", "pattern": "DEBUG:", "severity": "low"},
            ],
        },
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("DEBUG: internal.example.com is up")
    hostname_matches = [m for m in matches if m.keyword_type == "hostname"]
    debug_matches = [m for m in matches if m.keyword_type == "debug"]
    assert len(hostname_matches) == 1
    assert hostname_matches[0].severity == "high"
    assert len(debug_matches) == 1
    assert debug_matches[0].severity == "low"


# --- Task 5: Severity classification ---


def test_severity_high_for_domain_match():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("secret.example.com exposed!")
    assert all(m.severity == "high" for m in matches)


def test_severity_medium_for_keyword_match():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"keywords": ["Example Corp"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Found reference to Example Corp in log")
    assert all(m.severity == "medium" for m in matches)


def test_severity_override_from_custom_pattern():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={
            "keyword_patterns": [
                {"type": "critical_alert", "pattern": "CRITICAL:", "severity": "high"},
                {"type": "info_alert", "pattern": "INFO:", "severity": "low"},
            ],
        },
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("CRITICAL: system failure\nINFO: all good")
    critical = [m for m in matches if m.keyword_type == "critical_alert"]
    info = [m for m in matches if m.keyword_type == "info_alert"]
    assert len(critical) == 1
    assert critical[0].severity == "high"
    assert len(info) == 1
    assert info[0].severity == "low"


def test_severity_email_is_high():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={"domains": ["example.com"]},
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("admin@example.com exposed")
    email_matches = [m for m in matches if m.keyword_type == "email"]
    assert email_matches[0].severity == "high"


# --- Task 6: build_keyword_engine_for_target ---


def test_build_engine_from_target_id():
    from easm.config import Config, TargetConfig
    from easm.keywords import build_keyword_engine_for_target
    cfg = Config(targets=[
        TargetConfig(
            id="test", name="Test", type="org",
            match_rules={"domains": ["example.com"]},
            runners={},
        ),
    ])
    engine = build_keyword_engine_for_target(cfg, "test")
    assert engine is not None
    matches = engine.match("admin@example.com")
    assert len(matches) >= 1


def test_build_engine_returns_none_for_unknown_target():
    from easm.config import Config, TargetConfig
    from easm.keywords import build_keyword_engine_for_target
    cfg = Config(targets=[
        TargetConfig(
            id="test", name="Test", type="org",
            match_rules={"domains": ["example.com"]},
            runners={},
        ),
    ])
    engine = build_keyword_engine_for_target(cfg, "nonexistent")
    assert engine is None


def test_keyword_match_deduplication():
    from easm.config import TargetConfig
    target = TargetConfig(
        id="test", name="Test", type="org",
        match_rules={
            "domains": ["example.com"],
            "keywords": ["example.com"],
        },
        runners={},
    )
    engine = KeywordEngine(target)
    matches = engine.match("Visit example.com today")
    assert len(matches) >= 1
    types = [m.keyword_type for m in matches]
    assert types.count("domain") <= 1
