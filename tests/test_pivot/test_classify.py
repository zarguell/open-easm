from easm.classify import classify_entity, classify_cname_hosting
from easm.config import SaasProviderConfig, SaasProviderRule


def test_classify_cname_hosting_detects_github_pages():
    """classify_cname_hosting should detect GitHub Pages from CNAME target."""
    rules = SaasProviderConfig(rules=[
        SaasProviderRule(pattern="*.github.io", provider="github-pages", classification="saas-hosted"),
    ])
    result = classify_cname_hosting("www.arguelles.me", "username.github.io", rules)
    assert result["hosting_provider"] == "github-pages"
    assert result["hosting_classification"] == "saas-hosted"
    assert result["cname_target"] == "username.github.io"


def test_classify_cname_hosting_returns_empty_when_no_match():
    """classify_cname_hosting should return empty dict when CNAME target is not a known SaaS."""
    rules = SaasProviderConfig(rules=[
        SaasProviderRule(pattern="*.github.io", provider="github-pages", classification="saas-hosted"),
    ])
    result = classify_cname_hosting("www.example.com", "cdn.example-cdn.com", rules)
    assert result == {}


def test_classify_cname_hosting_returns_empty_when_no_cname():
    """classify_cname_hosting should return empty dict when no CNAME target provided."""
    rules = SaasProviderConfig(rules=[])
    result = classify_cname_hosting("www.example.com", None, rules)
    assert result == {}


def test_classify_cname_hosting_returns_empty_when_no_rules():
    """classify_cname_hosting should return empty dict when no SaaS rules configured."""
    result = classify_cname_hosting("www.example.com", "something.github.io", None)
    assert result == {}


def test_existing_classify_entity_unchanged():
    """classify_entity should still work as before — no regression."""
    rules = SaasProviderConfig(rules=[
        SaasProviderRule(pattern="*.github.io", provider="github-pages", classification="saas-hosted"),
    ])
    result = classify_entity("hostname", "something.github.io", saas_rules=rules)
    assert result.classification == "saas-hosted"
    assert result.provider == "github-pages"

    result2 = classify_entity("hostname", "www.arguelles.me", saas_rules=rules)
    assert result2.classification == "org-owned"
