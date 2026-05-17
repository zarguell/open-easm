import pytest
from easm.classify import classify_entity, ClassificationResult
from easm.config import SaasProviderRule, SaasProviderConfig


def test_classify_domain_org_owned():
    rules = SaasProviderConfig(rules=[
        SaasProviderRule(pattern="*.amazonaws.com", provider="aws", classification="saas-hosted"),
    ])
    result = classify_entity(
        entity_type="domain",
        entity_value="example.com",
        target_domains=["example.com"],
        saas_rules=rules,
    )
    assert result == ClassificationResult(classification="org-owned", provider=None)


def test_classify_domain_saas_hosted():
    rules = SaasProviderConfig(rules=[
        SaasProviderRule(pattern="*.amazonaws.com", provider="aws", classification="saas-hosted"),
        SaasProviderRule(pattern="*.cloudfront.net", provider="aws", classification="saas-hosted"),
    ])
    result = classify_entity(
        entity_type="domain",
        entity_value="d2x3y4z5.cloudfront.net",
        target_domains=["example.com"],
        saas_rules=rules,
    )
    assert result.classification == "saas-hosted"
    assert result.provider == "aws"


def test_classify_hostname_saas_hosted():
    rules = SaasProviderConfig(rules=[
        SaasProviderRule(pattern="*.amazonaws.com", provider="aws", classification="saas-hosted"),
    ])
    result = classify_entity(
        entity_type="hostname",
        entity_value="ec2-54-123-45-67.us-west-2.compute.amazonaws.com",
        target_domains=["example.com"],
        saas_rules=rules,
    )
    assert result.classification == "saas-hosted"
    assert result.provider == "aws"


def test_classify_no_rules_returns_org_owned():
    rules = SaasProviderConfig()
    result = classify_entity(
        entity_type="domain",
        entity_value="sub.example.com",
        target_domains=["example.com"],
        saas_rules=rules,
    )
    assert result == ClassificationResult(classification="org-owned", provider=None)


def test_classify_no_target_domains_returns_unknown():
    rules = SaasProviderConfig(rules=[
        SaasProviderRule(pattern="*.amazonaws.com", provider="aws", classification="saas-hosted"),
    ])
    result = classify_entity(
        entity_type="domain",
        entity_value="some-random-domain.com",
        target_domains=[],
        saas_rules=rules,
    )
    assert result.classification == "org-owned"


def test_classify_ip_with_no_rules_org_owned():
    rules = SaasProviderConfig()
    result = classify_entity(
        entity_type="ip",
        entity_value="1.2.3.4",
        target_domains=["example.com"],
        saas_rules=rules,
    )
    assert result.classification == "org-owned"


def test_classify_certificate_returns_org_owned():
    rules = SaasProviderConfig()
    result = classify_entity(
        entity_type="certificate",
        entity_value="abcdef1234567890",
        target_domains=["example.com"],
        saas_rules=rules,
    )
    assert result.classification == "org-owned"


def test_classify_asn_returns_org_owned():
    result = classify_entity(entity_type="asn", entity_value="AS12345", target_domains=["example.com"])
    assert result.classification == "org-owned"


def test_classify_glob_pattern_matching():
    rules = SaasProviderConfig(rules=[
        SaasProviderRule(pattern="*.azurewebsites.net", provider="azure", classification="saas-hosted"),
        SaasProviderRule(pattern="*.googleapis.com", provider="gcp", classification="saas-hosted"),
    ])
    result = classify_entity(
        entity_type="hostname",
        entity_value="myapp.azurewebsites.net",
        target_domains=["example.com"],
        saas_rules=rules,
    )
    assert result.classification == "saas-hosted"
    assert result.provider == "azure"


def test_classify_non_matching_glob_returns_org_owned():
    rules = SaasProviderConfig(rules=[
        SaasProviderRule(pattern="*.amazonaws.com", provider="aws", classification="saas-hosted"),
    ])
    result = classify_entity(
        entity_type="hostname",
        entity_value="myapp.herokuapp.com",
        target_domains=["example.com"],
        saas_rules=rules,
    )
    assert result.classification == "org-owned"


def test_classify_result_to_dict():
    result = ClassificationResult(classification="saas-hosted", provider="aws")
    d = result.to_dict()
    assert d["asset_classification"] == "saas-hosted"
    assert d["provider"] == "aws"


def test_classify_result_defaults():
    result = ClassificationResult()
    assert result.classification == "org-owned"
    assert result.provider is None
