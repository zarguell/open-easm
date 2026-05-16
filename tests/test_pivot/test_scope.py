import pytest
from easm.pivot.scope import ScopeEvaluator
from easm.models import ScopeResult


@pytest.fixture
def target():
    from easm.config import TargetConfig
    return TargetConfig(
        id="test", name="test", type="org",
        match_rules={"domains": ["example.com"], "asns": ["AS12345"]},
    )


def test_domain_in_scope(target):
    result = ScopeEvaluator().evaluate(target, "domain", "sub.example.com")
    assert result == ScopeResult.IN_SCOPE


def test_domain_out_of_scope(target):
    result = ScopeEvaluator().evaluate(target, "domain", "other.com")
    assert result == ScopeResult.OUT_OF_SCOPE


def test_asn_in_scope(target):
    result = ScopeEvaluator().evaluate(target, "asn", "AS12345")
    assert result == ScopeResult.IN_SCOPE


def test_asn_out_of_scope(target):
    result = ScopeEvaluator().evaluate(target, "asn", "AS99999")
    assert result == ScopeResult.OUT_OF_SCOPE


def test_unknown_type(target):
    result = ScopeEvaluator().evaluate(target, "org", "Some Corp")
    assert result == ScopeResult.UNKNOWN
