import pytest

from easm.pivot.handlers.subdomain_takeover import SubdomainTakeoverHandler, TAKEOVER_FINGERPRINTS


@pytest.mark.asyncio
async def test_takeover_handler_vulnerable_hostname():
    handler = SubdomainTakeoverHandler()
    results = await handler.execute({"entity_value": "test.github.io"}, None)
    assert len(results) == 1
    assert results[0]["takeover_check"]["takeover_risk"] is True
    assert len(results[0]["takeover_check"]["fingerprint_matches"]) == 1


@pytest.mark.asyncio
async def test_takeover_handler_safe_hostname():
    handler = SubdomainTakeoverHandler()
    results = await handler.execute({"entity_value": "safe.example.com"}, None)
    assert len(results) == 1
    assert results[0]["takeover_check"]["takeover_risk"] is False
    assert len(results[0]["takeover_check"]["fingerprint_matches"]) == 0


@pytest.mark.asyncio
async def test_takeover_handler_multiple_matches():
    handler = SubdomainTakeoverHandler()
    results = await handler.execute({"entity_value": "test.s3.amazonaws.com"}, None)
    assert results[0]["takeover_check"]["takeover_risk"] is True


def test_takeover_handler_class_attributes():
    assert SubdomainTakeoverHandler.pivot_type == "subdomain_takeover"
    assert SubdomainTakeoverHandler.source_name == "takeover"


def test_fingerprint_database_has_expected_entries():
    assert "github.io" in TAKEOVER_FINGERPRINTS
    assert "herokuapp.com" in TAKEOVER_FINGERPRINTS
    assert "s3.amazonaws.com" in TAKEOVER_FINGERPRINTS
    assert "azurewebsites.net" in TAKEOVER_FINGERPRINTS
    assert "cloudfront.net" in TAKEOVER_FINGERPRINTS
    assert len(TAKEOVER_FINGERPRINTS) == 10
