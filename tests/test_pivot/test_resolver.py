import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from easm.pivot.resolver import PivotResolver


def _make_defer_mock():
    """Create a mock for execute_pivot.configure(queue=...).defer_async."""
    defer_mock = AsyncMock()
    configured = MagicMock()
    configured.defer_async = defer_mock
    configure_mock = MagicMock(return_value=configured)
    return configure_mock, defer_mock


def _make_target(**overrides):
    from easm.config import TargetConfig

    defaults = {
        "id": "test-target",
        "name": "Test",
        "type": "org",
        "match_rules": {"domains": ["test-corp.com"]},
        "runners": {},
        "pivot": {
            "enabled": True,
            "max_depth": 3,
            "allowed_pivots": [
                {"from": "hostname", "to": "ip", "via": "dns_resolve"},
            ],
        },
    }
    defaults.update(overrides)
    return TargetConfig(**defaults)


@pytest.mark.asyncio
async def test_resolver_disabled_when_pivot_not_configured():
    from easm.config import TargetConfig

    target = TargetConfig(id="t", name="t", type="org")
    resolver = PivotResolver(None)
    await resolver.check_and_enqueue(target, "domain", "example.com", None)


@pytest.mark.asyncio
@patch("easm.tasks.pivot.execute_pivot")
async def test_resolver_skips_saas_hosted_entity(mock_execute_pivot, db_pool):
    """Should NOT enqueue pivot for saas-hosted entities."""
    pool = db_pool
    configure_mock, defer_mock = _make_defer_mock()
    mock_execute_pivot.configure = configure_mock

    entity_id = uuid.uuid7()
    await pool.execute(
        """INSERT INTO entities (id, org_id, target_id, entity_type, entity_value, attributes)
           VALUES ($1, $2, $3, $4, $5, $6::jsonb)""",
        entity_id, "default", "test-target", "hostname", "d3adb33f.cloudfront.net",
        json.dumps({"asset_classification": "saas-hosted", "provider": "aws"}),
    )

    target = _make_target()
    resolver = PivotResolver(pool)
    await resolver.check_and_enqueue(
        target, "hostname", "d3adb33f.cloudfront.net", entity_id,
        depth=1,
    )

    defer_mock.assert_not_called()


@pytest.mark.asyncio
@patch("easm.tasks.pivot.execute_pivot")
async def test_resolver_allows_org_owned_entity(mock_execute_pivot, db_pool):
    """Should enqueue pivot for org-owned entities."""
    pool = db_pool
    configure_mock, defer_mock = _make_defer_mock()
    mock_execute_pivot.configure = configure_mock

    entity_id = uuid.uuid7()
    await pool.execute(
        """INSERT INTO entities (id, org_id, target_id, entity_type, entity_value, attributes)
           VALUES ($1, $2, $3, $4, $5, $6::jsonb)""",
        entity_id, "default", "test-target", "hostname", "app.test-corp.com",
        json.dumps({"asset_classification": "org-owned"}),
    )

    target = _make_target()
    resolver = PivotResolver(pool)
    await resolver.check_and_enqueue(
        target, "hostname", "app.test-corp.com", entity_id,
        depth=1,
    )

    defer_mock.assert_called_once()


@pytest.mark.asyncio
@patch("easm.tasks.pivot.execute_pivot")
async def test_resolver_skips_third_party_integrated(mock_execute_pivot, db_pool):
    """Should NOT enqueue pivot for third-party-integrated entities."""
    pool = db_pool
    configure_mock, defer_mock = _make_defer_mock()
    mock_execute_pivot.configure = configure_mock

    entity_id = uuid.uuid7()
    await pool.execute(
        """INSERT INTO entities (id, org_id, target_id, entity_type, entity_value, attributes)
           VALUES ($1, $2, $3, $4, $5, $6::jsonb)""",
        entity_id, "default", "test-target", "hostname", "api.stripe.com",
        json.dumps({"asset_classification": "third-party-integrated"}),
    )

    target = _make_target(
        pivot={
            "enabled": True,
            "max_depth": 3,
            "allowed_pivots": [
                {"from": "hostname", "to": "ip", "via": "dns_resolve"},
            ],
            "scope_mode": "loose",
        },
    )
    resolver = PivotResolver(pool)
    await resolver.check_and_enqueue(
        target, "hostname", "api.stripe.com", entity_id,
        depth=1,
    )

    defer_mock.assert_not_called()


@pytest.mark.asyncio
@patch("easm.tasks.pivot.execute_pivot")
async def test_resolver_entity_without_classification_still_pivots(mock_execute_pivot, db_pool):
    """Entities with no classification (backwards compat) should still get pivots."""
    pool = db_pool
    configure_mock, defer_mock = _make_defer_mock()
    mock_execute_pivot.configure = configure_mock

    entity_id = uuid.uuid7()
    await pool.execute(
        """INSERT INTO entities (id, org_id, target_id, entity_type, entity_value, attributes)
           VALUES ($1, $2, $3, $4, $5, $6::jsonb)""",
        entity_id, "default", "test-target", "hostname", "legacy.test-corp.com",
        json.dumps({}),
    )

    target = _make_target()
    resolver = PivotResolver(pool)
    await resolver.check_and_enqueue(
        target, "hostname", "legacy.test-corp.com", entity_id,
        depth=1,
    )

    defer_mock.assert_called_once()
