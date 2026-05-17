import json
import uuid

import pytest
from easm.pivot.resolver import PivotResolver


@pytest.mark.asyncio
async def test_resolver_disabled_when_pivot_not_configured():
    from easm.config import TargetConfig
    target = TargetConfig(id="t", name="t", type="org")
    resolver = PivotResolver(None)
    await resolver.check_and_enqueue(target, "domain", "example.com", None)


@pytest.mark.asyncio
async def test_resolver_skips_saas_hosted_entity(db_pool):
    """Should NOT enqueue pivot for saas-hosted entities."""
    from easm.config import TargetConfig
    pool = db_pool

    entity_id = uuid.uuid7()
    await pool.execute(
        """INSERT INTO entities (id, org_id, target_id, entity_type, entity_value, attributes)
           VALUES ($1, $2, $3, $4, $5, $6::jsonb)""",
        entity_id, "default", "test-target", "hostname", "d3adb33f.cloudfront.net",
        json.dumps({"asset_classification": "saas-hosted", "provider": "aws"}),
    )

    target = TargetConfig(
        id="test-target", name="Test", type="org",
        match_rules={"domains": ["test-corp.com"]},
        runners={},
        pivot={"enabled": True, "max_depth": 3, "allowed_pivots": [{"from": "hostname", "to": "ip", "via": "dns_resolve"}]},
    )

    resolver = PivotResolver(pool)
    await resolver.check_and_enqueue(
        target, "hostname", "d3adb33f.cloudfront.net", entity_id,
        depth=1,
    )

    remaining = await pool.fetchval("SELECT COUNT(*) FROM pivot_queue")
    assert remaining == 0, "Should not enqueue pivot for saas-hosted entity"


@pytest.mark.asyncio
async def test_resolver_allows_org_owned_entity(db_pool):
    """Should enqueue pivot for org-owned entities."""
    from easm.config import TargetConfig
    pool = db_pool

    entity_id = uuid.uuid7()
    await pool.execute(
        """INSERT INTO entities (id, org_id, target_id, entity_type, entity_value, attributes)
           VALUES ($1, $2, $3, $4, $5, $6::jsonb)""",
        entity_id, "default", "test-target", "hostname", "app.test-corp.com",
        json.dumps({"asset_classification": "org-owned"}),
    )

    target = TargetConfig(
        id="test-target", name="Test", type="org",
        match_rules={"domains": ["test-corp.com"]},
        runners={},
        pivot={"enabled": True, "max_depth": 3, "allowed_pivots": [{"from": "hostname", "to": "ip", "via": "dns_resolve"}]},
    )

    resolver = PivotResolver(pool)
    await resolver.check_and_enqueue(
        target, "hostname", "app.test-corp.com", entity_id,
        depth=1,
    )

    remaining = await pool.fetchval("SELECT COUNT(*) FROM pivot_queue")
    assert remaining == 1, "Should enqueue pivot for org-owned entity"


@pytest.mark.asyncio
async def test_resolver_skips_third_party_integrated(db_pool):
    """Should NOT enqueue pivot for third-party-integrated entities."""
    from easm.config import TargetConfig
    pool = db_pool

    entity_id = uuid.uuid7()
    await pool.execute(
        """INSERT INTO entities (id, org_id, target_id, entity_type, entity_value, attributes)
           VALUES ($1, $2, $3, $4, $5, $6::jsonb)""",
        entity_id, "default", "test-target", "hostname", "api.stripe.com",
        json.dumps({"asset_classification": "third-party-integrated"}),
    )

    target = TargetConfig(
        id="test-target", name="Test", type="org",
        match_rules={"domains": ["test-corp.com"]},
        runners={},
        pivot={"enabled": True, "max_depth": 3,
               "allowed_pivots": [{"from": "hostname", "to": "ip", "via": "dns_resolve"}],
               "scope_mode": "loose"},
    )

    resolver = PivotResolver(pool)
    await resolver.check_and_enqueue(
        target, "hostname", "api.stripe.com", entity_id,
        depth=1,
    )

    remaining = await pool.fetchval("SELECT COUNT(*) FROM pivot_queue")
    assert remaining == 0, "Should not enqueue pivot for third-party-integrated entity"


@pytest.mark.asyncio
async def test_resolver_entity_without_classification_still_pivots(db_pool):
    """Entities with no classification (backwards compat) should still get pivots."""
    from easm.config import TargetConfig
    pool = db_pool

    entity_id = uuid.uuid7()
    await pool.execute(
        """INSERT INTO entities (id, org_id, target_id, entity_type, entity_value, attributes)
           VALUES ($1, $2, $3, $4, $5, $6::jsonb)""",
        entity_id, "default", "test-target", "hostname", "legacy.test-corp.com",
        json.dumps({}),
    )

    target = TargetConfig(
        id="test-target", name="Test", type="org",
        match_rules={"domains": ["test-corp.com"]},
        runners={},
        pivot={"enabled": True, "max_depth": 3, "allowed_pivots": [{"from": "hostname", "to": "ip", "via": "dns_resolve"}]},
    )

    resolver = PivotResolver(pool)
    await resolver.check_and_enqueue(
        target, "hostname", "legacy.test-corp.com", entity_id,
        depth=1,
    )

    remaining = await pool.fetchval("SELECT COUNT(*) FROM pivot_queue")
    assert remaining == 1, "Should enqueue pivot for entity with no classification (backwards compat)"
