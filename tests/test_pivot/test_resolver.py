import pytest
from easm.pivot.resolver import PivotResolver


@pytest.mark.asyncio
async def test_resolver_disabled_when_pivot_not_configured():
    from easm.config import TargetConfig
    target = TargetConfig(id="t", name="t", type="org")
    resolver = PivotResolver(None)
    await resolver.check_and_enqueue(target, "domain", "example.com", None)
