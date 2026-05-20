from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Any

from easm.config import SaasProviderConfig


@dataclass
class ClassificationResult:
    classification: str = "org-owned"
    provider: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "asset_classification": self.classification,
        }
        if self.provider:
            d["provider"] = self.provider
        return d


def classify_entity(
    entity_type: str,
    entity_value: str,
    target_domains: list[str] | None = None,
    saas_rules: SaasProviderConfig | None = None,
) -> ClassificationResult:
    if entity_type not in ("domain", "hostname"):
        return ClassificationResult()

    entity_lower = entity_value.lower()

    if saas_rules:
        for rule in saas_rules.rules:
            if fnmatch.fnmatch(entity_lower, rule.pattern):
                return ClassificationResult(
                    classification=rule.classification,
                    provider=rule.provider,
                )

    return ClassificationResult()


def classify_cname_hosting(
    hostname: str,
    cname_target: str | None,
    saas_rules: SaasProviderConfig | None = None,
) -> dict[str, str]:
    """Derive hosting metadata for an org-owned hostname from its CNAME target.

    Returns a dict with hosting_provider, hosting_classification, and cname_target
    when the CNAME target matches a known SaaS provider pattern.
    Returns empty dict when no match or no CNAME target.
    """
    if not cname_target or not saas_rules:
        return {}
    target_lower = cname_target.lower()
    for rule in saas_rules.rules:
        if fnmatch.fnmatch(target_lower, rule.pattern):
            return {
                "hosting_provider": rule.provider,
                "hosting_classification": rule.classification,
                "cname_target": cname_target,
            }
    return {}
