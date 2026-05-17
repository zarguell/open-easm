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
