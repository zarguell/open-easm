from __future__ import annotations

import json
from typing import Any


def asset_to_source_of_truth_record(asset: dict[str, Any]) -> dict[str, Any]:
    record = {
        "external_id": f"open-easm:{asset['entity_id']}",
        "system_of_record": "open-easm",
        "target_id": asset.get("target_id"),
        "asset": {
            "type": asset.get("entity_type"),
            "value": asset.get("entity_value"),
        },
        "confidence": {
            "score": asset.get("confidence_score"),
            "level": asset.get("confidence_level"),
        },
        "risk": {
            "score": asset.get("risk_score"),
            "level": asset.get("risk_level"),
        },
        "sources": asset.get("sources", []),
        "first_seen_at": asset.get("first_seen_at"),
        "last_seen_at": asset.get("last_seen_at"),
    }
    if "evidence_count" in asset:
        record["evidence_count"] = asset["evidence_count"]
    return record


def assets_to_ndjson(assets: list[dict[str, Any]]) -> str:
    return "\n".join(
        json.dumps(asset_to_source_of_truth_record(asset), sort_keys=True)
        for asset in assets
    )
