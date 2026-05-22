import json

from easm.assets.export import asset_to_source_of_truth_record, assets_to_ndjson


def test_asset_to_source_of_truth_record_is_outbound_only():
    record = asset_to_source_of_truth_record(
        {
            "entity_id": "entity-1",
            "target_id": "target-1",
            "entity_type": "hostname",
            "entity_value": "app.example.invalid",
            "confidence_score": 91,
            "confidence_level": "high",
            "risk_score": 42,
            "risk_level": "medium",
            "sources": ["subfinder"],
            "first_seen_at": "2026-05-18T12:00:00+00:00",
            "last_seen_at": "2026-05-18T12:30:00+00:00",
            "evidence_count": 1,
        }
    )

    assert record["external_id"] == "open-easm:entity-1"
    assert record["system_of_record"] == "open-easm"
    assert record["asset"] == {"type": "hostname", "value": "app.example.invalid"}
    assert record["confidence"] == {"score": 91, "level": "high"}
    assert record["risk"] == {"score": 42, "level": "medium"}
    assert record["evidence_count"] == 1
    assert "owner" not in record


def test_assets_to_ndjson_outputs_one_json_object_per_line():
    ndjson = assets_to_ndjson(
        [
            {
                "entity_id": "entity-1",
                "target_id": "target-1",
                "entity_type": "hostname",
                "entity_value": "app.example.invalid",
                "confidence_score": 91,
                "confidence_level": "high",
                "risk_score": 42,
                "risk_level": "medium",
                "sources": ["subfinder"],
                "first_seen_at": "2026-05-18T12:00:00+00:00",
                "last_seen_at": "2026-05-18T12:30:00+00:00",
                "evidence_count": 1,
            },
            {
                "entity_id": "entity-2",
                "target_id": "target-1",
                "entity_type": "ip",
                "entity_value": "192.0.2.10",
                "confidence_score": 80,
                "confidence_level": "medium",
                "risk_score": 10,
                "risk_level": "low",
                "sources": [],
                "first_seen_at": "2026-05-18T12:00:00+00:00",
                "last_seen_at": "2026-05-18T12:30:00+00:00",
            },
        ]
    )

    lines = ndjson.splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["external_id"] == "open-easm:entity-1"
    assert json.loads(lines[1])["asset"]["value"] == "192.0.2.10"
