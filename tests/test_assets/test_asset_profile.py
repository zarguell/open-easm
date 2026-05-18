from datetime import UTC, datetime

from easm.assets.profile import (
    build_asset_evidence,
    build_asset_profile,
    merge_asset_profiles,
)


OBSERVED_AT = datetime(2026, 5, 18, 12, 0, tzinfo=UTC)


def test_build_asset_evidence_records_source_and_summary():
    evidence = build_asset_evidence(
        source="subfinder",
        raw_event_id="00000000-0000-0000-0000-000000000001",
        observed_at=OBSERVED_AT,
        summary="subfinder returned app.example.invalid",
    )

    assert evidence == {
        "source": "subfinder",
        "raw_event_id": "00000000-0000-0000-0000-000000000001",
        "observed_at": "2026-05-18T12:00:00+00:00",
        "summary": "subfinder returned app.example.invalid",
    }


def test_build_asset_profile_scores_direct_target_match_high():
    evidence = [
        build_asset_evidence(
            source="subfinder",
            raw_event_id="id-1",
            observed_at=OBSERVED_AT,
            summary="subfinder returned app.example.invalid",
        ),
        build_asset_evidence(
            source="tls_cert",
            raw_event_id="id-2",
            observed_at=OBSERVED_AT,
            summary="tls cert observed app.example.invalid",
        ),
    ]

    profile = build_asset_profile(
        entity_type="hostname",
        entity_value="app.example.invalid",
        target_domains=["example.invalid"],
        sources=["subfinder", "tls_cert"],
        evidence=evidence,
        observed_at=OBSERVED_AT,
    )

    assert profile["confidence"]["level"] == "high"
    assert profile["confidence"]["score"] >= 80
    assert "direct_target_match" in profile["confidence"]["reasons"]
    assert "multi_source_seen" in profile["confidence"]["reasons"]
    assert profile["lifecycle"]["state"] == "active"
    assert profile["source_of_truth_feed"]["eligible"] is True


def test_ct_only_matching_target_is_capped_medium_and_feed_eligible():
    evidence = [
        build_asset_evidence(
            source="crtsh",
            raw_event_id="id-1",
            observed_at=OBSERVED_AT,
            summary="crtsh returned app.example.invalid",
        )
    ]

    profile = build_asset_profile(
        entity_type="hostname",
        entity_value="app.example.invalid",
        target_domains=["example.invalid"],
        sources=["crtsh"],
        evidence=evidence,
        observed_at=OBSERVED_AT,
    )

    assert profile["confidence"]["level"] == "medium"
    assert profile["confidence"]["score"] <= 60
    assert "certificate_only" in profile["confidence"]["reasons"]
    assert profile["source_of_truth_feed"]["eligible"] is True


def test_exact_domain_target_gets_direct_target_domain_bump():
    profile = build_asset_profile(
        entity_type="domain",
        entity_value="example.invalid",
        target_domains=["example.invalid"],
        sources=["seed"],
        evidence=[],
        observed_at=OBSERVED_AT,
    )

    assert profile["confidence"]["level"] == "high"
    assert profile["confidence"]["score"] >= 85
    assert "direct_target_domain" in profile["confidence"]["reasons"]


def test_configured_asn_target_is_feed_eligible_direct_match():
    profile = build_asset_profile(
        entity_type="asn",
        entity_value="AS64500",
        target_domains=[],
        target_asns=["AS64500"],
        sources=["asnmap"],
        evidence=[],
        observed_at=OBSERVED_AT,
    )

    assert profile["confidence"]["level"] == "medium"
    assert profile["confidence"]["score"] >= 60
    assert "direct_target_match" in profile["confidence"]["reasons"]
    assert profile["source_of_truth_feed"]["eligible"] is True


def test_asnmap_ip_range_is_feed_eligible():
    profile = build_asset_profile(
        entity_type="ip_range",
        entity_value="198.51.100.0/30",
        target_domains=[],
        sources=["asnmap"],
        evidence=[],
        observed_at=OBSERVED_AT,
    )

    assert profile["confidence"]["level"] == "medium"
    assert "asn_owned_range" in profile["confidence"]["reasons"]
    assert profile["source_of_truth_feed"]["eligible"] is True


def test_dns_confirmed_ip_is_feed_eligible():
    profile = build_asset_profile(
        entity_type="ip",
        entity_value="198.51.100.1",
        target_domains=[],
        sources=["dns"],
        evidence=[],
        observed_at=OBSERVED_AT,
    )

    assert profile["confidence"]["level"] == "medium"
    assert "dns_confirmed_ip" in profile["confidence"]["reasons"]
    assert profile["source_of_truth_feed"]["eligible"] is True


def test_build_asset_profile_dedupes_duplicate_evidence():
    evidence = build_asset_evidence(
        source="subfinder",
        raw_event_id="id-1",
        observed_at=OBSERVED_AT,
        summary="subfinder returned app.example.invalid",
    )

    profile = build_asset_profile(
        entity_type="hostname",
        entity_value="app.example.invalid",
        target_domains=["example.invalid"],
        sources=["subfinder"],
        evidence=[evidence, dict(evidence)],
        observed_at=OBSERVED_AT,
    )

    assert profile["evidence"] == [evidence]


def test_merge_asset_profiles_dedupes_sources_and_evidence():
    first = build_asset_profile(
        entity_type="hostname",
        entity_value="app.example.invalid",
        target_domains=["example.invalid"],
        sources=["subfinder"],
        evidence=[
            build_asset_evidence(
                source="subfinder",
                raw_event_id="id-1",
                observed_at=OBSERVED_AT,
                summary="subfinder returned app.example.invalid",
            )
        ],
        observed_at=OBSERVED_AT,
    )
    second = build_asset_profile(
        entity_type="hostname",
        entity_value="app.example.invalid",
        target_domains=["example.invalid"],
        sources=["tls_cert"],
        evidence=[
            build_asset_evidence(
                source="tls_cert",
                raw_event_id="id-2",
                observed_at=OBSERVED_AT,
                summary="tls cert observed app.example.invalid",
            )
        ],
        observed_at=OBSERVED_AT,
    )

    merged = merge_asset_profiles(first, second)

    assert merged["sources"] == ["subfinder", "tls_cert"]
    assert len(merged["evidence"]) == 2
    assert merged["confidence"]["level"] == "high"


def test_merge_asset_profiles_removes_stale_certificate_only_reason():
    ct_only = build_asset_profile(
        entity_type="hostname",
        entity_value="app.example.invalid",
        target_domains=["example.invalid"],
        sources=["crtsh"],
        evidence=[
            build_asset_evidence(
                source="crtsh",
                raw_event_id="id-1",
                observed_at=OBSERVED_AT,
                summary="crtsh returned app.example.invalid",
            )
        ],
        observed_at=OBSERVED_AT,
    )
    observed = build_asset_profile(
        entity_type="hostname",
        entity_value="app.example.invalid",
        target_domains=["example.invalid"],
        sources=["tls_cert"],
        evidence=[
            build_asset_evidence(
                source="tls_cert",
                raw_event_id="id-2",
                observed_at=OBSERVED_AT,
                summary="tls cert observed app.example.invalid",
            )
        ],
        observed_at=OBSERVED_AT,
    )

    merged = merge_asset_profiles(ct_only, observed)

    assert "certificate_only" not in merged["confidence"]["reasons"]
