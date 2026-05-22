from datetime import datetime, timezone

import pytest

from easm.certificates.profile import (
    build_certificate_profile,
    merge_certificate_profiles,
    parse_cert_datetime,
)


def test_parse_cert_datetime_accepts_date_and_iso_strings():
    assert parse_cert_datetime("2026-05-01").isoformat() == "2026-05-01T00:00:00+00:00"
    assert (
        parse_cert_datetime("2026-05-01T12:30:00Z").isoformat()
        == "2026-05-01T12:30:00+00:00"
    )


def test_build_certificate_profile_from_crtsh_normalizes_ct_fields():
    observed_at = datetime(2026, 5, 18, tzinfo=timezone.utc)

    profile = build_certificate_profile(
        source="crtsh",
        raw={
            "fingerprint": "ABCD",
            "serial_number": "01",
            "issuer_name_id": "123",
            "not_before": "2026-01-01",
            "not_after": "2026-06-01",
            "name_value": "www.example.invalid\napi.example.invalid",
        },
        observed_at=observed_at,
    )

    assert profile["fingerprint_sha256"] == "abcd"
    assert profile["issuer"]["name_id"] == "123"
    assert profile["san_dns_names"] == ["api.example.invalid", "www.example.invalid"]
    assert profile["ct"]["seen"] is True
    assert profile["deployment"]["state"] == "ct_only"
    assert profile["validity_days"] == 151


def test_build_certificate_profile_from_tls_cert_records_deployed_endpoint():
    observed_at = datetime(2026, 5, 18, tzinfo=timezone.utc)

    profile = build_certificate_profile(
        source="tls_cert",
        raw={
            "hostname": "www.example.invalid",
            "port": 443,
            "cert": {
                "fingerprint_sha256": "abcd",
                "subject_cn": "www.example.invalid",
                "issuer_cn": "Example Issuing CA",
                "issuer_org": "Example CA",
                "not_before": "2026-01-01T00:00:00+00:00",
                "not_after": "2026-06-01T00:00:00+00:00",
                "san_dns_names": ["www.example.invalid"],
                "public_key_algorithm": "RSA",
                "public_key_size_bits": 2048,
                "signature_algorithm": "sha256WithRSAEncryption",
                "signature_hash_algorithm": "sha256",
                "is_ca": False,
                "key_usage": ["digital_signature", "key_encipherment"],
                "extended_key_usage": ["server_auth"],
            },
        },
        observed_at=observed_at,
    )

    assert profile["deployment"]["state"] == "deployed"
    assert profile["deployment"]["observed_endpoints"] == [
        {"hostname": "www.example.invalid", "port": 443, "source": "tls_cert"}
    ]
    assert profile["observed_endpoints"] == [
        {"hostname": "www.example.invalid", "port": 443, "source": "tls_cert"}
    ]
    assert profile["public_key"] == {
        "algorithm": "RSA",
        "size_bits": 2048,
        "curve": "",
    }
    assert profile["signature"] == {
        "algorithm": "sha256WithRSAEncryption",
        "hash_algorithm": "sha256",
    }
    assert profile["x509"]["is_ca"] is False
    assert profile["x509"]["key_usage"] == ["digital_signature", "key_encipherment"]
    assert profile["x509"]["extended_key_usage"] == ["server_auth"]
    assert profile["sources"] == ["tls_cert"]


def test_merge_certificate_profiles_preserves_live_state_and_ct_seen():
    observed_at = datetime(2026, 5, 18, tzinfo=timezone.utc)
    ct_profile = build_certificate_profile(
        source="crtsh",
        raw={
            "fingerprint": "ABCD",
            "issuer_name_id": "123",
            "not_before": "2026-01-01",
            "not_after": "2026-06-01",
            "name_value": "www.example.invalid\napi.example.invalid",
        },
        observed_at=observed_at,
    )
    live_profile = build_certificate_profile(
        source="tls_cert",
        raw={
            "hostname": "www.example.invalid",
            "port": 443,
            "cert": {
                "fingerprint_sha256": "abcd",
                "not_before": "2026-01-01T00:00:00+00:00",
                "not_after": "2026-06-01T00:00:00+00:00",
                "san_dns_names": ["www.example.invalid"],
            },
        },
        observed_at=observed_at,
    )

    merged = merge_certificate_profiles(ct_profile, live_profile)

    assert merged["deployment"]["state"] == "deployed"
    assert merged["sources"] == ["crtsh", "tls_cert"]
    assert merged["ct"]["seen"] is True


def test_build_certificate_profile_rejects_unknown_source():
    with pytest.raises(ValueError, match="unsupported certificate source"):
        build_certificate_profile(source="unknown", raw={})
