from datetime import datetime, timezone

from easm.certificates.analysis import analyze_certificate_profile


NOW = datetime(2026, 5, 18, tzinfo=timezone.utc)


def test_expired_deployed_certificate_is_critical():
    analysis = analyze_certificate_profile(
        {
            "not_after": "2026-05-01T00:00:00+00:00",
            "deployment": {
                "state": "deployed",
                "observed_endpoints": [
                    {"hostname": "app.example.invalid", "port": 443},
                ],
            },
            "public_key": {"algorithm": "RSA", "size_bits": 2048},
            "signature": {"hash_algorithm": "sha256"},
        },
        now=NOW,
    )

    assert analysis["validity_state"] == "expired"
    assert analysis["risk"] == "critical"
    assert "expired_deployed" in analysis["reasons"]


def test_expired_ct_only_certificate_is_lower_than_deployed():
    analysis = analyze_certificate_profile(
        {
            "not_after": "2026-05-01T00:00:00+00:00",
            "deployment": {"state": "ct_only", "observed_endpoints": []},
            "observed_endpoints": [],
            "public_key": {"algorithm": "RSA", "size_bits": 2048},
            "signature": {"hash_algorithm": "sha256"},
        },
        now=NOW,
    )

    assert analysis["validity_state"] == "expired"
    assert analysis["risk"] == "medium"
    assert "expired_ct_only" in analysis["reasons"]


def test_unobserved_valid_ct_certificate_is_candidate():
    analysis = analyze_certificate_profile(
        {
            "not_after": "2026-06-15T00:00:00+00:00",
            "deployment": {"state": "ct_only", "observed_endpoints": []},
            "ct": {"seen": True},
        },
        now=NOW,
    )

    assert analysis["deployment_state"] == "unobserved_candidate"
    assert analysis["risk"] == "info"
    assert "valid_ct_only_not_observed" in analysis["reasons"]


def test_weak_crypto_is_high_risk_when_deployed():
    analysis = analyze_certificate_profile(
        {
            "not_after": "2026-08-01T00:00:00+00:00",
            "deployment": {
                "observed_endpoints": [
                    {"hostname": "app.example.invalid", "port": 443},
                ],
            },
            "public_key": {"algorithm": "RSA", "size_bits": 1024},
            "signature": {"hash_algorithm": "sha1"},
        },
        now=NOW,
    )

    assert analysis["strength"] == "weak"
    assert analysis["risk"] == "high"
    assert "rsa_key_too_small" in analysis["reasons"]
    assert "weak_signature_hash" in analysis["reasons"]
