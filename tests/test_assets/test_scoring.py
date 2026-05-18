from easm.assets.scoring import score_asset_exposure


def test_critical_open_finding_makes_asset_critical():
    risk = score_asset_exposure(
        entity={
            "type": "hostname",
            "value": "app.example.invalid",
            "attributes": {},
        },
        findings=[{"severity": "critical", "status": "open"}],
    )

    assert risk["level"] == "critical"
    assert risk["score"] >= 90
    assert "critical_finding" in risk["reasons"]


def test_high_open_finding_makes_asset_high_risk():
    risk = score_asset_exposure(
        entity={
            "type": "hostname",
            "value": "app.example.invalid",
            "attributes": {},
        },
        findings=[{"severity": "high", "status": "open"}],
    )

    assert risk["level"] == "high"
    assert risk["score"] >= 70
    assert "high_finding" in risk["reasons"]


def test_closed_critical_findings_do_not_escalate_risk():
    for status in ("closed", "resolved", "suppressed"):
        risk = score_asset_exposure(
            entity={
                "type": "hostname",
                "value": "app.example.invalid",
                "attributes": {},
            },
            findings=[{"severity": "critical", "status": status}],
        )

        assert risk["level"] == "none"
        assert risk["score"] == 0
        assert "critical_finding" not in risk["reasons"]


def test_internet_exposed_service_is_medium_or_high_risk():
    risk = score_asset_exposure(
        entity={
            "type": "hostname",
            "value": "app.example.invalid",
            "attributes": {"open_ports": [443, 8443]},
        },
        findings=[],
    )

    assert risk["level"] in {"medium", "high"}
    assert "internet_exposed_service" in risk["reasons"]


def test_services_attribute_with_port_marks_asset_internet_exposed():
    risk = score_asset_exposure(
        entity={
            "type": "hostname",
            "value": "app.example.invalid",
            "attributes": {"services": [{"port": 443}]},
        },
        findings=[],
    )

    assert risk["level"] in {"medium", "high"}
    assert "internet_exposed_service" in risk["reasons"]


def test_duplicate_risk_reasons_are_deduped():
    risk = score_asset_exposure(
        entity={
            "type": "hostname",
            "value": "app.example.invalid",
            "attributes": {
                "open_ports": [443],
                "services": [{"port": 443}],
                "certificate_profile": {
                    "analysis": {
                        "risk": "high",
                        "reasons": ["rsa_key_too_small", "rsa_key_too_small"],
                    },
                },
            },
        },
        findings=[
            {"severity": "high", "status": "open"},
            {"severity": "high", "status": "open"},
        ],
    )

    assert risk["reasons"].count("high_finding") == 1
    assert risk["reasons"].count("internet_exposed_service") == 1
    assert risk["reasons"].count("certificate:rsa_key_too_small") == 1


def test_certificate_profile_analysis_escalates_asset_risk():
    risk = score_asset_exposure(
        entity={
            "type": "hostname",
            "value": "app.example.invalid",
            "attributes": {
                "certificate_profile": {
                    "analysis": {
                        "risk": "high",
                        "reasons": ["rsa_key_too_small"],
                    },
                },
            },
        },
        findings=[],
    )

    assert risk["level"] in {"high", "critical"}
    assert "certificate:rsa_key_too_small" in risk["reasons"]
