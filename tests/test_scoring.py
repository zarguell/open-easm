"""Tests for executive pillar scoring."""

from __future__ import annotations

from easm.scoring.pillars import PILLARS, PROFILE_WEIGHTS, classify_domain
from easm.scoring.executive import build_executive_risk, SEVERITY_PENALTY


class TestClassifyDomain:
    def test_web_and_mail(self):
        assert classify_domain(has_web=True, has_mail=True) == "web_and_mail"

    def test_web_only(self):
        assert classify_domain(has_web=True, has_mail=False) == "web"

    def test_mail_only(self):
        assert classify_domain(has_web=False, has_mail=True) == "mail"

    def test_undetermined(self):
        assert classify_domain(has_web=False, has_mail=False) == "undetermined"


class TestPillarDefinitions:
    def test_seven_pillars(self):
        assert len(PILLARS) == 7
        ids = [p["id"] for p in PILLARS]
        assert "dns" in ids
        assert "mail" in ids
        assert "web" in ids
        assert "tls" in ids
        assert "surface" in ids
        assert "cti" in ids
        assert "cve" in ids

    def test_each_pillar_has_required_fields(self):
        for p in PILLARS:
            assert "id" in p
            assert "label" in p
            assert "patterns" in p
            assert "description" in p
            assert "recommendation" in p
            assert len(p["patterns"]) > 0

    def test_all_profiles_weight_sum_to_100(self):
        for profile_name, weights in PROFILE_WEIGHTS.items():
            total = sum(weights.values())
            assert total == 100, f"Profile {profile_name} weights sum to {total}, expected 100"

    def test_all_profiles_have_seven_pillars(self):
        pillar_ids = {p["id"] for p in PILLARS}
        for profile_name, weights in PROFILE_WEIGHTS.items():
            assert set(weights.keys()) == pillar_ids, f"Profile {profile_name} missing pillars"


class TestBuildExecutiveRisk:
    def _sample_findings(self):
        return [
            {"rule_id": "high_risk_port_exposed", "headline": "RDP port 3389 open on host.example.com", "risk": "high", "status": "open"},
            {"rule_id": "stale_certificate", "headline": "Expired certificate on web.example.com", "risk": "medium", "status": "open"},
            {"rule_id": "known_exploited_vulnerability", "headline": "CVE-2021-41773 on Apache", "risk": "critical", "status": "open"},
        ]

    def test_basic_output_structure(self):
        result = build_executive_risk(self._sample_findings(), has_web=True, has_mail=True)
        assert "overall_score" in result
        assert "technical_score" in result
        assert "posture" in result
        assert "risk_level" in result
        assert "pillars" in result
        assert "top_risks" in result
        assert "quick_wins" in result
        assert "board_summary" in result
        assert "weakest_pillars" in result
        assert "by_severity" in result

    def test_score_ranges(self):
        result = build_executive_risk(self._sample_findings(), has_web=True, has_mail=True)
        assert 0 <= result["overall_score"] <= 100
        assert 0 <= result["technical_score"] <= 1000

    def test_technical_score_equals_overall_times_10(self):
        result = build_executive_risk(self._sample_findings(), has_web=True, has_mail=True)
        assert result["technical_score"] == result["overall_score"] * 10

    def test_no_findings_gives_perfect_score(self):
        result = build_executive_risk([], has_web=True, has_mail=True)
        assert result["overall_score"] == 100
        assert result["posture"] == "Controlled"

    def test_critical_finding_lowers_score(self):
        result = build_executive_risk(
            [{"rule_id": "known_exploited_vulnerability", "headline": "Critical CVE", "risk": "critical", "status": "open"}],
            has_web=True,
        )
        assert result["overall_score"] < 100

    def test_profile_web(self):
        result = build_executive_risk([], has_web=True, has_mail=False)
        assert result["profile"] == "web"

    def test_profile_web_and_mail(self):
        result = build_executive_risk([], has_web=True, has_mail=True)
        assert result["profile"] == "web_and_mail"

    def test_top_risks_limited_to_five(self):
        many_findings = [
            {"rule_id": f"rule_{i}", "headline": f"Finding {i}", "risk": "high", "status": "open"}
            for i in range(10)
        ]
        result = build_executive_risk(many_findings, has_web=True)
        assert len(result["top_risks"]) <= 5

    def test_quick_wins_limited_to_five(self):
        findings = [
            {"rule_id": f"rule_{i}", "headline": f"Missing header X-Frame-Options {i}", "risk": "medium", "status": "open"}
            for i in range(10)
        ]
        result = build_executive_risk(findings, has_web=True)
        assert len(result["quick_wins"]) <= 5

    def test_mail_pillar_not_applicable_for_web_only(self):
        result = build_executive_risk([], has_web=True, has_mail=False)
        mail_pillar = next(p for p in result["pillars"] if p["id"] == "mail")
        assert mail_pillar["applicability"] == "not_applicable"
        assert mail_pillar["weight"] == 0

    def test_severity_penalties_are_positive(self):
        for sev, penalty in SEVERITY_PENALTY.items():
            if sev != "info":
                assert penalty > 0, f"Penalty for {sev} should be positive"
            else:
                assert penalty == 0

    def test_critical_penalty_larger_than_high(self):
        assert SEVERITY_PENALTY["critical"] > SEVERITY_PENALTY["high"]
        assert SEVERITY_PENALTY["high"] > SEVERITY_PENALTY["medium"]
        assert SEVERITY_PENALTY["medium"] > SEVERITY_PENALTY["low"]

    def test_contextual_surface_penalty(self):
        result_base = build_executive_risk([], has_web=True, ip_count=2)
        result_many = build_executive_risk([], has_web=True, ip_count=20)
        # More IPs should penalize surface pillar more
        surface_base = next(p for p in result_base["pillars"] if p["id"] == "surface")
        surface_many = next(p for p in result_many["pillars"] if p["id"] == "surface")
        assert surface_many["score"] <= surface_base["score"]

    def test_board_summary_non_empty(self):
        result = build_executive_risk(self._sample_findings(), has_web=True)
        assert len(result["board_summary"]) > 20
