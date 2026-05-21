"""Tests for PDF and Excel report generation."""

from __future__ import annotations

from easm.reports.pdf_report import generate_pdf_report
from easm.reports.excel_report import generate_excel_report


def _sample_data():
    return {
        "target_id": "example.com",
        "findings": [
            {
                "rule_id": "high_risk_port_exposed",
                "headline": "RDP port 3389 exposed",
                "risk": "high",
                "status": "open",
                "confidence_level": "high",
                "first_seen_at": "2026-05-20T10:00:00Z",
            },
            {
                "rule_id": "stale_certificate",
                "headline": "Expired TLS certificate",
                "risk": "medium",
                "status": "open",
                "confidence_level": "high",
                "first_seen_at": "2026-05-19T10:00:00Z",
            },
        ],
        "entities": [
            {
                "entity_value": "mail.example.com",
                "entity_type": "hostname",
                "risk_level": "high",
                "confidence_level": "high",
                "first_seen_at": "2026-05-18T10:00:00Z",
                "last_seen_at": "2026-05-21T10:00:00Z",
                "sources": ["subfinder", "certstream"],
            },
        ],
        "certificates": [
            {
                "subject_cn": "example.com",
                "issuer_organization": "Let's Encrypt",
                "risk": "medium",
                "deployment_state": "deployed",
                "not_after": "2026-06-01",
                "san_dns_names": ["example.com", "www.example.com"],
            },
        ],
        "runs": [],
        "change_events": [],
        "executive_risk": {
            "overall_score": 72,
            "technical_score": 720,
            "posture": "Adequate",
            "risk_level": "Moderate",
            "profile": "web_and_mail",
            "board_summary": "Overall posture adequate with moderate risk.",
            "by_severity": {"high": 1, "medium": 1},
            "pillars": [
                {"id": "dns", "label": "DNS", "weight": 10, "score": 90,
                 "level": "Controlled", "risk": "Low", "findings_count": 0,
                 "recommendation": "Correct weak DNS records."},
            ],
        },
        "sla_summary": {"overdue_count": 0, "total": 2},
        "ip_count": 5,
        "hostname_count": 12,
        "domain_count": 3,
    }


class TestPdfReport:
    def test_generates_non_empty_bytes(self):
        pdf = generate_pdf_report(_sample_data())
        assert isinstance(pdf, bytes)
        assert len(pdf) > 1000

    def test_starts_with_pdf_magic(self):
        pdf = generate_pdf_report(_sample_data())
        assert pdf[:5] == b"%PDF-"

    def test_handles_empty_data(self):
        data = {
            "target_id": "empty.com",
            "findings": [],
            "entities": [],
            "certificates": [],
            "runs": [],
            "change_events": [],
            "executive_risk": {
                "overall_score": 100, "technical_score": 1000,
                "posture": "Controlled", "risk_level": "Low",
                "profile": "undetermined", "board_summary": "No findings.",
                "by_severity": {}, "pillars": [],
            },
            "sla_summary": {"overdue_count": 0, "total": 0},
            "ip_count": 0, "hostname_count": 0, "domain_count": 0,
        }
        pdf = generate_pdf_report(data)
        assert len(pdf) > 500


class TestExcelReport:
    def test_generates_non_empty_bytes(self):
        xlsx = generate_excel_report(_sample_data())
        assert isinstance(xlsx, bytes)
        assert len(xlsx) > 1000

    def test_is_valid_zip(self):
        import zipfile
        from io import BytesIO
        xlsx = generate_excel_report(_sample_data())
        buf = BytesIO(xlsx)
        assert zipfile.is_zipfile(buf)

    def test_handles_empty_data(self):
        data = {
            "target_id": "empty.com",
            "findings": [],
            "entities": [],
            "certificates": [],
            "runs": [],
            "change_events": [],
            "executive_risk": {
                "overall_score": 100, "technical_score": 1000,
                "posture": "Controlled", "risk_level": "Low",
                "profile": "undetermined", "board_summary": "No findings.",
                "by_severity": {}, "pillars": [],
            },
            "sla_summary": {"overdue_count": 0, "total": 0},
            "ip_count": 0, "hostname_count": 0, "domain_count": 0,
        }
        xlsx = generate_excel_report(data)
        assert len(xlsx) > 500
