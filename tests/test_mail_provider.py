import pytest
from easm.mail_provider import classify_mail_provider


def test_classify_google_workspace_from_mx():
    mx_records = [{"preference": 10, "exchange": "smtp.google.com"}]
    result = classify_mail_provider(mx_records=mx_records, spf_record="")
    assert result["provider"] == "google_workspace"
    assert result["confidence"] == "high"


def test_classify_microsoft_365_from_mx():
    mx_records = [{"preference": 10, "exchange": "example-com.mail.protection.outlook.com"}]
    result = classify_mail_provider(mx_records=mx_records, spf_record="")
    assert result["provider"] == "microsoft_365"
    assert result["confidence"] == "high"


def test_classify_from_spf_include():
    mx_records = []
    spf = "v=spf1 include:_spf.google.com ~all"
    result = classify_mail_provider(mx_records=mx_records, spf_record=spf)
    assert result["provider"] == "google_workspace"
    assert result["confidence"] == "medium"


def test_classify_proofpoint_from_mx():
    mx_records = [{"preference": 10, "exchange": "mx.example.com.pphosted.com"}]
    result = classify_mail_provider(mx_records=mx_records, spf_record="")
    assert result["provider"] == "proofpoint"
    assert result["confidence"] == "high"


def test_classify_mimecast_from_mx():
    mx_records = [{"preference": 10, "exchange": "example-com.mail.mimecast.com"}]
    result = classify_mail_provider(mx_records=mx_records, spf_record="")
    assert result["provider"] == "mimecast"
    assert result["confidence"] == "high"


def test_classify_unknown_when_no_match():
    mx_records = [{"preference": 10, "exchange": "mail.unknown-corp.local"}]
    result = classify_mail_provider(mx_records=mx_records, spf_record="")
    assert result["provider"] == "unknown"
    assert result["confidence"] == "low"


def test_classify_empty_inputs():
    result = classify_mail_provider(mx_records=[], spf_record="")
    assert result["provider"] == "unknown"
    assert result["confidence"] == "low"


def test_classify_cross_validation_high_confidence():
    mx_records = [{"preference": 10, "exchange": "smtp.google.com"}]
    spf = "v=spf1 include:_spf.google.com ~all"
    result = classify_mail_provider(mx_records=mx_records, spf_record=spf)
    assert result["provider"] == "google_workspace"
    assert result["confidence"] == "high"
