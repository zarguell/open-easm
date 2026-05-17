import pytest
from easm.runners import (
    AsnmapRunner,
    CertStreamRunner,
    CrtShRunner,
    DnstwistRunner,
    SubfinderRunner,
    CloudBucketRunner,
    RUNNER_REGISTRY,
)


def test_runner_registry_has_all_runners():
    assert set(RUNNER_REGISTRY.keys()) == {"subfinder", "asnmap", "certstream", "crtsh", "dnstwist", "cloud_enum"}


def test_subfinder_runner_class_attributes():
    assert SubfinderRunner.source_name == "subfinder"
    assert SubfinderRunner.supports_schedule is True
    assert SubfinderRunner.supports_manual_trigger is True
    assert SubfinderRunner.is_continuous is False


def test_asnmap_runner_class_attributes():
    assert AsnmapRunner.source_name == "asnmap"
    assert AsnmapRunner.supports_schedule is True
    assert AsnmapRunner.supports_manual_trigger is True
    assert AsnmapRunner.is_continuous is False


def test_certstream_runner_class_attributes():
    assert CertStreamRunner.source_name == "certstream"
    assert CertStreamRunner.supports_schedule is False
    assert CertStreamRunner.supports_manual_trigger is False
    assert CertStreamRunner.is_continuous is True


def test_crtsh_runner_class_attributes():
    assert CrtShRunner.source_name == "crtsh"
    assert CrtShRunner.supports_schedule is True
    assert CrtShRunner.supports_manual_trigger is True
    assert CrtShRunner.is_continuous is False
    assert CrtShRunner.is_api_runner is True


def test_dnstwist_runner_class_attributes():
    assert DnstwistRunner.source_name == "dnstwist"
    assert DnstwistRunner.supports_schedule is True
    assert DnstwistRunner.supports_manual_trigger is True
    assert DnstwistRunner.is_continuous is False


def test_cloud_bucket_runner_attributes():
    assert CloudBucketRunner.source_name == "cloud_enum"
    assert CloudBucketRunner.supports_schedule is True
    assert CloudBucketRunner.supports_manual_trigger is True
    assert CloudBucketRunner.is_continuous is False
    assert CloudBucketRunner.is_api_runner is True
