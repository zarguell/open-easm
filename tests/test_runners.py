import pytest
from easm.runners import SubfinderRunner, AsnmapRunner, CertStreamRunner, RUNNER_REGISTRY


def test_runner_registry_has_all_runners():
    assert set(RUNNER_REGISTRY.keys()) == {"subfinder", "asnmap", "certstream"}


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
