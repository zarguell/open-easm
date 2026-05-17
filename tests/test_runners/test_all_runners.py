import pytest
from easm.runners import (
    AsnmapRunner,
    BreachMonitorRunner,
    CertStreamRunner,
    CloudBucketRunner,
    CommonCrawlRunner,
    CrtShRunner,
    DnstwistRunner,
    GithubScanRunner,
    PasteMonitorRunner,
    SearchEngineRunner,
    SubfinderRunner,
    RUNNER_REGISTRY,
)


def test_runner_registry_has_all_runners():
    assert set(RUNNER_REGISTRY.keys()) == {
        "subfinder", "asnmap", "certstream", "crtsh", "dnstwist",
        "cloud_enum", "paste_monitor", "github_scan", "breach_monitor",
        "commoncrawl", "searchengine",
    }


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


def test_paste_monitor_runner_class_attributes():
    from easm.runners.paste_monitor_runner import PasteMonitorRunner

    assert PasteMonitorRunner.source_name == "paste_monitor"
    assert PasteMonitorRunner.supports_schedule is True
    assert PasteMonitorRunner.supports_manual_trigger is True
    assert PasteMonitorRunner.is_continuous is False
    assert PasteMonitorRunner.is_api_runner is True


def test_github_scan_runner_class_attributes():
    from easm.runners.github_scan_runner import GithubScanRunner

    assert GithubScanRunner.source_name == "github_scan"
    assert GithubScanRunner.supports_schedule is True
    assert GithubScanRunner.supports_manual_trigger is True
    assert GithubScanRunner.is_continuous is False
    assert GithubScanRunner.is_api_runner is True


def test_breach_monitor_runner_class_attributes():
    from easm.runners.breach_monitor_runner import BreachMonitorRunner

    assert BreachMonitorRunner.source_name == "breach_monitor"
    assert BreachMonitorRunner.supports_schedule is True
    assert BreachMonitorRunner.supports_manual_trigger is True
    assert BreachMonitorRunner.is_continuous is False
    assert BreachMonitorRunner.is_api_runner is True


def test_commoncrawl_runner_class_attributes():
    assert CommonCrawlRunner.source_name == "commoncrawl"
    assert CommonCrawlRunner.supports_schedule is True
    assert CommonCrawlRunner.supports_manual_trigger is True
    assert CommonCrawlRunner.is_continuous is False
    assert CommonCrawlRunner.is_api_runner is True


def test_searchengine_runner_class_attributes():
    assert SearchEngineRunner.source_name == "searchengine"
    assert SearchEngineRunner.supports_schedule is True
    assert SearchEngineRunner.supports_manual_trigger is True
    assert SearchEngineRunner.is_continuous is False
    assert SearchEngineRunner.is_api_runner is True
