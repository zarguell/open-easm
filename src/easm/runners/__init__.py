from easm.runners.asnmap_runner import AsnmapRunner
from easm.runners.base import ApiRunner, BaseRunner
from easm.runners.breach_monitor_runner import BreachMonitorRunner
from easm.runners.certstream_runner import CertStreamRunner
from easm.runners.cloud_bucket_runner import CloudBucketRunner
from easm.runners.commoncrawl_runner import CommonCrawlRunner
from easm.runners.crtsh_runner import CrtShRunner
from easm.runners.dnstwist_runner import DnstwistRunner
from easm.runners.github_scan_runner import GithubScanRunner
from easm.runners.paste_monitor_runner import PasteMonitorRunner
from easm.runners.searchengine_runner import SearchEngineRunner
from easm.runners.subfinder_runner import SubfinderRunner

__all__ = [
    "ApiRunner", "BaseRunner",
    "SubfinderRunner", "AsnmapRunner", "CertStreamRunner",
    "CrtShRunner", "DnstwistRunner", "CloudBucketRunner",
    "PasteMonitorRunner", "GithubScanRunner", "BreachMonitorRunner",
    "CommonCrawlRunner", "SearchEngineRunner",
]

RUNNER_REGISTRY = {
    "subfinder": SubfinderRunner,
    "asnmap": AsnmapRunner,
    "certstream": CertStreamRunner,
    "crtsh": CrtShRunner,
    "dnstwist": DnstwistRunner,
    "cloud_enum": CloudBucketRunner,
    "paste_monitor": PasteMonitorRunner,
    "github_scan": GithubScanRunner,
    "breach_monitor": BreachMonitorRunner,
    "commoncrawl": CommonCrawlRunner,
    "searchengine": SearchEngineRunner,
}
