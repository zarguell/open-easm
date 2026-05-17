from easm.runners.asnmap_runner import AsnmapRunner
from easm.runners.base import ApiRunner, BaseRunner
from easm.runners.breach_monitor_runner import BreachMonitorRunner
from easm.runners.certstream_runner import CertStreamRunner
from easm.runners.cloud_bucket_runner import CloudBucketRunner
from easm.runners.commoncrawl_runner import CommonCrawlRunner
from easm.runners.crtsh_runner import CrtShRunner
from easm.runners.dnstwist_runner import DnstwistRunner
from easm.runners.discord_monitor_runner import DiscordMonitorRunner
from easm.runners.github_scan_runner import GithubScanRunner
from easm.runners.gist_monitor_runner import GistMonitorRunner
from easm.runners.paste_monitor_runner import PasteMonitorRunner
from easm.runners.stackoverflow_monitor_runner import StackOverflowMonitorRunner
from easm.runners.nuclei_runner import NucleiRunner
from easm.runners.portscan_runner import PortScanRunner
from easm.runners.screenshot_runner import ScreenshotRunner
from easm.runners.searchengine_runner import SearchEngineRunner
from easm.runners.subfinder_runner import SubfinderRunner
from easm.runners.wappalyzer_runner import WappalyzerRunner

__all__ = [
    "ApiRunner", "BaseRunner",
    "SubfinderRunner", "AsnmapRunner", "CertStreamRunner",
    "CrtShRunner", "DnstwistRunner", "CloudBucketRunner",
    "DiscordMonitorRunner", "GistMonitorRunner", "StackOverflowMonitorRunner",
    "PasteMonitorRunner", "GithubScanRunner", "BreachMonitorRunner",
    "CommonCrawlRunner", "SearchEngineRunner",
    "WappalyzerRunner", "ScreenshotRunner", "PortScanRunner", "NucleiRunner",
]

RUNNER_REGISTRY = {
    "subfinder": SubfinderRunner,
    "asnmap": AsnmapRunner,
    "certstream": CertStreamRunner,
    "crtsh": CrtShRunner,
    "dnstwist": DnstwistRunner,
    "cloud_enum": CloudBucketRunner,
    "paste_monitor": PasteMonitorRunner,
    "gist_monitor": GistMonitorRunner,
    "stackoverflow_monitor": StackOverflowMonitorRunner,
    "discord_monitor": DiscordMonitorRunner,
    "github_scan": GithubScanRunner,
    "breach_monitor": BreachMonitorRunner,
    "commoncrawl": CommonCrawlRunner,
    "searchengine": SearchEngineRunner,
    "wappalyzer": WappalyzerRunner,
    "screenshot": ScreenshotRunner,
    "portscan": PortScanRunner,
    "nuclei": NucleiRunner,
}
