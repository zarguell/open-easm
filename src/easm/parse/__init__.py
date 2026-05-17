from easm.parse.abuseipdb_parser import AbuseIpDbParser
from easm.parse.asnmap_parser import AsnmapParser
from easm.parse.breach_monitor_parser import BreachMonitorParser
from easm.parse.censys_parser import CensysParser
from easm.parse.certstream_parser import CertStreamParser
from easm.parse.cloud_bucket_parser import CloudBucketParser
from easm.parse.commoncrawl_parser import CommonCrawlParser
from easm.parse.crtsh_parser import CrtShParser
from easm.parse.dns_mail_records_parser import DnsMailRecordsParser
from easm.parse.dns_parser import DnsParser
from easm.parse.dnstwist_parser import DnstwistParser
from easm.parse.domain_extract_parser import DomainExtractParser
from easm.parse.geoip_parser import GeoIpParser
from easm.parse.github_scan_parser import GithubScanParser
from easm.parse.greynoise_parser import GreyNoiseParser
from easm.parse.paste_monitor_parser import PasteMonitorParser
from easm.parse.gist_monitor_parser import GistMonitorParser
from easm.parse.stackoverflow_monitor_parser import StackOverflowParser
from easm.parse.discord_monitor_parser import DiscordMonitorParser
from easm.parse.passive_dns_parser import PassiveDnsParser
from easm.parse.reverse_dns_parser import ReverseDnsParser
from easm.parse.reverse_whois_parser import ReverseWhoisParser
from easm.parse.nuclei_parser import NucleiParser
from easm.parse.portscan_parser import PortScanParser
from easm.parse.screenshot_parser import ScreenshotParser
from easm.parse.searchengine_parser import SearchEngineParser
from easm.parse.shodan_parser import ShodanParser
from easm.parse.subdomain_takeover_parser import SubdomainTakeoverParser
from easm.parse.subfinder_parser import SubfinderParser
from easm.parse.tls_cert_parser import TlsCertParser
from easm.parse.urlscan_parser import UrlScanParser
from easm.parse.wappalyzer_parser import WappalyzerParser

PARSER_REGISTRY = {
    "dns_mail_records": DnsMailRecordsParser,
    "subfinder": SubfinderParser,
    "asnmap": AsnmapParser,
    "certstream": CertStreamParser,
    "crtsh": CrtShParser,
    "dnstwist": DnstwistParser,
    "dns": DnsParser,
    "reverse_dns": ReverseDnsParser,
    "domain_extract": DomainExtractParser,
    "tls_cert": TlsCertParser,
    "geoip": GeoIpParser,
    "greynoise": GreyNoiseParser,
    "abuseipdb": AbuseIpDbParser,
    "urlscan": UrlScanParser,
    "cloud_enum": CloudBucketParser,
    "discord_monitor": DiscordMonitorParser,
    "gist_monitor": GistMonitorParser,
    "paste_monitor": PasteMonitorParser,
    "stackoverflow_monitor": StackOverflowParser,
    "github_scan": GithubScanParser,
    "breach_monitor": BreachMonitorParser,
    "shodan": ShodanParser,
    "censys": CensysParser,
    "reverse_whois": ReverseWhoisParser,
    "securitytrails": PassiveDnsParser,
    "takeover": SubdomainTakeoverParser,
    "commoncrawl": CommonCrawlParser,
    "searchengine": SearchEngineParser,
    "wappalyzer": WappalyzerParser,
    "screenshot": ScreenshotParser,
    "portscan": PortScanParser,
    "nuclei": NucleiParser,
}
