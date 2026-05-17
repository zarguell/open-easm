from easm.parse.abuseipdb_parser import AbuseIpDbParser
from easm.parse.asnmap_parser import AsnmapParser
from easm.parse.breach_monitor_parser import BreachMonitorParser
from easm.parse.certstream_parser import CertStreamParser
from easm.parse.cloud_bucket_parser import CloudBucketParser
from easm.parse.crtsh_parser import CrtShParser
from easm.parse.dns_mail_records_parser import DnsMailRecordsParser
from easm.parse.dns_parser import DnsParser
from easm.parse.dnstwist_parser import DnstwistParser
from easm.parse.domain_extract_parser import DomainExtractParser
from easm.parse.geoip_parser import GeoIpParser
from easm.parse.github_scan_parser import GithubScanParser
from easm.parse.greynoise_parser import GreyNoiseParser
from easm.parse.paste_monitor_parser import PasteMonitorParser
from easm.parse.reverse_dns_parser import ReverseDnsParser
from easm.parse.subfinder_parser import SubfinderParser
from easm.parse.tls_cert_parser import TlsCertParser
from easm.parse.urlscan_parser import UrlScanParser

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
    "paste_monitor": PasteMonitorParser,
    "github_scan": GithubScanParser,
    "breach_monitor": BreachMonitorParser,
}
