from easm.parse.subfinder_parser import SubfinderParser
from easm.parse.asnmap_parser import AsnmapParser
from easm.parse.certstream_parser import CertStreamParser
from easm.parse.crtsh_parser import CrtShParser
from easm.parse.dnstwist_parser import DnstwistParser
from easm.parse.dns_parser import DnsParser
from easm.parse.reverse_dns_parser import ReverseDnsParser
from easm.parse.domain_extract_parser import DomainExtractParser
from easm.parse.dns_mail_records_parser import DnsMailRecordsParser
from easm.parse.tls_cert_parser import TlsCertParser
from easm.parse.geoip_parser import GeoIpParser

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
}
