from easm.parse.subfinder_parser import SubfinderParser
from easm.parse.asnmap_parser import AsnmapParser
from easm.parse.certstream_parser import CertStreamParser
from easm.parse.crtsh_parser import CrtShParser
from easm.parse.dnstwist_parser import DnstwistParser

PARSER_REGISTRY = {
    "subfinder": SubfinderParser,
    "asnmap": AsnmapParser,
    "certstream": CertStreamParser,
    "crtsh": CrtShParser,
    "dnstwist": DnstwistParser,
}
