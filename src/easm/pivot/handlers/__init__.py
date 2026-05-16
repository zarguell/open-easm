from easm.pivot.handlers.dns_resolve import DnsResolveHandler
from easm.pivot.handlers.crtsh_search import CrtShSearchHandler
from easm.pivot.handlers.rdap_lookup import RdapLookupHandler
from easm.pivot.handlers.shodan_enrich import ShodanEnrichHandler
from easm.pivot.handlers.reverse_dns import ReverseDnsHandler
from easm.pivot.handlers.domain_rdap import DomainRdapHandler
from easm.pivot.handlers.subdomain_enum import SubdomainEnumHandler
from easm.pivot.handlers.domain_extract import DomainExtractHandler

PIVOT_HANDLER_REGISTRY: dict = {
    "dns_resolve": DnsResolveHandler,
    "crtsh_search": CrtShSearchHandler,
    "rdap_lookup": RdapLookupHandler,
    "shodan_enrich": ShodanEnrichHandler,
    "reverse_dns": ReverseDnsHandler,
    "domain_rdap": DomainRdapHandler,
    "subdomain_enum": SubdomainEnumHandler,
    "domain_extract": DomainExtractHandler,
}
