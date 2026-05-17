from easm.runners.asnmap_runner import AsnmapRunner
from easm.runners.base import ApiRunner, BaseRunner
from easm.runners.certstream_runner import CertStreamRunner
from easm.runners.cloud_bucket_runner import CloudBucketRunner
from easm.runners.crtsh_runner import CrtShRunner
from easm.runners.dnstwist_runner import DnstwistRunner
from easm.runners.subfinder_runner import SubfinderRunner

__all__ = [
    "ApiRunner", "BaseRunner",
    "SubfinderRunner", "AsnmapRunner", "CertStreamRunner",
    "CrtShRunner", "DnstwistRunner", "CloudBucketRunner",
]

RUNNER_REGISTRY = {
    "subfinder": SubfinderRunner,
    "asnmap": AsnmapRunner,
    "certstream": CertStreamRunner,
    "crtsh": CrtShRunner,
    "dnstwist": DnstwistRunner,
    "cloud_enum": CloudBucketRunner,
}
