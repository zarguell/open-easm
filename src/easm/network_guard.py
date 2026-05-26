"""Network guard — validates that hostnames resolve to public IPs before
active scanning or outbound checks.  Prevents SSRF and accidental scanning
of internal infrastructure."""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field

import dns.resolver

logger = logging.getLogger(__name__)

_DNS_TIMEOUT = 4.0


@dataclass(frozen=True)
class GuardResult:
    hostname: str
    ips: list[str]
    public_ips: list[str]
    blocked_ips: list[str]
    safe: bool
    reason: str | None = None


def _is_public_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_reserved
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
    )


def resolve_and_validate(hostname: str) -> GuardResult:
    """Resolve *hostname* and return a :class:`GuardResult`.

    ``safe`` is ``True`` only when the hostname resolves to **at least one**
    public IP and **zero** private / reserved IPs.  Mixed-resolution hostnames
    (e.g. split-horizon DNS returning both 10.x and a public address) are
    treated as unsafe to avoid leaking internal topology.
    """
    ips: list[str] = []
    error: str | None = None

    resolver = dns.resolver.Resolver()
    resolver.lifetime = _DNS_TIMEOUT
    resolver.timeout = _DNS_TIMEOUT

    for rtype in ("A", "AAAA"):
        try:
            answers = resolver.resolve(hostname, rtype)
            ips.extend(str(r).strip() for r in answers)
        except dns.resolver.NXDOMAIN:
            error = "NXDOMAIN"
            break
        except dns.resolver.NoAnswer:
            continue
        except Exception as exc:
            if not error:
                error = str(exc)

    ips = sorted(set(ips))
    public_ips = [ip for ip in ips if _is_public_ip(ip)]
    blocked_ips = [ip for ip in ips if not _is_public_ip(ip)]

    if blocked_ips:
        safe = False
        reason = (
            f"hostname resolves to non-public IP(s): "
            f"{', '.join(blocked_ips)}"
        )
    elif not public_ips:
        safe = False
        reason = error or "hostname does not resolve to any public IP"
    else:
        safe = True
        reason = None

    return GuardResult(
        hostname=hostname,
        ips=ips,
        public_ips=public_ips,
        blocked_ips=blocked_ips,
        safe=safe,
        reason=reason,
    )
