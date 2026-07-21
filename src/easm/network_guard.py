"""Network guard — validates that hostnames resolve to public IPs before
active scanning or outbound checks, and rejects private-IP connections at
the HTTP transport layer.  Prevents SSRF and accidental scanning of internal
infrastructure."""

from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass

import dns.resolver
import httpx

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


# ---------------------------------------------------------------------------
# httpx transport that rejects connections to private/internal IP ranges.
# Provides defense-in-depth against SSRF at the HTTP-client layer, complementing
# the pre-flight ``resolve_and_validate`` check above.
# ---------------------------------------------------------------------------

_PRIVATE_CIDRS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private_ip(host: str) -> bool:
    if not host:
        return False
    try:
        ip_str = socket.gethostbyname(host)
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_CIDRS)
    except (socket.gaierror, ValueError):
        return False


class PrivateIPRejectTransport(httpx.BaseTransport):
    def __init__(self, wrapped: httpx.BaseTransport | None = None):
        self._wrapped = wrapped or httpx.HTTPTransport()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if _is_private_ip(host):
            raise httpx.ConnectError(
                f"Connection to private IP blocked by network guard: {host}"
            )
        return self._wrapped.handle_request(request)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if _is_private_ip(host):
            raise httpx.ConnectError(
                f"Connection to private IP blocked by network guard: {host}"
            )
        return await self._wrapped.handle_async_request(request)


def create_guard_client(**kwargs) -> httpx.AsyncClient:
    transport = kwargs.pop("transport", None)
    kwargs["transport"] = PrivateIPRejectTransport(transport)
    return httpx.AsyncClient(**kwargs)
