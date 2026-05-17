from __future__ import annotations

import asyncio
from dataclasses import dataclass, field


@dataclass
class ApiRateLimiters:
    """Per-API asyncio semaphores for concurrency control."""

    crtsh: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(5))
    shodan: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(5))
    censys: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(2))
    greynoise: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(10))
    abuseipdb: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(5))
    urlscan: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(3))
    securitytrails: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(3))
    rdap: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(3))


def get_default_limiters() -> ApiRateLimiters:
    return ApiRateLimiters()
