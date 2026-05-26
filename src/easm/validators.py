"""Input validation helpers."""

from __future__ import annotations

import re

_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE
)


def normalize_domain(domain: str) -> str:
    """Lowercase, strip whitespace, and validate a domain name."""
    d = domain.strip().lower().rstrip(".")
    if not _DOMAIN_RE.match(d):
        raise ValueError(f"Invalid domain: {domain!r}")
    return d
