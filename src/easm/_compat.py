"""Python version compatibility shims."""

from __future__ import annotations

import uuid


def uuid7() -> uuid.UUID:
    """Return a UUID7, falling back to UUID4 on Python < 3.14."""
    _uuid7 = getattr(uuid, "uuid7", None)
    if _uuid7 is not None:
        return _uuid7()
    return uuid.uuid4()
