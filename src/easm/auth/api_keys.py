from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets

logger = logging.getLogger(__name__)

# Server-side pepper loaded from environment. If not set, a random pepper
# is generated per process — keys hashed in one process won't validate in
# another. Set EASM_API_KEY_PEPPER in production for stable hashing.
_pepper: bytes | None = None


def _get_pepper() -> bytes:
    global _pepper
    if _pepper is None:
        env = os.environ.get("EASM_API_KEY_PEPPER")
        if env:
            _pepper = env.encode()
        else:
            _pepper = secrets.token_bytes(32)
            logger.warning(
                "EASM_API_KEY_PEPPER not set — using ephemeral pepper. "
                "All API keys will be invalidated on restart. "
                "Set EASM_API_KEY_PEPPER in production."
            )
    return _pepper


def generate_api_key() -> tuple[str, str, str]:
    """Generate a new API key. Returns (raw_key, prefix, key_hash)."""
    raw = f"easm_{secrets.token_urlsafe(32)}"
    prefix = raw[:12]
    key_hash = hash_api_key(raw)
    return raw, prefix, key_hash


def hash_api_key(raw_key: str) -> str:
    return hmac.new(_get_pepper(), raw_key.encode(), hashlib.sha256).hexdigest()


def verify_api_key(raw_key: str, key_hash: str) -> bool:
    expected = hash_api_key(raw_key)
    return hmac.compare_digest(expected, key_hash)
