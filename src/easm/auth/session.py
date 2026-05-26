from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt


def create_session_token(
    *,
    user_id: str,
    username: str,
    org_id: str,
    role: str,
    secret: str,
    max_age_seconds: int,
) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "username": username,
        "org_id": org_id,
        "role": role,
        "iss": "open-easm",
        "aud": "open-easm",
        "exp": now + timedelta(seconds=max_age_seconds),
        "iat": now,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_session_token(token: str, secret: str) -> dict:
    return jwt.decode(token, secret, algorithms=["HS256"], audience="open-easm", issuer="open-easm")
