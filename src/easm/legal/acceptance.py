"""Legal acceptance creation and validation."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

import asyncpg

from easm.legal.terms import TERMS_VERSION, terms_hash

logger = logging.getLogger(__name__)


async def create_acceptance(
    pool: asyncpg.Pool,
    *,
    client_ip: str,
    user_agent: str,
    accepted: bool,
    supplied_hash: str | None,
) -> dict:
    if not accepted:
        raise ValueError("Terms must be accepted to use OpenEASM.")

    current_hash = terms_hash()
    if supplied_hash and supplied_hash != current_hash:
        raise ValueError(
            "The displayed terms are outdated. Please reload the page."
        )

    token = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO legal_acceptances (token, terms_version, terms_hash, "
            "accepted_at, client_ip, user_agent) VALUES ($1, $2, $3, $4, $5, $6)",
            token,
            TERMS_VERSION,
            current_hash,
            now,
            client_ip,
            user_agent[:1000],
        )

    return {
        "accepted": True,
        "token": token,
        "version": TERMS_VERSION,
        "hash": current_hash,
        "accepted_at": now.isoformat(),
    }


async def validate_acceptance(pool: asyncpg.Pool, token: str | None) -> dict:
    current_hash = terms_hash()

    if not token:
        return {
            "accepted": False,
            "reason": "missing_token",
            "version": TERMS_VERSION,
            "hash": current_hash,
        }

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT terms_version, terms_hash, accepted_at "
            "FROM legal_acceptances WHERE token = $1",
            token,
        )

    if not row:
        return {
            "accepted": False,
            "reason": "unknown_token",
            "version": TERMS_VERSION,
            "hash": current_hash,
        }

    if row["terms_version"] != TERMS_VERSION or row["terms_hash"] != current_hash:
        return {
            "accepted": False,
            "reason": "terms_changed",
            "version": TERMS_VERSION,
            "hash": current_hash,
        }

    return {
        "accepted": True,
        "version": row["terms_version"],
        "hash": row["terms_hash"],
        "accepted_at": row["accepted_at"].isoformat() if row["accepted_at"] else None,
    }
