"""DNS TXT record-based domain ownership verification."""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone

import asyncpg
import dns.resolver

logger = logging.getLogger(__name__)

_DNS_TIMEOUT = 4.0


def _generate_token() -> str:
    return secrets.token_hex(16)


def _verification_name(domain: str) -> str:
    return f"_easm-verification.{domain}"


def _expected_value(token: str) -> str:
    return f"open-easm-verification={token}"


def _clean_txt(value: str) -> str:
    return value.replace('" "', "").replace('"', "").strip()


def _now():
    return datetime.now(timezone.utc)


async def start_verification(pool: asyncpg.Pool, domain: str) -> dict:
    """Start domain verification. Returns verification instructions."""
    async with pool.acquire() as conn:
        existing = await conn.fetchrow(
            "SELECT domain, status FROM verified_domains WHERE domain = $1",
            domain,
        )

        if existing and existing["status"] == "verified":
            row = await conn.fetchrow(
                "SELECT * FROM verified_domains WHERE domain = $1", domain
            )
            return _serialize(row)

        token = _generate_token()
        now = _now()

        if existing:
            await conn.execute(
                "UPDATE verified_domains SET token = $1, status = 'pending', "
                "verification_name = $2, expected_value = $3, created_at = $4, "
                "verified_at = NULL, last_checked_at = NULL, last_error = NULL "
                "WHERE domain = $5",
                token, _verification_name(domain), _expected_value(token),
                now, domain,
            )
        else:
            await conn.execute(
                "INSERT INTO verified_domains "
                "(domain, token, status, method, verification_name, expected_value, created_at) "
                "VALUES ($1, $2, 'pending', 'dns_txt', $3, $4, $5)",
                domain, token, _verification_name(domain), _expected_value(token), now,
            )

        row = await conn.fetchrow(
            "SELECT * FROM verified_domains WHERE domain = $1", domain
        )
        return _serialize(row)


async def check_verification(pool: asyncpg.Pool, domain: str) -> dict | None:
    """Check DNS TXT record and update verification status."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM verified_domains WHERE domain = $1", domain
        )
        if not row:
            return None

        now = _now()
        await conn.execute(
            "UPDATE verified_domains SET last_checked_at = $1, last_error = NULL "
            "WHERE domain = $2",
            now, domain,
        )

        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = _DNS_TIMEOUT
            resolver.timeout = _DNS_TIMEOUT
            answers = resolver.resolve(row["verification_name"], "TXT")
            values = [_clean_txt(str(a)) for a in answers]

            if row["expected_value"] in values:
                await conn.execute(
                    "UPDATE verified_domains SET status = 'verified', "
                    "verified_at = $1 WHERE domain = $2",
                    now, domain,
                )
            else:
                await conn.execute(
                    "UPDATE verified_domains SET status = 'pending', "
                    "last_error = $1 WHERE domain = $2",
                    "TXT found but expected value absent. "
                    f"Values seen: {' | '.join(values)}",
                    domain,
                )
        except Exception as exc:
            await conn.execute(
                "UPDATE verified_domains SET last_error = $1 WHERE domain = $2 "
                "AND status != 'verified'",
                str(exc), domain,
            )

        row = await conn.fetchrow(
            "SELECT * FROM verified_domains WHERE domain = $1", domain
        )
        return _serialize(row)


async def get_domain_status(pool: asyncpg.Pool, domain: str) -> dict:
    """Get current verification status for a domain."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM verified_domains WHERE domain = $1", domain
        )
        if not row:
            return {"domain": domain, "status": "not_started", "verified": False}
        return _serialize(row)


async def list_verified_domains(pool: asyncpg.Pool) -> list[dict]:
    """List all verification records."""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM verified_domains ORDER BY created_at DESC"
        )
        return [_serialize(r) for r in rows]


async def delete_verification(pool: asyncpg.Pool, domain: str) -> bool:
    """Remove a domain verification record."""
    async with pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM verified_domains WHERE domain = $1", domain
        )
        return result == "DELETE 1"


def _serialize(row) -> dict:
    return {
        "domain": row["domain"],
        "status": row["status"],
        "verified": row["status"] == "verified",
        "method": row["method"],
        "verification_name": row["verification_name"],
        "expected_value": row["expected_value"],
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        "verified_at": row["verified_at"].isoformat() if row["verified_at"] else None,
        "last_checked_at": (
            row["last_checked_at"].isoformat() if row["last_checked_at"] else None
        ),
        "last_error": row["last_error"],
    }
