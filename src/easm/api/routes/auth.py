from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, Field

from easm.auth.password import hash_password, verify_password
from easm.auth.session import create_session_token

logger = logging.getLogger(__name__)
router = APIRouter(tags=["auth"])


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)
    email: str | None = None
    display_name: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class CreateApiKeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)


def _set_session_cookie(
    response: Response,
    token: str,
    max_age: int,
    cookie_name: str,
    secure: bool = True,
) -> None:
    response.set_cookie(
        key=cookie_name,
        value=token,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/",
    )


def _clear_session_cookie(response: Response, cookie_name: str) -> None:
    response.delete_cookie(key=cookie_name, path="/")


def _user_response(user: dict) -> dict:
    return {
        "id": str(user["id"]),
        "username": user["username"],
        "display_name": user.get("display_name"),
        "email": user.get("email"),
        "role": user["role"],
        "org_id": user["org_id"],
    }


@router.post("/auth/register", status_code=201)
async def register(req: RegisterRequest, request: Request) -> Any:
    from easm.api.deps import get_store

    store = get_store()

    # After bootstrap, require authenticated admin
    if not await store.is_first_user():
        user = getattr(request.state, "user", None)
        if user is None or user.get("role") != "admin":
            return Response(status_code=403, content='{"error": "registration_requires_admin"}')

    existing = await store.get_user_by_username("default", req.username)
    if existing is not None:
        return Response(status_code=409, content='{"error": "username_taken"}')

    hashed = hash_password(req.password)
    try:
        async with store.pool.acquire() as conn:
            async with conn.transaction(isolation="serializable"):
                count = await conn.fetchval("SELECT COUNT(*) FROM users")
                if count > 0:
                    user = getattr(request.state, "user", None)
                    if user is None or user.get("role") != "admin":
                        return Response(
                            status_code=403,
                            content='{"error": "registration_requires_admin"}',
                        )
                row = await conn.fetchrow(
                    """
                    INSERT INTO users (org_id, username, email, display_name, password_hash, role)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    ON CONFLICT (org_id, username) DO NOTHING
                    RETURNING *
                    """,
                    "default",
                    req.username,
                    req.email,
                    req.display_name,
                    hashed,
                    "admin",
                )
                if row is None:
                    return Response(status_code=409, content='{"error": "username_taken"}')
                user = dict(row)
    except Exception:
        return Response(status_code=409, content='{"error": "username_taken"}')
    return _user_response(user)


@router.post("/auth/login")
async def login(req: LoginRequest, request: Request) -> Any:
    from easm.api.deps import get_auth_config, get_store

    store = get_store()
    auth_config = get_auth_config()

    if auth_config.local is None:
        return Response(status_code=400, content='{"error": "local_auth_not_configured"}')

    user = await store.get_user_by_username("default", req.username)
    if user is None or user.get("password_hash") is None:
        return Response(status_code=401, content='{"error": "invalid_credentials"}')

    if not verify_password(req.password, user["password_hash"]):
        return Response(status_code=401, content='{"error": "invalid_credentials"}')

    token = create_session_token(
        user_id=str(user["id"]),
        username=user["username"],
        org_id=user["org_id"],
        role=user["role"],
        secret=auth_config.local.session_secret,
        max_age_seconds=auth_config.local.session_max_age_seconds,
    )

    body = _user_response(user)
    response = Response(
        status_code=200,
        content=json.dumps(body).encode(),
        media_type="application/json",
    )
    _set_session_cookie(
        response,
        token,
        auth_config.local.session_max_age_seconds,
        auth_config.local.cookie_name,
        secure=auth_config.local.cookie_secure,
    )
    return response


@router.post("/auth/logout")
async def logout(request: Request) -> Any:
    from easm.api.deps import get_auth_config

    auth_config = get_auth_config()
    cookie_name = auth_config.local.cookie_name if auth_config.local else "easm_session"

    response = Response(
        status_code=200,
        content='{"message":"logged_out"}',
        media_type="application/json",
    )
    _clear_session_cookie(response, cookie_name)
    return response


@router.get("/auth/me")
async def me(request: Request) -> Any:
    user = getattr(request.state, "user", None)
    if user is None:
        return Response(status_code=401, content='{"error": "not_authenticated"}')
    return user


@router.post("/auth/api-keys", status_code=201)
async def create_api_key(req: CreateApiKeyRequest, request: Request) -> Any:
    from easm.api.deps import get_store
    from easm.auth.api_keys import generate_api_key

    user = getattr(request.state, "user", None)
    if user is None:
        return Response(status_code=401, content='{"error": "not_authenticated"}')

    store = get_store()
    raw, prefix, key_hash = generate_api_key()

    expires_at = None
    if req.expires_in_days is not None:
        from datetime import UTC, datetime, timedelta

        expires_at = datetime.now(UTC) + timedelta(days=req.expires_in_days)

    api_key = await store.create_api_key(
        user_id=user["user_id"],
        org_id=user["org_id"],
        name=req.name,
        key_prefix=prefix,
        key_hash=key_hash,
        expires_at=expires_at,
    )
    return {
        "id": str(api_key["id"]),
        "name": api_key["name"],
        "key_prefix": api_key["key_prefix"],
        "expires_at": api_key["expires_at"].isoformat() if api_key.get("expires_at") else None,
        "created_at": api_key["created_at"].isoformat() if api_key.get("created_at") else None,
        "key": raw,
    }


@router.get("/auth/api-keys")
async def list_api_keys(request: Request) -> Any:
    from easm.api.deps import get_store

    user = getattr(request.state, "user", None)
    if user is None:
        return Response(status_code=401, content='{"error": "not_authenticated"}')

    store = get_store()
    keys = await store.list_api_keys(user["user_id"])
    return [
        {
            "id": str(k["id"]),
            "name": k["name"],
            "key_prefix": k["key_prefix"],
            "expires_at": k["expires_at"].isoformat() if k.get("expires_at") else None,
            "last_used_at": k["last_used_at"].isoformat() if k.get("last_used_at") else None,
            "created_at": k["created_at"].isoformat() if k.get("created_at") else None,
        }
        for k in keys
    ]


@router.delete("/auth/api-keys/{api_key_id}")
async def delete_api_key(api_key_id: str, request: Request) -> Response:
    from easm.api.deps import get_store

    user = getattr(request.state, "user", None)
    if user is None:
        return Response(status_code=401, content='{"error": "not_authenticated"}')

    store = get_store()
    deleted = await store.delete_api_key(api_key_id, user["user_id"])
    if not deleted:
        return Response(status_code=404, content='{"error": "not_found"}')
    return Response(status_code=204)


@router.get("/auth/sso/{provider}")
async def sso_login(provider: str, request: Request) -> Any:
    from easm.api.deps import get_auth_config
    from easm.auth.sso import get_sso_provider

    auth_config = get_auth_config()
    if auth_config.sso is None or auth_config.sso.provider != provider:
        return Response(status_code=404, content='{"error": "sso_not_configured"}')

    sso = get_sso_provider(auth_config.sso)
    async with sso:
        return await sso.get_login_redirect()


@router.get("/auth/sso/{provider}/callback")
async def sso_callback(provider: str, request: Request) -> Any:
    from easm.api.deps import get_auth_config, get_store
    from easm.auth.config import LocalAuthConfig
    from easm.auth.sso import get_sso_provider

    auth_config = get_auth_config()
    if auth_config.sso is None or auth_config.sso.provider != provider:
        return Response(status_code=404, content='{"error": "sso_not_configured"}')

    sso = get_sso_provider(auth_config.sso)
    async with sso:
        sso_user = await sso.verify_and_process(request)

    if sso_user is None:
        return Response(status_code=401, content='{"error": "sso_verification_failed"}')

    store = get_store()
    provider_id = str(sso_user.id) if sso_user.id else ""

    # Find or create user
    user = await store.get_user_by_sso(provider, provider_id)
    if user is None:
        import re

        raw_name = sso_user.display_name or sso_user.email or f"{provider}_user"
        username = re.sub(r"[^a-zA-Z0-9_-]", "_", raw_name)[:64]
        existing = await store.get_user_by_username("default", username)
        if existing is not None:
            username = f"{username}_{provider_id[:8]}"
        user = await store.create_user(
            org_id="default",
            username=username,
            email=sso_user.email,
            display_name=sso_user.display_name,
            role="admin",
            sso_provider=provider,
            sso_provider_id=provider_id,
        )

    # Resolve session config: prefer auth.local, fall back to sso.session_secret
    local_cfg = auth_config.local
    if local_cfg is None:
        local_cfg = LocalAuthConfig(
            session_secret=auth_config.sso.session_secret,  # type: ignore[arg-type]
            session_max_age_seconds=86400,
        )

    token = create_session_token(
        user_id=str(user["id"]),
        username=user["username"],
        org_id=user["org_id"],
        role=user["role"],
        secret=local_cfg.session_secret,
        max_age_seconds=local_cfg.session_max_age_seconds,
    )

    response = Response(
        status_code=200,
        content=json.dumps(_user_response(user)).encode(),
        media_type="application/json",
    )
    _set_session_cookie(
        response, token, local_cfg.session_max_age_seconds, local_cfg.cookie_name,
        secure=local_cfg.cookie_secure,
    )
    return response
