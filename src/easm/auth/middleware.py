from __future__ import annotations

import ipaddress
import logging

import asyncpg
import jwt
from fastapi import Request, Response
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

# Paths exempt from authentication
EXEMPT_PATHS = {"/api/healthz", "/api/auth/login", "/api/auth/register", "/api/auth/logout"}
EXEMPT_PREFIXES = ("/ui",)


def _is_exempt(path: str) -> bool:
    if path in EXEMPT_PATHS:
        return True
    # SSO login redirect + callback are exempt
    if path.startswith("/api/auth/sso"):
        return True
    return any(path.startswith(p) for p in EXEMPT_PREFIXES)


def _is_trusted_proxy(client_ip: str, trusted_proxies: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    return any(
        addr in ipaddress.ip_network(cidr, strict=False)
        for cidr in trusted_proxies
    )


async def auth_middleware(request: Request, call_next) -> Response:
    if _is_exempt(request.url.path):
        # Still try session auth for exempt paths (e.g. admin registering users)
        await _try_session_auth(request)
        return await call_next(request)

    from easm.api.deps import get_auth_config, get_store

    auth_config = get_auth_config()

    # Try API key first (works in any mode)
    if auth_config.api_keys.enabled:
        raw_key = request.headers.get(auth_config.api_keys.header_name)
        if raw_key:
            from easm.auth.api_keys import hash_api_key

            key_hash = hash_api_key(raw_key)
            try:
                store = get_store()
                result = await store.validate_api_key(key_hash)
                if result:
                    request.state.user = {
                        "user_id": result["user_id"],
                        "username": result["username"],
                        "org_id": result["org_id"],
                        "role": result["role"],
                    }
                    return await call_next(request)
            except (asyncpg.PostgresError, KeyError, ValueError) as e:
                logger.warning(
                    "api key validation failed",
                    exc_info=True, extra={"error": str(e)},
                )
            return JSONResponse(status_code=401, content={"error": "invalid_api_key"})

    # Mode-specific auth
    if auth_config.mode == "none":
        request.state.user = None
        return await call_next(request)

    if auth_config.mode == "reverse_proxy":
        return await _handle_reverse_proxy(request, call_next, auth_config)

    if auth_config.mode in ("local", "sso"):
        return await _handle_session_auth(request, call_next, auth_config)

    request.state.user = None
    return await call_next(request)


async def _handle_reverse_proxy(request: Request, call_next, auth_config) -> Response:
    cfg = auth_config.reverse_proxy
    if cfg is None:
        return JSONResponse(status_code=500, content={"error": "reverse_proxy config missing"})

    client_ip = request.client.host if request.client else "0.0.0.0"
    if not _is_trusted_proxy(client_ip, cfg.trusted_proxies):
        return JSONResponse(status_code=401, content={"error": "untrusted_proxy"})

    username = request.headers.get(cfg.header)
    if not username:
        return JSONResponse(status_code=401, content={"error": "missing_auth_header"})

    try:
        from easm.api.deps import get_store

        store = get_store()
        user = await store.get_user_by_username("default", username)
        if user is None:
            if not cfg.auto_provision:
                return JSONResponse(status_code=401, content={"error": "unknown_user"})
            user = await store.create_user(
                org_id="default",
                username=username,
                role=cfg.auto_provision_role,
            )
        request.state.user = {
            "user_id": user["id"],
            "username": user["username"],
            "org_id": user["org_id"],
            "role": user["role"],
        }
    except (asyncpg.PostgresError, KeyError, ValueError) as e:
        logger.warning(
            "reverse proxy user lookup failed",
            exc_info=True, extra={"error": str(e)},
        )
        return JSONResponse(status_code=500, content={"error": "user_lookup_failed"})

    return await call_next(request)


async def _try_session_auth(request: Request) -> None:
    """Try to populate request.state.user from session cookie. Silently no-ops if no session."""
    from easm.api.deps import get_auth_config

    auth_config = get_auth_config()
    if auth_config.local is None:
        return

    token = request.cookies.get(auth_config.local.cookie_name)
    if not token:
        return

    try:
        from easm.auth.session import decode_session_token

        payload = decode_session_token(token, auth_config.local.session_secret)
        request.state.user = {
            "user_id": payload["sub"],
            "username": payload["username"],
            "org_id": payload["org_id"],
            "role": payload["role"],
        }
    except (jwt.PyJWTError, KeyError, ValueError) as e:
        logger.debug(
            "session token decode failed on exempt path",
            extra={"error": str(e)},
        )


async def _handle_session_auth(request: Request, call_next, auth_config) -> Response:
    local_cfg = auth_config.local
    if local_cfg is None:
        return JSONResponse(status_code=500, content={"error": "local/sso session config missing"})

    token = request.cookies.get(local_cfg.cookie_name)
    if not token:
        return JSONResponse(status_code=401, content={"error": "no_session"})

    try:
        from easm.auth.session import decode_session_token

        payload = decode_session_token(token, local_cfg.session_secret)
        request.state.user = {
            "user_id": payload["sub"],
            "username": payload["username"],
            "org_id": payload["org_id"],
            "role": payload["role"],
        }
    except jwt.ExpiredSignatureError:
        return JSONResponse(status_code=401, content={"error": "session_expired"})
    except (jwt.PyJWTError, KeyError, ValueError) as e:
        logger.debug("invalid session token", extra={"error": str(e)})
        return JSONResponse(status_code=401, content={"error": "invalid_session"})

    return await call_next(request)
