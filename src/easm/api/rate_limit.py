"""Simple in-memory per-IP rate limiter for sensitive endpoints."""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from collections.abc import Awaitable, Callable

from fastapi import HTTPException, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate-limits specific paths per IP address."""

    def __init__(
        self,
        app: ASGIApp,
        limits: dict[str, tuple[int, int]] | None = None,
    ) -> None:
        super().__init__(app)
        self.limits = limits or {
            "/api/auth/login": (5, 60),
            "/api/auth/register": (3, 300),
            "/api/runs/": (10, 60),
        }
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        for path, (max_reqs, window_sec) in self.limits.items():
            if request.url.path.startswith(path):
                await self._check_rate_limit(request, path, max_reqs, window_sec)
                break
        response = await call_next(request)
        return response

    async def _check_rate_limit(
        self, request: Request, path: str, max_reqs: int, window_sec: int,
    ) -> None:
        host = request.client.host if request.client else "unknown"
        key = f"{host}:{path}"
        now = time.time()
        async with self._lock:
            bucket = self._buckets[key]
            cutoff = now - window_sec
            bucket[:] = [t for t in bucket if t > cutoff]
            if len(bucket) >= max_reqs:
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded. Try again in {window_sec}s.",
                )
            bucket.append(now)
