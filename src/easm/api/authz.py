from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import HTTPException, Request, status


def require_role(role: str = "admin") -> Callable[[Request], Awaitable[None]]:
    """Dependency factory that checks the authenticated user has the required role."""

    async def _check(request: Request) -> None:
        user = getattr(request.state, "user", None)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )
        if user.get("role", "") != role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role}' required",
            )

    return _check


require_admin = require_role("admin")


def current_org_id(request: Request) -> str:
    """Get the current user's org_id, raising if not available."""
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return str(user.get("org_id", "default"))
