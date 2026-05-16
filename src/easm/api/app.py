from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from easm.api.routes import health, targets, events, runs

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("API starting up")
    yield
    logger.info("API shutting down")


def create_app() -> FastAPI:
    app = FastAPI(
        title="open-easm",
        description="Self-hosted passive External Attack Surface Management monitoring platform",
        version="0.2.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(Exception)
    async def global_exception_handler(request, exc):
        logger.exception("unhandled exception", extra={"path": request.url.path})
        return JSONResponse(status_code=500, content={"error": "internal", "detail": str(exc)})

    app.include_router(health.router)
    app.include_router(targets.router)
    app.include_router(events.router)
    app.include_router(runs.router)

    return app
