from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from easm.api.routes import config as config_route
from easm.api.routes import entities, events, findings as findings_route, graph, health, pivot_queue, runs, targets

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> Any:
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
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled exception", extra={"path": request.url.path})
        return JSONResponse(status_code=500, content={"error": "internal", "detail": str(exc)})

    app.include_router(health.router, prefix="/api")
    app.include_router(targets.router, prefix="/api")
    app.include_router(events.router, prefix="/api")
    app.include_router(runs.router, prefix="/api")
    app.include_router(entities.router, prefix="/api")
    app.include_router(graph.router, prefix="/api")
    app.include_router(config_route.router, prefix="/api")
    app.include_router(pivot_queue.router, prefix="/api")
    app.include_router(findings_route.router, prefix="/api")

    # Serve React SPA from ui/dist (production only)
    import os
    _static_dir = os.path.join(os.path.dirname(__file__), "..", "..", "..", "ui", "dist")
    if os.path.isdir(_static_dir):
        from fastapi.staticfiles import StaticFiles  # noqa: F401
        from fastapi.responses import FileResponse

        @app.get("/ui/{full_path:path}")
        async def serve_spa(full_path: str):
            file_path = os.path.join(_static_dir, full_path)
            if os.path.isfile(file_path):
                return FileResponse(file_path)
            return FileResponse(os.path.join(_static_dir, "index.html"))

        @app.get("/ui")
        async def serve_spa_index():
            return FileResponse(os.path.join(_static_dir, "index.html"))

    return app
