"""FastAPI application factory."""
from __future__ import annotations

import json
import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from soar import bootstrap
from soar.api import analysis_routes, auth, events, incidents, response, system
from soar.config import get_settings
from soar.db import get_engine
from soar.observability import metrics

log = logging.getLogger("soar")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {"ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"), "level": record.levelname,
                   "logger": record.name, "msg": record.getMessage()}
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging() -> None:
    root = logging.getLogger()
    if any(getattr(h, "_soar", False) for h in root.handlers):
        return
    handler = logging.StreamHandler()
    handler._soar = True  # type: ignore[attr-defined]
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    bootstrap.startup()
    yield


def create_app() -> FastAPI:
    s = get_settings()
    app = FastAPI(title="SOAR Intelligence API", version="2.0.0", lifespan=lifespan,
                  docs_url="/api/docs" if s.env != "production" else None,
                  redoc_url=None, openapi_url="/api/openapi.json" if s.env != "production" else None)

    app.add_middleware(CORSMiddleware, allow_origins=s.origins, allow_credentials=True,
                       allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
                       allow_headers=["Authorization", "Content-Type", "X-Requested-With",
                                      "X-API-Key"])

    @app.middleware("http")
    async def observe(request: Request, call_next):  # noqa: ANN001
        rid = uuid.uuid4().hex[:12]
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            log.exception("unhandled error rid=%s path=%s", rid, request.url.path)
            metrics.count("http_500")
            response = JSONResponse({"detail": "Internal server error", "request_id": rid}, 500)
        ms = (time.perf_counter() - start) * 1000
        metrics.observe("http_latency_ms", ms)
        metrics.count(f"http_{response.status_code // 100}xx")
        response.headers["X-Request-ID"] = rid
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    for r in (auth.router, auth.users_router, events.router, incidents.router, response.router,
              analysis_routes.router, system.router):
        app.include_router(r, prefix="/api")

    @app.get("/api/health", tags=["system"])
    def health():
        return {"status": "ok", "service": "soar-api"}

    @app.get("/api/ready", tags=["system"])
    def ready():
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception:
            return JSONResponse({"status": "unavailable", "database": "down"}, 503)
        return {"status": "ready", "database": "up"}

    return app


app = create_app()
