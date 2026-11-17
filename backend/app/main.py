"""FastAPI application factory."""

from __future__ import annotations

import contextlib
import logging
from collections.abc import AsyncIterator, Awaitable, Callable

from fastapi import FastAPI, Request, Response, status
from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError

from app import realtime
from app.api import alerts, audit_logs, auth, devices, events, rules, system, traffic, users
from app.ratelimit import FailureLimiter
from netguard_common.config import Settings, load_settings
from netguard_common.db import make_engine
from netguard_common.logging_config import configure_logging

log = logging.getLogger(__name__)
DbCheck = Callable[[], bool]

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}
DOC_PATHS = ("/docs", "/redoc", "/openapi.json")


def _engine_check(engine: Engine) -> DbCheck:
    def check() -> bool:
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return True
        except SQLAlchemyError:
            log.exception("database readiness check failed")
            return False

    return check


def create_app(
    settings: Settings | None = None,
    db_check: DbCheck | None = None,
    engine: Engine | None = None,
) -> FastAPI:
    settings = settings or load_settings()
    configure_logging("api", settings.log_level, settings.log_format)
    if engine is None and db_check is None:
        engine = make_engine(settings, "api", pool_size=10)
    if db_check is None:
        if engine is None:
            raise RuntimeError("an engine or a db_check is required")
        db_check = _engine_check(engine)
    check = db_check

    dev = settings.env != "production"

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        hub = None
        if engine is not None:
            hub = realtime.Hub(settings, engine)
            app.state.hub = hub
            hub.start()
        try:
            yield
        finally:
            if hub is not None:
                await hub.stop()

    app = FastAPI(
        lifespan=lifespan,
        title="NetGuard IDS API",
        version="0.2.0",
        docs_url="/docs" if dev else None,  # interactive docs only outside production
        redoc_url=None,
        openapi_url="/openapi.json" if dev else None,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.limiter = FailureLimiter()

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            if name == "Content-Security-Policy" and request.url.path.startswith(DOC_PATHS):
                continue  # the dev-only docs page needs scripts; it does not exist in production
            response.headers.setdefault(name, value)
        return response

    @app.get("/api/health")
    def health() -> dict[str, str]:
        """Liveness: the process is up. Says nothing about dependencies."""
        return {"status": "ok"}

    @app.get("/api/health/ready")
    def ready(response: Response) -> dict[str, str]:
        """Readiness: reports dependency state without leaking internals."""
        if check():
            return {"status": "ok", "database": "ok"}
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "degraded", "database": "unavailable"}

    app.include_router(auth.router)
    app.include_router(users.router)
    app.include_router(realtime.router)
    for module in (system, devices, traffic, events, alerts, rules, audit_logs):
        app.include_router(module.router)
    return app
