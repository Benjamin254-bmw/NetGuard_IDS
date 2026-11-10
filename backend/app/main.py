"""FastAPI application factory. Phase 1 exposes health endpoints only."""

from __future__ import annotations

import logging
from collections.abc import Callable

from fastapi import FastAPI, Response, status
from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError

from netguard_common.config import Settings, load_settings
from netguard_common.db import make_engine
from netguard_common.logging_config import configure_logging

log = logging.getLogger(__name__)
DbCheck = Callable[[], bool]


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


def create_app(settings: Settings | None = None, db_check: DbCheck | None = None) -> FastAPI:
    settings = settings or load_settings()
    configure_logging("api", settings.log_level, settings.log_format)
    if db_check is None:
        db_check = _engine_check(make_engine(settings, "api"))
    check = db_check

    app = FastAPI(title="NetGuard IDS API", version="0.1.0")

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

    return app
