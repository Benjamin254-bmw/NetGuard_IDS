"""Run the API: ``python -m app`` (host and port come from settings; nothing here needs root)."""

from __future__ import annotations

import uvicorn

from app.main import create_app
from netguard_common.config import load_settings


def main() -> None:
    settings = load_settings()
    uvicorn.run(
        create_app(settings),
        host=settings.api_host,
        port=settings.api_port,
        log_config=None,  # application logging is configured by create_app
        server_header=False,
    )


if __name__ == "__main__":
    main()
