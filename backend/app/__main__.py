"""Run the API: ``python -m app`` (host and port come from settings; nothing here needs root)."""

from __future__ import annotations

from typing import Any

import uvicorn

from app.main import create_app
from netguard_common.config import Settings, load_settings

# X-Forwarded-For / X-Forwarded-Proto are honoured ONLY from these peers: the reverse proxy on the
# same machine (deploy/nginx). Stated here rather than inherited from uvicorn's FORWARDED_ALLOW_IPS
# default, so an environment variable cannot widen it. Behind nginx this gives the real client
# address (login limiter, audit log) and the https scheme (same-origin checks); without a proxy the
# peer is the client itself.
TRUSTED_PROXIES = "127.0.0.1,::1"


def server_options(settings: Settings) -> dict[str, Any]:
    return {
        "host": settings.api_host,
        "port": settings.api_port,
        "log_config": None,  # application logging is configured by create_app
        "server_header": False,
        "proxy_headers": True,
        "forwarded_allow_ips": TRUSTED_PROXIES,
    }


def main() -> None:
    settings = load_settings()
    uvicorn.run(create_app(settings), **server_options(settings))


if __name__ == "__main__":
    main()
