"""Typed, validated configuration loaded from NETGUARD_* environment variables / a .env file."""

from __future__ import annotations

import os
from ipaddress import IPv4Network
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL

Role = Literal["migrator", "monitor", "api"]
PLACEHOLDER = "CHANGE_ME"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NETGUARD_", extra="ignore")

    env: Literal["development", "test", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: Literal["text", "json"] = "text"

    db_host: str = "127.0.0.1"
    db_port: int = 5432
    db_name: str = "netguard"
    db_migrator_user: str = "netguard_migrator"
    db_migrator_password: SecretStr | None = None
    db_monitor_user: str = "netguard_monitor"
    db_monitor_password: SecretStr | None = None
    db_api_user: str = "netguard_api"
    db_api_password: SecretStr | None = None

    secret_key: SecretStr | None = None

    # No defaults on purpose: capture and discovery must be explicitly authorised.
    monitor_interface: str | None = None
    authorized_subnet: IPv4Network | None = None

    # Monitor tuning. Every value is bounded so a typo cannot disable a safeguard.
    capture_queue_size: int = Field(10_000, ge=1_000, le=1_000_000)
    write_queue_size: int = Field(500, ge=10, le=100_000)
    flow_cap_per_minute: int = Field(5_000, ge=100, le=1_000_000)
    inactive_after_seconds: int = Field(300, ge=10, le=86_400)
    promiscuous: bool = False  # for mirror/SPAN ports; ends when the socket closes
    active_discovery: bool = False  # off unless explicitly enabled
    active_discovery_interval_seconds: int = Field(300, ge=30, le=86_400)
    retention_1s_hours: int = Field(24, ge=1, le=720)
    retention_1m_days: int = Field(30, ge=1, le=3650)
    spill_dir: Path = Path("var/spill")
    spill_max_mb: int = Field(100, ge=1, le=10_240)

    # Detection (Phase 4). The auth log is optional: without it the auth_failures rule is idle.
    auth_log_path: Path | None = None
    rules_reload_seconds: int = Field(10, ge=2, le=3600)

    @field_validator("monitor_interface", "authorized_subnet", "auth_log_path", mode="before")
    @classmethod
    def _empty_is_unset(cls, v: object) -> object:
        return None if isinstance(v, str) and v.strip() == "" else v

    @model_validator(mode="after")
    def _reject_placeholders(self) -> Settings:
        secrets = {
            "db_migrator_password": self.db_migrator_password,
            "db_monitor_password": self.db_monitor_password,
            "db_api_password": self.db_api_password,
            "secret_key": self.secret_key,
        }
        for name, value in secrets.items():
            if value is not None and value.get_secret_value() == PLACEHOLDER:
                raise ValueError(f"{name} still has the placeholder value; run 'make init-env'")
        if self.env == "production" and self.secret_key is None:
            raise ValueError("secret_key is required when env=production")
        return self

    def db_url(self, role: Role) -> URL:
        """Build the SQLAlchemy URL for one least-privilege database role."""
        user = getattr(self, f"db_{role}_user")
        password: SecretStr | None = getattr(self, f"db_{role}_password")
        if password is None:
            raise ValueError(f"NETGUARD_DB_{role.upper()}_PASSWORD is not set")
        return URL.create(
            "postgresql+psycopg",
            username=user,
            password=password.get_secret_value(),
            host=self.db_host,
            port=self.db_port,
            database=self.db_name,
        )


def load_settings(env_file: str | os.PathLike[str] | None = None) -> Settings:
    """Load settings. Order: explicit arg, $NETGUARD_ENV_FILE, ./.env (if present), environment."""
    chosen: str | None = os.fspath(env_file) if env_file else os.environ.get("NETGUARD_ENV_FILE")
    if chosen is None and Path(".env").is_file() and os.access(".env", os.R_OK):
        chosen = ".env"  # an unreadable .env is skipped: the environment may supply everything
    return Settings(_env_file=chosen)
