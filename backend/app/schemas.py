"""Request/response models. Inputs forbid unknown fields and bound every string and number."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

USERNAME_RE = r"^[A-Za-z0-9_.-]{3,64}$"
EMAIL_RE = r"^[^@\s]{1,64}@[^@\s]{1,189}\.[^@\s]{2,24}$"
Role = Literal["admin", "analyst"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class LoginIn(Strict):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class PasswordChangeIn(Strict):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class UserCreateIn(Strict):
    username: str = Field(pattern=USERNAME_RE)
    password: str = Field(min_length=1, max_length=256)
    role: Role = "analyst"
    email: str | None = Field(default=None, pattern=EMAIL_RE)


class UserPatchIn(Strict):
    role: Role | None = None
    is_active: bool | None = None
    email: str | None = Field(default=None, pattern=EMAIL_RE)


class PasswordResetIn(Strict):
    new_password: str = Field(min_length=1, max_length=256)


class UserOut(BaseModel):
    id: int
    username: str
    email: str | None
    role: Role
    is_active: bool = True
    created_at: datetime | None = None
    last_login_at: datetime | None = None
    locked: bool = False


class SessionOut(BaseModel):
    user: UserOut


EventStatus = Literal["new", "investigating", "resolved", "false_positive"]
AlertStatus = Literal["new", "acknowledged", "dismissed"]
SeverityName = Literal["informational", "low", "medium", "high", "critical"]


class EventStatusIn(Strict):
    status: EventStatus


class AlertStatusIn(Strict):
    status: AlertStatus


class RulePatchIn(Strict):
    enabled: bool | None = None
    severity: SeverityName | None = None
    threshold: int | None = Field(default=None, ge=1, le=2_000_000_000)
    window_seconds: int | None = Field(default=None, ge=1, le=3600)
    cooldown_seconds: int | None = Field(default=None, ge=0, le=86_400)
    params: dict[str, object] | None = None
