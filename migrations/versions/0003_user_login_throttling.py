"""login throttling and session revocation columns on users

Revision ID: 0003
Revises: 0002
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("failed_login_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
    )
    op.add_column("users", sa.Column("locked_until", postgresql.TIMESTAMP(timezone=True)))
    op.add_column(
        "users",
        sa.Column("session_version", sa.Integer(), server_default=sa.text("1"), nullable=False),
    )
    op.add_column("users", sa.Column("password_changed_at", postgresql.TIMESTAMP(timezone=True)))
    op.create_check_constraint(
        op.f("ck_users_failed_login_count_nonneg"), "users", "failed_login_count >= 0"
    )
    op.create_check_constraint(
        op.f("ck_users_session_version_positive"), "users", "session_version >= 1"
    )
    # Grants are unchanged: the api role already holds SELECT, INSERT, UPDATE on all of users.


def downgrade() -> None:
    op.drop_constraint(op.f("ck_users_session_version_positive"), "users", type_="check")
    op.drop_constraint(op.f("ck_users_failed_login_count_nonneg"), "users", type_="check")
    op.drop_column("users", "password_changed_at")
    op.drop_column("users", "session_version")
    op.drop_column("users", "locked_until")
    op.drop_column("users", "failed_login_count")
