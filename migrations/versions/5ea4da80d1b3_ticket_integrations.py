"""ticket integrations

Revision ID: 5ea4da80d1b3
Revises: 30d8a25ac98c
Create Date: 2026-07-19 17:54:18.258502
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5ea4da80d1b3'
down_revision: str | None = '30d8a25ac98c'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("finding_group", schema=None) as batch_op:
        batch_op.add_column(sa.Column("ticket_url", sa.String(), nullable=True))

    op.create_table(
        "integration_target",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["created_by"], ["app_user.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("integration_target")
    with op.batch_alter_table("finding_group", schema=None) as batch_op:
        batch_op.drop_column("ticket_url")
