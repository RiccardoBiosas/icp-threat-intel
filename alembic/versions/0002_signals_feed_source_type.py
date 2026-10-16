"""Add the ``signals_feed`` source type (community forums, below vendor reporting).

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-15

Widens the ``source_type`` CHECK constraints on ``sources`` and ``events``. SQLite rebuilds
both tables through batch mode (neither has immutability triggers). Downgrading fails while
any row still uses ``signals_feed``; delete those rows first.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_SOURCE_TYPES = (
    "ic_read_state", "raw_gateway", "dashboard_api", "icp_ledger", "nns", "npm", "pypi",
    "threatfox", "urlhaus", "github_advisories", "vendor_rss",
)  # fmt: skip
NEW_SOURCE_TYPES = (*OLD_SOURCE_TYPES, "signals_feed")
TABLES = ("sources", "events")


def _swap(values: Sequence[str]) -> None:
    quoted = ", ".join(f"'{v}'" for v in values)
    for table in TABLES:
        name = f"ck_{table}_source_type_enum"
        with op.batch_alter_table(table) as batch:
            batch.drop_constraint(op.f(name), type_="check")
            batch.create_check_constraint(op.f(name), sa.text(f"source_type IN ({quoted})"))


def upgrade() -> None:
    _swap(NEW_SOURCE_TYPES)


def downgrade() -> None:
    _swap(OLD_SOURCE_TYPES)
