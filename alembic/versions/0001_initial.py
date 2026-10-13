"""Initial schema: every SPEC table, pgvector extension and immutability triggers.

Revision ID: 0001
Revises:
Create Date: 2026-10-14

Generated with ``alembic revision --autogenerate`` and condensed with column helpers.
``tests/unit/test_models.py`` checks that it matches the ORM models exactly. Postgres-only
steps (pgvector extension, plpgsql triggers) sit behind a dialect check; SQLite gets
equivalent triggers.
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
BIG = sa.BigInteger().with_variant(sa.Integer(), "sqlite")
TS = sa.DateTime(timezone=True)
STR27 = sa.String(length=27)
STR64 = sa.String(length=64)
NUM = sa.Numeric(precision=30, scale=0)

SOURCE_TYPES = (
    "ic_read_state", "raw_gateway", "dashboard_api", "icp_ledger", "nns", "npm", "pypi",
    "threatfox", "urlhaus", "github_advisories", "vendor_rss",
)  # fmt: skip
CANISTER_STATUSES = ("running", "stopping", "stopped", "unknown")
DETECTION_STATUSES = ("candidate", "verified", "dismissed")
ECOSYSTEMS = ("npm", "pypi")
IOC_TYPES = (
    "canister_id", "url", "domain", "package_version", "file_path", "systemd_unit", "account",
)  # fmt: skip
IMMUTABLE_TABLES = ("raw_snapshots", "canister_snapshots")
# Dependency order; downgrade drops in reverse.
TABLES = (
    "canisters", "detections", "packages", "publications", "sources", "iocs", "raw_snapshots",
    "canister_snapshots", "events", "ledger_transfers", "package_versions", "proposals",
)  # fmt: skip


def c(name: str, type_: Any, nullable: bool = False, **kw: Any) -> sa.Column[Any]:
    return sa.Column(name, type_, nullable=nullable, **kw)


def enum(name: str, values: Sequence[str]) -> sa.Enum:
    return sa.Enum(*values, name=name, native_enum=False, length=32)


def enum_ck(table: str, column: str, values: Sequence[str]) -> sa.CheckConstraint:
    quoted = ", ".join(f"'{v}'" for v in values)
    return sa.CheckConstraint(f"{column} IN ({quoted})", name=op.f(f"ck_{table}_{column}_enum"))


def ck(table: str, name: str, sql: str) -> sa.CheckConstraint:
    return sa.CheckConstraint(sql, name=op.f(f"ck_{table}_{name}"))


def pk(table: str) -> sa.PrimaryKeyConstraint:
    return sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{table}"))


def uq(table: str, *cols: str) -> sa.UniqueConstraint:
    return sa.UniqueConstraint(*cols, name=op.f(f"uq_{table}_{'_'.join(cols)}"))


def fk(table: str, col: str, target: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint([col], [f"{target}.id"], name=op.f(f"fk_{table}_{col}_{target}"))


def index(table: str, *cols: str) -> None:
    for col in cols:
        op.create_index(op.f(f"ix_{table}_{col}"), table, [col], unique=False)


def upgrade() -> None:
    dialect = op.get_context().dialect.name
    if dialect == "postgresql":
        op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    t = "canisters"
    op.create_table(
        t,
        c("id", STR27), c("subnet", sa.String(length=63), True), c("controllers", JSON),
        c("module_hash", STR64, True), c("status", enum("canister_status", CANISTER_STATUSES)),
        c("first_seen", TS), c("last_seen", TS), c("candid_methods", JSON, True),
        c("candid_sha256", STR64, True), c("is_ioc", sa.Boolean()), c("updated_at", TS),
        enum_ck(t, "status", CANISTER_STATUSES), ck(t, "id_length", "length(id) = 27"), pk(t),
    )  # fmt: skip
    t = "detections"
    op.create_table(
        t,
        c("id", BIG), c("rule_id", sa.String(length=8)), c("rule_version", sa.String(length=16)),
        c("subject_type", sa.String(length=16)), c("subject_id", sa.Text()),
        c("canister_id", STR27, True), c("score", sa.Float()),
        c("weighted_confidence", sa.Float()), c("signals", JSON), c("evidence_refs", JSON),
        c("status", enum("detection_status", DETECTION_STATUSES)), c("status_history", JSON),
        c("created_at", TS), c("updated_at", TS), c("verified_at", TS, True),
        c("dismissed_at", TS, True), c("dedup_key", STR64),
        enum_ck(t, "status", DETECTION_STATUSES),
        ck(t, "score_range", "score >= 0 AND score <= 1"),
        ck(t, "confidence_range", "weighted_confidence >= 0 AND weighted_confidence <= 1"),
        pk(t), uq(t, "dedup_key"),
    )  # fmt: skip
    index(t, "canister_id", "rule_id")
    t = "packages"
    op.create_table(
        t,
        c("id", sa.Integer()), c("ecosystem", enum("ecosystem", ECOSYSTEMS)), c("name", sa.Text()),
        c("first_seen", TS), c("last_seen", TS), c("is_ioc", sa.Boolean()),
        enum_ck(t, "ecosystem", ECOSYSTEMS), pk(t), uq(t, "ecosystem", "name"),
    )  # fmt: skip
    t = "publications"
    op.create_table(
        t,
        c("id", BIG), c("case_id", sa.String(length=36)), c("format", sa.String(length=16)),
        c("detection_ids", JSON), c("ioc_ids", JSON), c("disclosed_at", TS),
        c("disclosure_contact", sa.Text()), c("created_at", TS), c("payload_sha256", STR64),
        c("path", sa.Text()), c("submitted", sa.Boolean(), server_default=sa.false()),
        c("submitted_at", TS, True), pk(t),
    )  # fmt: skip
    index(t, "case_id")
    t = "sources"
    op.create_table(
        t,
        c("id", sa.Integer()), c("name", STR64),
        c("source_type", enum("source_type", SOURCE_TYPES)),
        c("base_url", sa.Text()), c("reliability", sa.SmallInteger()),
        c("status", sa.String(length=16)), c("enabled", sa.Boolean()), c("created_at", TS),
        enum_ck(t, "source_type", SOURCE_TYPES),
        ck(t, "reliability", "reliability BETWEEN 0 AND 100"), pk(t), uq(t, "name"),
    )  # fmt: skip
    t = "iocs"
    op.create_table(
        t,
        c("id", sa.Integer()), c("ioc_type", enum("ioc_type", IOC_TYPES)), c("value", sa.Text()),
        c("threat_type", STR64, True), c("malware", sa.String(length=128), True),
        c("confidence", sa.SmallInteger(), True), c("first_seen", TS, True),
        c("last_seen", TS, True), c("expires_at", TS, True), c("tags", JSON),
        c("reporter", sa.String(length=128), True), c("campaign", STR64, True),
        c("source_id", sa.Integer()), c("source_ref", sa.String(length=128)),
        c("source_url", sa.Text()), c("notes", sa.Text(), True), c("detection_id", BIG, True),
        enum_ck(t, "ioc_type", IOC_TYPES),
        ck(t, "confidence", "confidence IS NULL OR confidence BETWEEN 0 AND 100"),
        fk(t, "detection_id", "detections"), fk(t, "source_id", "sources"), pk(t),
        uq(t, "ioc_type", "value", "source_ref"),
    )  # fmt: skip
    t = "raw_snapshots"
    op.create_table(
        t,
        c("id", BIG), c("source_id", sa.Integer()), c("url", sa.Text()), c("fetched_at", TS),
        c("sha256", STR64), c("body", sa.LargeBinary()), c("stored_sha256", STR64),
        c("size_bytes", sa.Integer()), c("truncated", sa.Boolean()),
        c("http_status", sa.SmallInteger(), True), c("content_type", sa.String(length=255), True),
        c("headers", JSON), c("redacted", sa.Boolean()), c("redaction_kinds", JSON),
        c("synthetic", sa.Boolean()), c("request_meta", JSON),
        fk(t, "source_id", "sources"), pk(t), uq(t, "source_id", "url", "sha256"),
    )  # fmt: skip
    t = "canister_snapshots"
    op.create_table(
        t,
        c("id", BIG), c("canister_id", STR27), c("observed_at", TS), c("source_id", sa.Integer()),
        c("raw_snapshot_id", BIG, True), c("census_run_id", sa.String(length=36), True),
        c("subnet", sa.String(length=63), True), c("controllers", JSON),
        c("module_hash", STR64, True), c("status", enum("canister_status", CANISTER_STATUSES)),
        c("candid_methods", JSON, True), c("candid_sha256", STR64, True),
        enum_ck(t, "status", CANISTER_STATUSES), fk(t, "canister_id", "canisters"),
        fk(t, "raw_snapshot_id", "raw_snapshots"), fk(t, "source_id", "sources"), pk(t),
        uq(t, "canister_id", "source_id", "raw_snapshot_id"),
    )  # fmt: skip
    index(t, "canister_id", "census_run_id")
    t = "events"
    op.create_table(
        t,
        c("id", BIG), c("kind", STR64), c("subject_type", sa.String(length=16)),
        c("subject_id", sa.Text()), c("canister_id", STR27, True), c("observed_at", TS),
        c("source_id", sa.Integer()), c("source_type", enum("source_type", SOURCE_TYPES)),
        c("raw_snapshot_id", BIG, True), c("parser", STR64), c("weight", sa.SmallInteger()),
        c("is_ioc", sa.Boolean()), c("payload", JSON), c("dedup_key", STR64),
        enum_ck(t, "source_type", SOURCE_TYPES), fk(t, "raw_snapshot_id", "raw_snapshots"),
        fk(t, "source_id", "sources"), pk(t), uq(t, "dedup_key"),
    )  # fmt: skip
    index(t, "canister_id", "kind")
    t = "ledger_transfers"
    op.create_table(
        t,
        c("id", BIG), c("block_index", sa.BigInteger()), c("from_account", STR64),
        c("to_account", STR64), c("amount_e8s", NUM), c("fee_e8s", NUM), c("memo", NUM, True),
        c("created_at", TS), c("is_cmc_topup", sa.Boolean()),
        c("target_canister_id", STR27, True), c("raw_snapshot_id", BIG),
        fk(t, "raw_snapshot_id", "raw_snapshots"), pk(t), uq(t, "block_index"),
    )  # fmt: skip
    index(t, "from_account", "target_canister_id", "to_account")
    t = "package_versions"
    op.create_table(
        t,
        c("id", BIG), c("package_id", sa.Integer()), c("version", sa.String(length=128)),
        c("published_at", TS, True), c("tarball_sha256", STR64, True),
        c("tarball_path", sa.Text(), True), c("install_hooks", JSON), c("canister_refs", JSON),
        c("host_indicators", JSON), c("raw_snapshot_id", BIG, True), c("is_ioc", sa.Boolean()),
        fk(t, "package_id", "packages"), fk(t, "raw_snapshot_id", "raw_snapshots"), pk(t),
        uq(t, "package_id", "version"),
    )  # fmt: skip
    t = "proposals"
    op.create_table(
        t,
        c("id", BIG, autoincrement=False), c("title", sa.Text()), c("topic", STR64),
        c("action_type", STR64), c("status", sa.String(length=32)), c("proposer", STR64, True),
        c("created_at", TS), c("decided_at", TS, True), c("executed_at", TS, True),
        c("referenced_canisters", JSON), c("referenced_subnets", JSON), c("summary", sa.Text()),
        c("raw_snapshot_id", BIG), fk(t, "raw_snapshot_id", "raw_snapshots"), pk(t),
    )  # fmt: skip

    for statement in _trigger_ddl(dialect):
        op.execute(statement)


def _trigger_ddl(dialect: str) -> list[str]:
    """Reject UPDATE and DELETE on the append-only tables (same SQL as db/immutability.py)."""
    statements: list[str] = []
    if dialect == "postgresql":
        statements.append(
            "CREATE OR REPLACE FUNCTION reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN RAISE EXCEPTION USING MESSAGE = TG_TABLE_NAME || ' is immutable'; END $$"
        )
    for table in IMMUTABLE_TABLES:
        if dialect == "postgresql":
            statements.append(
                f"CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE ON {table} "
                "FOR EACH ROW EXECUTE FUNCTION reject_mutation()"
            )
        elif dialect == "sqlite":
            statements.extend(
                f"CREATE TRIGGER {table}_no_{op_.lower()} BEFORE {op_} ON {table} "
                f"BEGIN SELECT RAISE(ABORT, '{table} is immutable'); END"
                for op_ in ("UPDATE", "DELETE")
            )
    return statements


def downgrade() -> None:
    for table in reversed(TABLES):
        op.drop_table(table)  # indexes and triggers go with the table
    if op.get_context().dialect.name == "postgresql":
        op.execute("DROP FUNCTION IF EXISTS reject_mutation()")
