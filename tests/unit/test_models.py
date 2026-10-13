"""Data model: tables, constraints, the detection status enum, immutability, and the
initial migration matching the models."""

import io
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import Engine, delete, inspect, text, update
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateTable

from icp_threat_intel.core.enums import CanisterStatus, DetectionStatus, SourceType
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.immutability import IMMUTABLE_TABLES, ImmutableRowError
from icp_threat_intel.db.models import (
    Canister,
    CanisterSnapshot,
    DetectionRow,
    EventRow,
    Ioc,
    Publication,
    RawSnapshotRow,
    Source,
)
from icp_threat_intel.db.session import make_engine

REPO = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)
CANISTER = "tdtqy-oyaaa-aaaae-af2dq-cai"
SPEC_TABLES = {
    "sources",
    "canisters",
    "canister_snapshots",
    "raw_snapshots",
    "events",
    "packages",
    "package_versions",
    "ledger_transfers",
    "proposals",
    "detections",
    "iocs",
    "publications",
}


@pytest.fixture
def engine() -> Iterator[Engine]:
    eng = make_engine("sqlite://")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def session(engine: Engine) -> Iterator[Session]:
    with Session(engine) as s:
        yield s


def _source(session: Session, name: str = "ic-read-state", reliability: int = 90) -> Source:
    src = Source(
        name=name, source_type=SourceType.IC_READ_STATE, base_url="https://icp-api.io",
        reliability=reliability,
    )  # fmt: skip
    session.add(src)
    session.flush()
    return src


def _raw(
    session: Session, src: Source, url: str = "ic://x/read_state/module_hash"
) -> RawSnapshotRow:
    row = RawSnapshotRow(
        source_id=src.id, url=url, fetched_at=NOW, sha256="a" * 64, body=b"body",
        stored_sha256="a" * 64, size_bytes=4,
    )  # fmt: skip
    session.add(row)
    session.flush()
    return row


def _snapshot(session: Session, src: Source, raw: RawSnapshotRow) -> CanisterSnapshot:
    session.add(Canister(id=CANISTER))
    snap = CanisterSnapshot(
        canister_id=CANISTER, observed_at=NOW, source_id=src.id, raw_snapshot_id=raw.id,
        status=CanisterStatus.RUNNING,
    )  # fmt: skip
    session.add(snap)
    session.flush()
    return snap


def _detection(**overrides: object) -> DetectionRow:
    fields: dict[str, object] = {
        "rule_id": "H1", "subject_type": "canister", "subject_id": CANISTER, "score": 0.8,
        "dedup_key": "d" * 64,
    }  # fmt: skip
    fields.update(overrides)
    return DetectionRow(**fields)


def test_every_spec_table_is_mapped() -> None:
    assert set(Base.metadata.tables) == SPEC_TABLES


def test_postgres_gets_jsonb_and_bigint() -> None:
    ddl = str(CreateTable(RawSnapshotRow.__table__).compile(dialect=postgresql.dialect()))  # type: ignore[arg-type]
    assert "JSONB" in ddl
    assert "BIGSERIAL" in ddl or "BIGINT" in ddl
    assert "TIMESTAMP WITH TIME ZONE" in ddl
    lite = str(CreateTable(RawSnapshotRow.__table__).compile(dialect=sqlite.dialect()))  # type: ignore[arg-type]
    assert "JSONB" not in lite
    assert "id INTEGER NOT NULL" in lite


def test_source_reliability_is_bounded(session: Session) -> None:
    with pytest.raises(IntegrityError):
        _source(session, reliability=101)


def test_source_name_is_unique(session: Session) -> None:
    _source(session)
    with pytest.raises(IntegrityError):
        _source(session)


def test_canister_id_is_validated(session: Session) -> None:
    with pytest.raises(ValueError):
        Canister(id="not-a-canister")
    with pytest.raises(IntegrityError):
        session.execute(text("INSERT INTO canisters (id, controllers, status, first_seen, "
                             "last_seen, is_ioc, updated_at) VALUES ('abc', '[]', 'running', "
                             "'2026-01-01', '2026-01-01', 0, '2026-01-01')"))  # fmt: skip


def test_detection_status_enum(session: Session) -> None:
    status_type = DetectionRow.__table__.c.status.type
    assert list(status_type.enums) == ["candidate", "verified", "dismissed"]  # type: ignore[attr-defined]
    assert [s.value for s in DetectionStatus] == ["candidate", "verified", "dismissed"]
    det = _detection()
    session.add(det)
    session.flush()
    assert det.status is DetectionStatus.CANDIDATE


def test_detection_status_rejects_unknown_values(session: Session) -> None:
    session.add(_detection(status="bogus"))
    with pytest.raises(StatementError):
        session.flush()
    session.rollback()
    with pytest.raises(IntegrityError):
        session.execute(text(
            "INSERT INTO detections (rule_id, rule_version, subject_type, subject_id, score, "
            "weighted_confidence, signals, evidence_refs, status, status_history, created_at, "
            "updated_at, dedup_key) VALUES ('H1', '1', 'canister', 'x', 0.5, 0, '[]', '[]', "
            "'bogus', '[]', '2026-01-01', '2026-01-01', 'k')"
        ))  # fmt: skip


@pytest.mark.parametrize("score", [-0.1, 1.5])
def test_detection_score_is_bounded(session: Session, score: float) -> None:
    session.add(_detection(score=score))
    with pytest.raises(IntegrityError):
        session.flush()


def test_detection_dedup_key_is_unique(session: Session) -> None:
    session.add(_detection())
    session.flush()
    session.add(_detection())
    with pytest.raises(IntegrityError):
        session.flush()


def test_event_dedup_key_and_canister_id(session: Session) -> None:
    src = _source(session)

    def event() -> EventRow:
        return EventRow(
            kind="canister.state_observed", subject_type="canister", subject_id=CANISTER,
            canister_id=CANISTER, observed_at=NOW, source_id=src.id,
            source_type=SourceType.IC_READ_STATE, parser="read_state/1", dedup_key="e" * 64,
        )  # fmt: skip

    session.add(event())
    session.flush()
    session.add(event())
    with pytest.raises(IntegrityError):
        session.flush()
    with pytest.raises(ValueError):
        EventRow(canister_id="bad")


def test_raw_snapshot_is_unique_per_source_url_hash(session: Session) -> None:
    src = _source(session)
    _raw(session, src)
    with pytest.raises(IntegrityError):
        _raw(session, src)


def test_ioc_uniqueness_and_confidence(session: Session) -> None:
    src = _source(session, name="threatfox")

    def ioc(confidence: int = 90) -> Ioc:
        return Ioc(
            ioc_type="url", value=f"https://{CANISTER}.raw.icp0.io/", confidence=confidence,
            source_id=src.id, source_ref="threatfox:1781006",
            source_url="https://threatfox.abuse.ch/ioc/1781006/",
        )  # fmt: skip

    session.add(ioc())
    session.flush()
    session.add(ioc())
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()
    src = _source(session, name="threatfox")
    session.add(ioc(confidence=101))
    with pytest.raises(IntegrityError):
        session.flush()


def test_publication_needs_disclosed_at_and_is_not_submitted(session: Session) -> None:
    def pub(disclosed_at: datetime | None) -> Publication:
        return Publication(
            case_id="c", format="stix21", disclosed_at=disclosed_at, disclosure_contact="x",
            payload_sha256="b" * 64, path="out/c.json",
        )  # fmt: skip

    ok = pub(NOW)
    session.add(ok)
    session.flush()
    assert ok.submitted is False
    session.add(pub(None))
    with pytest.raises(IntegrityError):
        session.flush()


@pytest.mark.parametrize("kind", ["raw", "snapshot"])
def test_immutable_rows_refuse_orm_update(session: Session, kind: str) -> None:
    src = _source(session)
    raw = _raw(session, src)
    row: RawSnapshotRow | CanisterSnapshot = raw if kind == "raw" else _snapshot(session, src, raw)
    if isinstance(row, RawSnapshotRow):
        row.url = "changed"
    else:
        row.module_hash = "c" * 64
    with pytest.raises(ImmutableRowError):
        session.flush()


@pytest.mark.parametrize("kind", ["raw", "snapshot"])
def test_immutable_rows_refuse_orm_delete(session: Session, kind: str) -> None:
    src = _source(session)
    raw = _raw(session, src)
    row: RawSnapshotRow | CanisterSnapshot = raw if kind == "raw" else _snapshot(session, src, raw)
    session.delete(row)
    with pytest.raises(ImmutableRowError):
        session.flush()


@pytest.mark.parametrize("model", [RawSnapshotRow, CanisterSnapshot])
def test_immutable_tables_refuse_bulk_statements(
    session: Session, model: type[RawSnapshotRow] | type[CanisterSnapshot]
) -> None:
    with pytest.raises(ImmutableRowError):
        session.execute(update(model).values(id=1))
    with pytest.raises(ImmutableRowError):
        session.execute(delete(model))


@pytest.mark.parametrize("table", IMMUTABLE_TABLES)
def test_database_triggers_refuse_raw_sql(session: Session, table: str) -> None:
    src = _source(session)
    _snapshot(session, src, _raw(session, src))
    with pytest.raises(IntegrityError):
        session.execute(text(f"UPDATE {table} SET id = id"))  # noqa: S608
    with pytest.raises(IntegrityError):
        session.execute(text(f"DELETE FROM {table}"))  # noqa: S608


def test_immutable_tables_still_accept_inserts(session: Session) -> None:
    src = _source(session)
    _raw(session, src, url="a")
    _raw(session, src, url="b")
    assert session.query(RawSnapshotRow).count() == 2


def _alembic_config(url: str, buffer: io.StringIO | None = None) -> Config:
    cfg = Config(str(REPO / "alembic.ini"), output_buffer=buffer)
    cfg.set_main_option("script_location", str(REPO / "alembic"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def test_migration_matches_models(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'migrated.db'}"
    command.upgrade(_alembic_config(url), "head")
    engine = make_engine(url)
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
        triggers = conn.execute(text("SELECT name FROM sqlite_master WHERE type = 'trigger'"))
        trigger_names = {row[0] for row in triggers}
    assert diff == []
    assert set(inspect(engine).get_table_names()) == SPEC_TABLES | {"alembic_version"}
    assert len(trigger_names) == 2 * len(IMMUTABLE_TABLES)
    engine.dispose()


def test_migration_downgrades_cleanly(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'down.db'}"
    cfg = _alembic_config(url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    engine = make_engine(url)
    assert set(inspect(engine).get_table_names()) == {"alembic_version"}
    engine.dispose()


def test_offline_postgres_sql_has_pgvector_and_triggers() -> None:
    buffer = io.StringIO()
    command.upgrade(
        _alembic_config("postgresql+psycopg://u:p@localhost/x", buffer), "head", sql=True
    )
    sql = buffer.getvalue()
    assert "CREATE EXTENSION IF NOT EXISTS vector" in sql
    assert "JSONB" in sql
    for table in IMMUTABLE_TABLES:
        assert f"CREATE TRIGGER {table}_immutable" in sql
    for table in SPEC_TABLES:
        assert f"CREATE TABLE {table} " in sql
