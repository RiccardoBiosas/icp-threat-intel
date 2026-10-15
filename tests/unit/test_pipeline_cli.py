"""``parse``, ``enrich`` and ``score`` over a database filled from the cassettes (no network)."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker
from typer.testing import CliRunner

from icp_threat_intel.cli.app import app
from icp_threat_intel.core.enums import DetectionStatus, IocType, SourceType
from icp_threat_intel.core.trust import default_reliability
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import CanisterSnapshot, DetectionRow, EventRow, Ioc, Source
from icp_threat_intel.db.session import make_engine, make_session_factory
from icp_threat_intel.enrichment.refresh import refresh_ioc_flags
from icp_threat_intel.raw_store.store import SqlRawStore
from icp_threat_intel.verification.scoring import event_from_row, score_stored_events
from tests.collectors._cassettes import SEED_CANISTERS
from tests.parsers.conftest import collect_all

TDTQY, CJN37 = SEED_CANISTERS
runner = CliRunner()


@pytest.fixture
def db(tmp_path: Path) -> Iterator[tuple[str, sessionmaker[Session]]]:
    url = f"sqlite:///{tmp_path / 'pipeline.db'}"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    sessions = make_session_factory(engine)
    collect_all(SqlRawStore(sessions))  # 14 raw snapshots from the T07-T09 cassettes
    yield url, sessions
    engine.dispose()


def _run(url: str, *args: str) -> Any:
    result = runner.invoke(app, list(args), env={"ICP_THREAT_INTEL_DATABASE_URL": url})
    assert result.exit_code == 0, result.output
    return result


def _count(sessions: sessionmaker[Session], model: type) -> int:
    with sessions() as s:
        return int(s.scalar(select(func.count()).select_from(model)) or 0)


def _add_ioc(sessions: sessionmaker[Session], value: str) -> None:
    with sessions() as s, s.begin():
        source = Source(
            name="threatfox",
            source_type=SourceType.THREATFOX,
            base_url="https://threatfox.abuse.ch",
            reliability=default_reliability(SourceType.THREATFOX),
        )
        s.add(source)
        s.flush()
        s.add(
            Ioc(ioc_type=IocType.URL, value=value, source_id=source.id, source_ref="t",
                source_url="")
        )  # fmt: skip


def test_parse_ingests_raw_snapshots_and_is_idempotent(
    db: tuple[str, sessionmaker[Session]],
) -> None:
    url, sessions = db
    first = _run(url, "parse")
    assert "14 snapshot(s): 14 new event(s), 4 new canister snapshot(s)" in first.output
    assert _count(sessions, EventRow) == 14 and _count(sessions, CanisterSnapshot) == 4
    again = _run(url, "parse")
    assert "0 new event(s), 0 new canister snapshot(s)" in again.output
    assert _count(sessions, EventRow) == 14


def test_parse_on_an_empty_store(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'empty.db'}"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    engine.dispose()
    assert "0 snapshot(s)" in _run(url, "parse").output


def test_enrich_marks_events_for_iocs_added_after_parsing(
    db: tuple[str, sessionmaker[Session]],
) -> None:
    url, sessions = db
    _run(url, "parse")
    with sessions() as s:
        assert not any(r.is_ioc for r in s.scalars(select(EventRow)))
    _add_ioc(sessions, f"https://{TDTQY}.raw.icp0.io/")
    out = _run(url, "enrich").output
    assert "enrich: 7 event(s) marked IOC, 0 unmarked" in out
    with sessions() as s:
        flagged = {r.canister_id for r in s.scalars(select(EventRow)) if r.is_ioc}
    assert flagged == {TDTQY}
    assert "0 event(s) marked IOC, 0 unmarked" in _run(url, "enrich").output


def test_refresh_unmarks_events_whose_ioc_was_removed(
    db: tuple[str, sessionmaker[Session]],
) -> None:
    url, sessions = db
    _add_ioc(sessions, CJN37)
    _run(url, "parse")
    with sessions() as s, s.begin():
        for ioc in s.scalars(select(Ioc)):
            s.delete(ioc)
    with sessions() as s, s.begin():
        marked, unmarked = refresh_ioc_flags(s)
    assert (marked, unmarked) == (0, 7)


def test_score_saves_candidates_once(db: tuple[str, sessionmaker[Session]]) -> None:
    url, sessions = db
    _run(url, "parse")
    out = _run(url, "score").output
    assert "1 new candidate detection(s)" in out
    assert f"new #1 H1  {TDTQY}" in out
    with sessions() as s:
        (row,) = s.scalars(select(DetectionRow)).all()
    assert row.status is DetectionStatus.CANDIDATE and row.rule_id == "H1"
    assert {r["source_type"] for r in row.evidence_refs} == {"ic_read_state", "raw_gateway"}
    again = _run(url, "score").output
    assert "0 new candidate detection(s), 0 updated with new evidence" in again
    assert _count(sessions, DetectionRow) == 1


def test_rescoring_after_a_new_observation_updates_instead_of_duplicating(
    db: tuple[str, sessionmaker[Session]],
) -> None:
    url, sessions = db
    _run(url, "parse")
    _run(url, "score")
    with sessions() as s, s.begin():  # a later inspection: one more Candid observation
        latest = s.scalars(
            select(EventRow).where(EventRow.kind == "canister.candid_observed",
                                   EventRow.canister_id == TDTQY)
        ).one()  # fmt: skip
        s.add(
            EventRow(**{c: getattr(latest, c) for c in (
                "kind", "subject_type", "subject_id", "canister_id", "observed_at", "source_id",
                "source_type", "raw_snapshot_id", "parser", "weight", "is_ioc", "payload")},
                dedup_key="later-observation")
        )  # fmt: skip
    out = _run(url, "score").output
    assert "0 new candidate detection(s), 1 updated with new evidence" in out
    assert f"updated #1 H1  {TDTQY}" in out
    assert _count(sessions, DetectionRow) == 1


def test_score_with_no_events(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'none.db'}"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    engine.dispose()
    out = _run(url, "score").output
    assert "0 event(s), 0 detection(s), 0 new candidate detection(s)" in out


def test_event_from_row_round_trips_and_is_timezone_aware(
    db: tuple[str, sessionmaker[Session]],
) -> None:
    url, sessions = db
    _run(url, "parse")
    with sessions() as s, s.begin():
        row = s.scalars(select(EventRow).order_by(EventRow.id)).first()
        assert row is not None
        event = event_from_row(row)
        assert event.id == row.id and event.kind == row.kind and event.payload == row.payload
        assert event.observed_at.tzinfo is not None
        results = score_stored_events(s)
    assert [(d.rule_id, outcome) for d, _id, outcome in results] == [("H1", "created")]
