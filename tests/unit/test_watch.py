"""Watched IOC canisters and the census summary, gathered from the database."""

from collections.abc import Iterator
from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from icp_threat_intel.alerting.watch import latest_census, watched_canisters
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import Canister, EventRow
from icp_threat_intel.db.session import make_engine, make_session_factory
from icp_threat_intel.parsers.ingest import Ingestor
from icp_threat_intel.raw_store.store import SqlRawStore
from tests.collectors._cassettes import SEED_CANISTERS
from tests.parsers.conftest import collect_all

TDTQY, CJN37 = SEED_CANISTERS


@pytest.fixture
def sessions() -> Iterator[sessionmaker[Session]]:
    engine = make_engine("sqlite://")
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    with factory() as s, s.begin():
        s.add_all([Canister(id=TDTQY, is_ioc=True), Canister(id=CJN37, is_ioc=True)])
    Ingestor(factory).ingest(collect_all(SqlRawStore(factory)))
    yield factory
    engine.dispose()


def _by_id(sessions: sessionmaker[Session]) -> dict[str, object]:
    with sessions() as s:
        return {w.canister_id: w for w in watched_canisters(s)}


def test_watched_canisters_report_latest_state(sessions: sessionmaker[Session]) -> None:
    watched = _by_id(sessions)
    assert set(watched) == {TDTQY, CJN37}
    tdtqy = watched[TDTQY]
    assert tdtqy.observations == 1  # type: ignore[attr-defined]
    assert tdtqy.module_hash and len(tdtqy.controllers) == 1  # type: ignore[attr-defined]
    assert tdtqy.candid_sha256 is not None  # type: ignore[attr-defined]
    assert tdtqy.gateway == "200 url" and tdtqy.changes == ()  # type: ignore[attr-defined]
    assert watched[CJN37].gateway == "404 other"  # type: ignore[attr-defined]


def _repeat_state(sessions: sessionmaker[Session], canister: str, **payload: object) -> None:
    """Add a later read_state observation of ``canister`` with some payload fields changed."""
    with sessions() as s, s.begin():
        last = s.scalars(
            select(EventRow).where(EventRow.kind == "canister.state_observed",
                                   EventRow.canister_id == canister,
                                   EventRow.source_type == "ic_read_state")
        ).one()  # fmt: skip
        s.add(
            EventRow(
                kind=last.kind, subject_type=last.subject_type, subject_id=last.subject_id,
                canister_id=last.canister_id, observed_at=last.observed_at + timedelta(days=1),
                source_id=last.source_id, source_type=last.source_type,
                raw_snapshot_id=last.raw_snapshot_id, parser=last.parser, weight=last.weight,
                is_ioc=True, payload={**last.payload, **payload}, dedup_key=f"later-{canister}",
            )
        )  # fmt: skip


def test_unchanged_second_observation(sessions: sessionmaker[Session]) -> None:
    _repeat_state(sessions, TDTQY)
    tdtqy = _by_id(sessions)[TDTQY]
    assert tdtqy.observations == 2 and tdtqy.changes == ()  # type: ignore[attr-defined]


def test_changed_module_hash_and_controllers_are_reported(sessions: sessionmaker[Session]) -> None:
    _repeat_state(sessions, CJN37, module_hash="ab" * 32, controllers=["x", "y"])
    cjn37 = _by_id(sessions)[CJN37]
    assert cjn37.changes == ("module_hash", "controllers")  # type: ignore[attr-defined]
    assert cjn37.module_hash == "ab" * 32  # type: ignore[attr-defined]


def test_never_observed_ioc_canister(sessions: sessionmaker[Session]) -> None:
    other = "aaaaa-aaaaa-aaaaa-aaaaa-cai"
    with sessions() as s, s.begin():
        s.add(Canister(id=other, is_ioc=True))
    w = _by_id(sessions)[other]
    assert w.observations == 0 and w.last_observed is None and w.gateway == "not fetched"  # type: ignore[attr-defined]


def test_latest_census_none_then_summary(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        assert latest_census(s) is None
    with sessions() as s, s.begin():
        source_id = s.scalars(select(EventRow.source_id)).first()
        last = s.scalars(select(EventRow)).first()
        assert last is not None and source_id is not None
        s.add(
            EventRow(
                kind="census.run_completed", subject_type="census_run", subject_id="run-9",
                canister_id=None, observed_at=last.observed_at, source_id=source_id,
                source_type="dashboard_api", parser="census@1", weight=75, is_ioc=False,
                payload={"run_id": "run-9", "canisters": 2000, "added": 2000, "removed": 0,
                         "changed": 0, "ceiling_hit": True, "complete_subnets": [],
                         "incomplete_subnets": [f"s{i}" for i in range(42)]},
                dedup_key="census-run-9",
            )
        )  # fmt: skip
    with sessions() as s:
        census = latest_census(s)
    assert census is not None
    assert (
        census.run_id,
        census.canisters,
        census.complete_subnets,
        census.incomplete_subnets,
    ) == ("run-9", 2000, 0, 42)
    assert census.ceiling_hit is True and census.observed_at.tzinfo is not None
