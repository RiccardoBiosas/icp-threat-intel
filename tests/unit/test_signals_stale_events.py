"""Re-parsing with stricter rules hides events an older parse emitted for the same snapshot."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from icp_threat_intel.alerting.blocklisted import blocklisted_canisters
from icp_threat_intel.alerting.signals import matched_signals
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.models import RawFetch
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import EventRow, Source
from icp_threat_intel.db.session import make_engine, make_session_factory
from icp_threat_intel.raw_store.store import SqlRawStore

NOW = datetime(2026, 10, 16, 6, 0, tzinfo=UTC)
START = NOW - timedelta(hours=24)
CANISTER = "tdtqy-oyaaa-aaaae-af2dq-cai"


@pytest.fixture
def session() -> Iterator[Session]:
    engine = make_engine("sqlite://")
    Base.metadata.create_all(engine)
    sessions = make_session_factory(engine)
    store = SqlRawStore(sessions)
    for i in (1, 2):  # two stored responses
        store.save(
            RawFetch(
                source_type=SourceType.SIGNALS_FEED,
                source_name="hackernews",
                url=f"https://hn.algolia.com/api/v1/search_by_date?page={i}",
                fetched_at=NOW,
                body=f"[{i}]".encode(),
                http_status=200,
            )
        )
    with sessions() as s:
        yield s
    engine.dispose()


def _event(
    s: Session, n: int, snapshot: int, parser: str, kind: str, subject: str, **payload: object
) -> None:
    src = s.query(Source).filter_by(name="hackernews").one()
    canister = CANISTER if kind == "signal.canister_listed" else None
    s.add(
        EventRow(
            kind=kind,
            subject_type="canister" if canister else "signal_post",
            subject_id=subject,
            canister_id=canister,
            observed_at=NOW - timedelta(minutes=10),
            source_id=src.id,
            source_type=SourceType.SIGNALS_FEED,
            raw_snapshot_id=snapshot,
            parser=parser,
            weight=40,
            payload={"feed": "hackernews", "post_id": n, "keywords": ["scam"], **payload},
            dedup_key=f"{n:064d}",
        )
    )
    s.flush()


def test_events_from_an_older_parse_of_a_reparsed_snapshot_are_ignored(session: Session) -> None:
    # snapshot 1: v2 matched post 10; v3 re-parsed it and matched nothing (only feed_polled)
    _event(session, 10, 1, "signals_feed@2", "signal.post_observed", "hackernews:10")
    _event(session, 11, 1, "signals_feed@3", "signal.feed_polled", "hackernews")
    # snapshot 2: parsed only by v2 so far; its post still counts
    _event(session, 20, 2, "signals_feed@2", "signal.post_observed", "hackernews:20")
    assert [p.post_id for p in matched_signals(session, START)] == [20]


def test_newest_parse_wins_even_if_it_also_matches(session: Session) -> None:
    _event(
        session, 10, 1, "signals_feed@2", "signal.post_observed", "hackernews:10", keywords=["scam"]
    )
    _event(
        session,
        11,
        1,
        "signals_feed@3",
        "signal.post_observed",
        "hackernews:10",
        keywords=["phishing"],
    )
    (post,) = matched_signals(session, START)
    assert post.keywords == ("phishing",)


def test_blocklisted_canisters_use_the_newest_parse(session: Session) -> None:
    _event(session, 30, 1, "signals_feed@2", "signal.canister_listed", CANISTER, hosts=["a"])
    _event(session, 31, 1, "signals_feed@3", "signal.blocklist_polled", "phishdestroy")
    assert blocklisted_canisters(session, START) == []
