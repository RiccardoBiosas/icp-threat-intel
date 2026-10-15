"""Signals parser on blocklist snapshots: blocklist_polled and canister_listed events."""

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import Engine, select

from icp_threat_intel.core.enums import IocType, SourceType
from icp_threat_intel.core.models import RawFetch, RawSnapshot
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import EventRow, Ioc, Source
from icp_threat_intel.db.session import make_engine, make_session_factory
from icp_threat_intel.parsers.base import dedup_key
from icp_threat_intel.parsers.ingest import Ingestor
from icp_threat_intel.parsers.signals_feed import SignalsFeedParser
from icp_threat_intel.raw_store.store import SqlRawStore
from tests.collectors import _blocklist_fixtures as fx

T0 = datetime(2026, 10, 16, 6, 0, tzinfo=UTC)
URL = "https://gitlab.com/phishdestroy/destroylist/-/raw/main/list.json"
META = {"feed": "phishdestroy", "platform": "blocklist", "request": "blocklist"}


def _snap(body: bytes = fx.LIST, status: int = 200, truncated: bool = False) -> RawSnapshot:
    fields: dict[str, Any] = {
        "id": 5,
        "source_type": SourceType.SIGNALS_FEED,
        "source_name": "phishdestroy",
        "url": URL,
        "fetched_at": T0,
        "sha256": "0" * 64,
        "stored_sha256": "0" * 64,
        "body": body,
        "size_bytes": len(body),
        "truncated": truncated,
        "http_status": status,
        "synthetic": True,
        "request_meta": META,
    }
    return RawSnapshot(**fields)


def test_polled_summary() -> None:
    polled = SignalsFeedParser().parse(_snap()).events[0]
    assert polled.kind == "signal.blocklist_polled"
    assert (polled.subject_type, polled.subject_id) == ("signal_feed", "phishdestroy")
    assert polled.payload == {
        "status": "ok",
        "http_status": 200,
        "feed": "phishdestroy",
        "entries": 10,
        "ic_hosts": 7,
        "canisters": 4,
        "unmapped_ic_hosts": 2,
        "synthetic": True,
    }


def test_one_listed_event_per_canister() -> None:
    events = SignalsFeedParser().parse(_snap()).events[1:]
    assert [e.kind for e in events] == ["signal.canister_listed"] * 4
    by_id = {e.canister_id: e for e in events}
    assert set(by_id) == {fx.CAN_A, fx.CAN_B, fx.CAN_C, fx.IOC_CANISTER}
    a = by_id[fx.CAN_A]
    assert (a.subject_type, a.subject_id) == ("canister", fx.CAN_A)
    assert a.payload["hosts"] == [f"{fx.CAN_A}.icp0.io", f"{fx.CAN_A}.raw.icp0.io"]
    assert a.payload["feed"] == "phishdestroy"
    assert a.payload["list"] == "phishing_and_scam_domains"
    assert by_id[fx.CAN_C].payload["hosts"] == [fx.CAN_C.replace("-", "") + ".icp0.io"]


def test_listed_events_are_sorted_and_deterministic() -> None:
    first = SignalsFeedParser().parse(_snap())
    second = SignalsFeedParser().parse(_snap())
    assert first == second
    assert [dedup_key(e) for e in first.events] == [dedup_key(e) for e in second.events]
    ids = [e.canister_id for e in first.events[1:]]
    assert ids == sorted(ids)


@pytest.mark.parametrize(
    ("body", "status", "truncated", "parse_status"),
    [
        (b"x", 503, False, "error"),
        (b"{}", 200, False, "unusable_body"),
        (b'["a.example"', 200, True, "truncated"),
    ],
)
def test_bad_downloads(body: bytes, status: int, truncated: bool, parse_status: str) -> None:
    (event,) = SignalsFeedParser().parse(_snap(body, status, truncated)).events
    assert event.kind == "signal.blocklist_polled"
    assert event.payload["status"] == parse_status


@pytest.fixture
def engine() -> Iterator[Engine]:
    eng = make_engine("sqlite://")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


def test_ingest_marks_ioc_canisters(engine: Engine) -> None:
    sessions = make_session_factory(engine)
    with sessions() as s, s.begin():
        src = Source(name="seed", source_type=SourceType.VENDOR_RSS, base_url="", reliability=60)
        s.add(src)
        s.flush()
        s.add(
            Ioc(
                ioc_type=IocType.CANISTER_ID,
                value=fx.IOC_CANISTER,
                source_id=src.id,
                source_ref="seed",
                source_url="",
            )
        )
    store = SqlRawStore(sessions)
    store.save(
        RawFetch(
            source_type=SourceType.SIGNALS_FEED,
            source_name="phishdestroy",
            url=URL,
            fetched_at=T0,
            body=fx.LIST,
            http_status=200,
            synthetic=True,
            request_meta=META,
        )
    )
    Ingestor(sessions).ingest(list(store.iter_snapshots(SourceType.SIGNALS_FEED)))
    with sessions() as s:
        rows = s.execute(
            select(EventRow.canister_id, EventRow.is_ioc, EventRow.weight).where(
                EventRow.kind == "signal.canister_listed"
            )
        ).all()
    assert len(rows) == 4
    assert {c for c, ioc, _ in rows if ioc} == {fx.IOC_CANISTER}
    assert {w for _, _, w in rows} == {40}
