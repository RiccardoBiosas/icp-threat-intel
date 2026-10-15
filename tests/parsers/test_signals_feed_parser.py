"""Signals-feed snapshots -> feed_polled, post_observed and canister_reference events."""

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from sqlalchemy import Engine, select

from icp_threat_intel.collectors.runner import collect_into
from icp_threat_intel.collectors.signals_feed import SignalsFeedCollector, signals_http
from icp_threat_intel.core.enums import IocType, SourceType
from icp_threat_intel.core.models import Event, RawSnapshot
from icp_threat_intel.core.ratelimit import HostRateLimiter
from icp_threat_intel.core.trust import default_reliability
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import EventRow, Ioc, Source
from icp_threat_intel.db.session import make_engine, make_session_factory
from icp_threat_intel.parsers.base import dedup_key
from icp_threat_intel.parsers.ingest import PARSERS, Ingestor
from icp_threat_intel.parsers.signals_feed import EXCERPT_CHARS, SignalsFeedParser
from icp_threat_intel.raw_store.store import SqlRawStore
from tests.collectors import _signals_feed_fixtures as fx

T0 = datetime(2026, 10, 15, 6, 0, tzinfo=UTC)


def _snap(body: bytes, status: int = 200) -> RawSnapshot:
    fields: dict[str, Any] = {
        "id": 11,
        "source_type": SourceType.SIGNALS_FEED,
        "source_name": "dfinity-forum",
        "url": "https://forum.dfinity.org/posts.json",
        "fetched_at": T0,
        "sha256": "0" * 64,
        "stored_sha256": "0" * 64,
        "body": body,
        "size_bytes": len(body),
        "http_status": status,
        "synthetic": True,
        "request_meta": {"feed": "dfinity-forum", "platform": "discourse", "page": 1},
    }
    return RawSnapshot(**fields)


def _kinds(events: tuple[Event, ...]) -> list[str]:
    return [e.kind for e in events]


def test_registered_for_ingest() -> None:
    assert isinstance(PARSERS[SourceType.SIGNALS_FEED], SignalsFeedParser)


def test_page_events() -> None:
    events = SignalsFeedParser().parse(_snap(fx.PAGE_1)).events
    assert _kinds(events) == [
        "signal.feed_polled",
        "signal.post_observed",  # 103: keywords + IOC canister
        "signal.canister_reference",
        "signal.post_observed",  # 102: canister mention, no keyword
        "signal.canister_reference",
    ]  # 101 has neither and yields nothing
    assert all(e.source_type is SourceType.SIGNALS_FEED for e in events)
    assert all(e.observed_at == T0 and e.payload["synthetic"] is True for e in events)


def test_feed_polled_summarises_the_page() -> None:
    polled = SignalsFeedParser().parse(_snap(fx.PAGE_1)).events[0]
    assert (polled.subject_type, polled.subject_id) == ("signal_feed", "dfinity-forum")
    assert polled.canister_id is None
    assert polled.payload == {
        "status": "ok",
        "http_status": 200,
        "feed": "dfinity-forum",
        "posts": 3,
        "matched_posts": 2,
        "newest_post_id": 103,
        "oldest_post_id": 101,
        "synthetic": True,
    }


def test_post_observed_payload() -> None:
    post = SignalsFeedParser().parse(_snap(fx.PAGE_1)).events[1]
    assert (post.subject_type, post.subject_id) == ("signal_post", "dfinity-forum:103")
    payload = post.payload
    assert payload["url"] == "https://forum.dfinity.org/t/synthetic-topic-900/900/1"
    assert payload["keywords"] == ["c2", "malicious"]
    assert payload["canister_ids"] == [fx.IOC_CANISTER]
    assert payload["author"] == "synthetic_staff" and payload["author_staff"] is True
    assert payload["created_at"] == "2026-10-15T05:00:00.000Z"
    assert payload["topic_title"] == "Synthetic topic 900"
    assert payload["excerpt"].startswith("Heads up: canister")


def test_canister_reference_is_about_the_canister() -> None:
    events = SignalsFeedParser().parse(_snap(fx.PAGE_1)).events
    ref = events[2]
    assert (ref.subject_type, ref.subject_id, ref.canister_id) == (
        "canister",
        fx.IOC_CANISTER,
        fx.IOC_CANISTER,
    )
    assert ref.payload["post_id"] == 103 and ref.payload["keywords"] == ["c2", "malicious"]
    other = events[4]
    assert other.canister_id == fx.OTHER_CANISTER and other.payload["keywords"] == []
    assert events[3].payload["ic_hosts"] == ["x.icp0.io"]


def test_keyword_only_post_is_observed() -> None:
    events = SignalsFeedParser().parse(_snap(fx.PAGE_2)).events
    assert _kinds(events) == ["signal.feed_polled", "signal.post_observed"]
    assert events[1].payload["keywords"] == ["phishing"]
    assert events[1].payload["canister_ids"] == []


def test_keywords_match_whole_words_only() -> None:
    body = fx.body(fx.post(1, "A scampi recipe and a wormhole; nothing malicious-looking? no."))
    (_, post) = SignalsFeedParser().parse(_snap(body)).events
    assert post.payload["keywords"] == ["malicious"]


def test_excerpt_is_bounded_and_whitespace_collapsed() -> None:
    body = fx.body(fx.post(1, "malware\n\n" + "x " * 1000))
    (_, post) = SignalsFeedParser().parse(_snap(body)).events
    excerpt = post.payload["excerpt"]
    assert len(excerpt) <= EXCERPT_CHARS and "\n" not in excerpt


def test_post_without_slug_links_by_topic_id() -> None:
    body = b'{"latest_posts": [{"id": 9, "topic_id": 4, "post_number": 2, "raw": "scam"}]}'
    (_, post) = SignalsFeedParser().parse(_snap(body)).events
    assert post.payload["url"] == "https://forum.dfinity.org/t/4/2"


@pytest.mark.parametrize(
    ("body", "status", "parse_status"),
    [(b"oops", 503, "error"), (b"not json", 200, "unusable_body")],
)
def test_bad_pages_still_give_a_polled_event(body: bytes, status: int, parse_status: str) -> None:
    (event,) = SignalsFeedParser().parse(_snap(body, status)).events
    assert event.kind == "signal.feed_polled"
    assert event.payload["status"] == parse_status
    assert event.payload["http_status"] == status


def test_parsing_is_deterministic() -> None:
    first = SignalsFeedParser().parse(_snap(fx.PAGE_1))
    second = SignalsFeedParser().parse(_snap(fx.PAGE_1))
    assert first == second
    assert [dedup_key(e) for e in first.events] == [dedup_key(e) for e in second.events]


@pytest.fixture
def engine() -> Iterator[Engine]:
    eng = make_engine("sqlite://")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


def _handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, content=fx.PAGE_1, headers={"content-type": "application/json"})


def test_ingest_marks_ioc_references_and_weights_events(engine: Engine) -> None:
    sessions = make_session_factory(engine)
    with sessions() as s, s.begin():
        src = Source(
            name="seed",
            source_type=SourceType.VENDOR_RSS,
            base_url="",
            reliability=60,
        )
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
    limiter = HostRateLimiter(rate_per_second=1000.0, burst=1000, sleep=lambda _s: None)
    http = signals_http(
        "test@example.invalid",
        transport=httpx.MockTransport(_handler),
        limiter=limiter,
        sleep=lambda _s: None,
    )
    store = SqlRawStore(sessions)
    collect_into(SignalsFeedCollector(http, clock=lambda: T0, synthetic=True), store, [])
    snapshots = list(store.iter_snapshots(SourceType.SIGNALS_FEED))  # one in-memory connection
    result = Ingestor(sessions).ingest(snapshots)
    assert result.events_created == 5 and result.snapshots_created == 0
    with sessions() as s:
        rows = s.execute(
            select(EventRow.canister_id, EventRow.is_ioc, EventRow.weight).where(
                EventRow.kind == "signal.canister_reference"
            )
        ).all()
    assert {(c, ioc) for c, ioc, _ in rows} == {
        (fx.IOC_CANISTER, True),
        (fx.OTHER_CANISTER, False),
    }
    assert {w for _, _, w in rows} == {default_reliability(SourceType.SIGNALS_FEED)}
