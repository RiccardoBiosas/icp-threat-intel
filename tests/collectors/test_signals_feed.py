"""Signals-feed collector: low-authority community forums (Discourse ``/posts.json``)."""

from collections.abc import Iterator
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import Engine, select

from icp_threat_intel.collectors.runner import collect_into
from icp_threat_intel.collectors.signals_feed import (
    DEFAULT_FEEDS,
    DFINITY_FORUM,
    MAX_PAGES,
    SignalFeed,
    SignalsFeedCollector,
    extract_posts,
    feed_hosts,
    latest_posts_url,
    signals_http,
)
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.http import ALLOWLIST, HostNotAllowed, SafeHttpClient
from icp_threat_intel.core.interfaces import Collector
from icp_threat_intel.core.ratelimit import HostRateLimiter
from icp_threat_intel.core.trust import default_reliability
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import Source
from icp_threat_intel.db.session import make_engine, make_session_factory
from icp_threat_intel.raw_store.store import SqlRawStore
from tests.collectors import _signals_feed_fixtures as fx

T0 = datetime(2026, 10, 15, 6, 0, tzinfo=UTC)
CONTACT = "test@example.invalid"


class Replay:
    """Serves page 1 for the bare URL, page 2 for ``before=101``, empty otherwise."""

    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        before = request.url.params.get("before")
        content = {None: fx.PAGE_1, "101": fx.PAGE_2}.get(before, fx.EMPTY)
        return httpx.Response(
            self.status, content=content, headers={"content-type": "application/json"}
        )


def _http(handler: Replay, feeds: tuple[SignalFeed, ...] = DEFAULT_FEEDS) -> SafeHttpClient:
    limiter = HostRateLimiter(rate_per_second=1000.0, burst=1000, sleep=lambda _s: None)
    return signals_http(
        CONTACT,
        feeds,
        transport=httpx.MockTransport(handler),
        limiter=limiter,
        sleep=lambda _s: None,
    )


def _collector(handler: Replay, *, pages: int = 1) -> SignalsFeedCollector:
    return SignalsFeedCollector(_http(handler), pages=pages, clock=lambda: T0, synthetic=True)


@pytest.fixture
def engine() -> Iterator[Engine]:
    eng = make_engine("sqlite://")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


def test_satisfies_collector_protocol() -> None:
    collector = _collector(Replay())
    assert isinstance(collector, Collector)
    assert collector.source_type is SourceType.SIGNALS_FEED


def test_dfinity_forum_is_the_default_feed() -> None:
    assert DEFAULT_FEEDS == (DFINITY_FORUM,)
    assert DFINITY_FORUM.host == "forum.dfinity.org"
    assert feed_hosts(DEFAULT_FEEDS) == ("forum.dfinity.org",)
    assert latest_posts_url(DFINITY_FORUM) == "https://forum.dfinity.org/posts.json"
    assert latest_posts_url(DFINITY_FORUM, before=7) == (
        "https://forum.dfinity.org/posts.json?before=7"
    )


def test_forum_host_is_not_in_the_global_allowlist() -> None:
    assert not any("dfinity.org" in host for host in ALLOWLIST)


def test_plain_client_refuses_the_forum() -> None:
    limiter = HostRateLimiter(rate_per_second=1000.0, burst=1000, sleep=lambda _s: None)
    plain = SafeHttpClient(
        CONTACT, transport=httpx.MockTransport(Replay()), limiter=limiter, sleep=lambda _s: None
    )
    collector = SignalsFeedCollector(plain, clock=lambda: T0)
    with pytest.raises(HostNotAllowed):
        list(collector.collect([]))


def test_feed_must_be_https_without_path() -> None:
    with pytest.raises(ValueError):
        SignalFeed("bad", "discourse", "http://forum.example.org")
    with pytest.raises(ValueError):
        SignalFeed("bad", "discourse", "https://forum.example.org/sub")
    with pytest.raises(ValueError):
        SignalFeed("Bad Name", "discourse", "https://forum.example.org")


def test_collects_one_page_by_default() -> None:
    handler = Replay()
    (fetch,) = list(_collector(handler).collect([]))
    assert fetch.source_type is SourceType.SIGNALS_FEED
    assert fetch.source_name == "dfinity-forum"
    assert fetch.url == "https://forum.dfinity.org/posts.json"
    assert fetch.http_status == 200 and fetch.synthetic and fetch.fetched_at == T0
    assert fetch.request_meta == {
        "feed": "dfinity-forum",
        "platform": "discourse",
        "request": "latest_posts",
        "page": 1,
        "before": None,
        "redirects": [],
    }
    assert [str(r.url) for r in handler.requests] == [fetch.url]


def test_pages_walk_backwards_with_before() -> None:
    handler = Replay()
    fetches = list(_collector(handler, pages=5).collect(["dfinity-forum"]))
    # page 1 (ids 101-103), page 2 (id 100), page 3 empty: stop
    assert [f.request_meta["before"] for f in fetches] == [None, 101, 100]
    assert [f.request_meta["page"] for f in fetches] == [1, 2, 3]


def test_error_page_is_kept_and_stops_paging() -> None:
    fetches = list(_collector(Replay(status=503), pages=3).collect([]))
    assert len(fetches) == 1
    assert fetches[0].http_status == 503


def test_unknown_feed_name_is_refused() -> None:
    with pytest.raises(ValueError, match="unknown signals feed"):
        list(_collector(Replay()).collect(["no-such-forum"]))


@pytest.mark.parametrize("pages", [0, MAX_PAGES + 1])
def test_page_count_is_bounded(pages: int) -> None:
    with pytest.raises(ValueError):
        _collector(Replay(), pages=pages)


def test_extract_posts_is_defensive() -> None:
    assert extract_posts(b"not json") is None
    assert extract_posts(b"[]") is None
    assert extract_posts(b'{"latest_posts": "x"}') is None
    posts = extract_posts(b'{"latest_posts": [{"id": "x"}, {"id": 5, "topic_id": 1, "raw": 3}, 7]}')
    assert posts is not None
    (only,) = posts
    assert only.post_id == 5 and only.raw == "" and only.topic_slug is None
    assert only.staff is False


def test_extract_posts_reads_fields() -> None:
    posts = extract_posts(fx.PAGE_1)
    assert posts is not None
    first = posts[0]
    assert (first.post_id, first.topic_id, first.post_number) == (103, 900, 1)
    assert first.staff is True and first.username == "synthetic_staff"
    assert first.category_id == 14 and fx.IOC_CANISTER in first.raw


def test_fetches_land_in_the_raw_store_with_signal_weight(engine: Engine) -> None:
    sessions = make_session_factory(engine)
    store = SqlRawStore(sessions)
    refs = collect_into(_collector(Replay(), pages=2), store, [])
    assert len(refs) == 2 and all(r.created for r in refs)
    with sessions() as s:
        source = s.scalar(select(Source).where(Source.name == "dfinity-forum"))
    assert source is not None
    assert source.source_type is SourceType.SIGNALS_FEED
    assert source.reliability == default_reliability(SourceType.SIGNALS_FEED)
