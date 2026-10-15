"""Signals search: curated generic terms, then the full topics behind the hits."""

from datetime import UTC, datetime

import httpx
import pytest

from icp_threat_intel.collectors.signals_feed import DFINITY_FORUM, signals_http
from icp_threat_intel.collectors.signals_search import (
    MAX_TOPICS,
    TOPIC_CHUNK,
    SignalsSearchCollector,
    extract_search_hits,
    search_url,
    topic_posts_url,
    topic_url,
)
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.http import SafeHttpClient
from icp_threat_intel.core.interfaces import Collector
from icp_threat_intel.core.ratelimit import HostRateLimiter
from tests.collectors import _signals_feed_fixtures as fx

T0 = datetime(2026, 10, 15, 6, 0, tzinfo=UTC)
TERMS = ("phishing", "drainer")


class Forum:
    """phishing: topics 500 (hit #1) and 501 (hit #25); drainer: topic 500 again."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path, params = request.url.path, request.url.params
        if path == "/search.json":
            q = params["q"]
            page = params.get("page", "1")
            if q.startswith("phishing") and page == "1":
                body = fx.search_body((5001, 500, 1), (5025, 501, 25), more=True)
            elif q.startswith("phishing") and page == "2":
                body = fx.search_body((5002, 500, 2))
            elif q.startswith("drainer") and page == "1":
                body = fx.search_body((5001, 500, 1))
            else:
                body = fx.search_body()
        elif path == "/t/500.json":
            body = fx.topic_body(
                500,
                fx.topic_post(5001, 500, 1, "Phishing site copies the NNS frontend"),
                fx.topic_post(5002, 500, 2, "Same here"),
            )
        elif path == "/t/501.json":
            first = [fx.topic_post(5100 + i, 501, i, "chatter") for i in range(1, 21)]
            body = fx.topic_body(501, *first, stream=(*range(5101, 5121), 5025))
        elif path == "/t/501/posts.json":
            body = fx.topic_posts_body(fx.topic_post(5025, 501, 25, "a wallet drainer"))
        else:
            return httpx.Response(404, content=b"{}")
        return httpx.Response(200, content=body, headers={"content-type": "application/json"})


def _http(forum: Forum) -> SafeHttpClient:
    limiter = HostRateLimiter(rate_per_second=1000.0, burst=1000, sleep=lambda _s: None)
    return signals_http(
        "test@example.invalid",
        transport=httpx.MockTransport(forum),
        limiter=limiter,
        sleep=lambda _s: None,
    )


def _collector(forum: Forum, **kw: object) -> tuple[SignalsSearchCollector, list[float]]:
    slept: list[float] = []
    collector = SignalsSearchCollector(
        _http(forum), terms=TERMS, clock=lambda: T0, synthetic=True, sleep=slept.append, **kw
    )  # type: ignore[arg-type]
    return collector, slept


def test_satisfies_collector_protocol() -> None:
    collector, _ = _collector(Forum())
    assert isinstance(collector, Collector)
    assert collector.source_type is SourceType.SIGNALS_FEED


def test_urls() -> None:
    assert search_url(DFINITY_FORUM, "phishing") == (
        "https://forum.dfinity.org/search.json?q=phishing+order%3Alatest&page=1"
    )
    assert topic_url(DFINITY_FORUM, 7) == "https://forum.dfinity.org/t/7.json?include_raw=true"
    assert topic_posts_url(DFINITY_FORUM, 7, [3, 4]) == (
        "https://forum.dfinity.org/t/7/posts.json?post_ids%5B%5D=3&post_ids%5B%5D=4"
        "&include_raw=true"
    )


def test_searches_then_fetches_each_topic_once() -> None:
    forum = Forum()
    collector, slept = _collector(forum, search_pages=2)
    fetches = list(collector.collect([]))
    requests = [f.request_meta["request"] for f in fetches]
    assert requests == ["search", "search", "search", "topic", "topic", "topic_posts"]
    assert [f.request_meta.get("term") for f in fetches[:3]] == ["phishing", "phishing", "drainer"]
    assert [f.request_meta.get("topic_id") for f in fetches[3:]] == [500, 501, 501]
    assert all(f.source_name == "dfinity-forum" for f in fetches)
    assert slept == [5.0, 5.0]  # a pause before every search after the first


def test_later_hit_posts_are_fetched_with_topic_metadata() -> None:
    fetches = list(_collector(Forum())[0].collect([]))
    extra = fetches[-1]
    assert extra.request_meta["post_ids"] == [5025]
    assert extra.request_meta["topic_title"] == "Synthetic topic 501"
    assert extra.request_meta["topic_slug"] == "synthetic-topic-501"
    assert extra.request_meta["category_id"] == 14


def test_one_search_page_by_default() -> None:
    fetches = list(_collector(Forum())[0].collect([]))
    assert [f.request_meta["request"] for f in fetches].count("search") == 2


def test_max_topics_caps_topic_fetches() -> None:
    fetches = list(_collector(Forum(), max_topics=1)[0].collect([]))
    assert [
        f.request_meta.get("topic_id") for f in fetches if f.request_meta["request"] != "search"
    ] == [500]


@pytest.mark.parametrize(
    ("key", "value"),
    [("max_topics", 0), ("max_topics", MAX_TOPICS + 1), ("search_pages", 0), ("search_pages", 6)],
)
def test_bounds(key: str, value: int) -> None:
    with pytest.raises(ValueError):
        _collector(Forum(), **{key: value})


def test_unknown_feed_refused() -> None:
    with pytest.raises(ValueError, match="unknown signals feed"):
        list(_collector(Forum())[0].collect(["nope"]))


def test_failed_search_is_kept_and_skipped() -> None:
    def failing(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, content=b"{}")

    limiter = HostRateLimiter(rate_per_second=1000.0, burst=1000, sleep=lambda _s: None)
    http = signals_http(
        "t@example.invalid",
        transport=httpx.MockTransport(failing),
        limiter=limiter,
        sleep=lambda _s: None,
    )
    collector = SignalsSearchCollector(
        http, terms=("phishing",), clock=lambda: T0, sleep=lambda _s: None
    )
    (fetch,) = list(collector.collect([]))
    assert fetch.http_status == 404


def test_extract_search_hits_is_defensive() -> None:
    assert extract_search_hits(b"nope") is None
    assert extract_search_hits(b'{"posts": 3}') is None
    hits = extract_search_hits(
        b'{"posts": [{"id": 1, "topic_id": 2, "post_number": 3}, {"id": "x"}, 4]}'
    )
    assert hits is not None and [(h.post_id, h.topic_id, h.post_number) for h in hits] == [
        (1, 2, 3)
    ]


def test_topic_chunk_size() -> None:
    assert TOPIC_CHUNK == 20
