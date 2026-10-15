"""Hacker News signals (Algolia search): curated ICP queries, newest first, paged."""

from datetime import UTC, datetime

import httpx
import pytest

from icp_threat_intel.collectors.signals_hn import (
    HN_HOST,
    MAX_HN_PAGES,
    HackerNewsCollector,
    extract_hn_posts,
    hn_http,
    hn_item_url,
    hn_search_url,
    html_to_text,
)
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.http import ALLOWLIST, HostNotAllowed, SafeHttpClient
from icp_threat_intel.core.interfaces import Collector
from icp_threat_intel.core.ratelimit import HostRateLimiter
from icp_threat_intel.parsers.signals_keywords import HN_QUERIES, UnsafeSearchTerm
from tests.collectors import _hn_fixtures as fx

T0 = datetime(2026, 10, 16, 6, 0, tzinfo=UTC)


class Algolia:
    def __init__(self, pages: int = 1) -> None:
        self.pages = pages
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        page = int(request.url.params.get("page", "0"))
        if page >= self.pages:
            content = fx.EMPTY
        elif self.pages == 1:
            content = fx.PAGE
        else:
            hit = fx.story(9200 + page, "Internet Computer phishing")
            content = fx.body(hit, page=page, nb_pages=self.pages)
        return httpx.Response(200, content=content, headers={"content-type": "application/json"})


def _collector(api: Algolia, **kw: object) -> HackerNewsCollector:
    limiter = HostRateLimiter(rate_per_second=1000.0, burst=1000, sleep=lambda _s: None)
    http = hn_http(
        "test@example.invalid",
        transport=httpx.MockTransport(api),
        limiter=limiter,
        sleep=lambda _s: None,
    )
    kw.setdefault("queries", ("internet computer",))
    return HackerNewsCollector(http, clock=lambda: T0, synthetic=True, **kw)  # type: ignore[arg-type]


def test_protocol_and_host() -> None:
    collector = _collector(Algolia())
    assert isinstance(collector, Collector)
    assert collector.source_type is SourceType.SIGNALS_FEED
    assert HN_HOST == "hn.algolia.com"
    assert not any("algolia" in h for h in ALLOWLIST)


def test_plain_client_refuses_algolia() -> None:
    limiter = HostRateLimiter(rate_per_second=1000.0, burst=1000, sleep=lambda _s: None)
    plain = SafeHttpClient(
        "t@example.invalid",
        transport=httpx.MockTransport(Algolia()),
        limiter=limiter,
        sleep=lambda _s: None,
    )
    with pytest.raises(HostNotAllowed):
        list(HackerNewsCollector(plain, queries=("dfinity",), clock=lambda: T0).collect([]))


def test_urls() -> None:
    assert hn_search_url("internet computer") == (
        "https://hn.algolia.com/api/v1/search_by_date?query=internet+computer"
        "&tags=%28story%2Ccomment%29&hitsPerPage=100&page=0"
    )
    assert hn_search_url("dfinity", page=2, since=1700000000).endswith(
        "&page=2&numericFilters=created_at_i%3E1700000000"
    )
    assert hn_item_url(123) == "https://news.ycombinator.com/item?id=123"


def test_queries_are_curated_and_safe() -> None:
    icp_context = ("computer", "dfinity", "canister", "teampcp")
    assert HN_QUERIES and all(any(c in q for c in icp_context) for q in HN_QUERIES)
    with pytest.raises(UnsafeSearchTerm, match="not a curated"):
        _collector(Algolia(), queries=("phishing",))
    with pytest.raises(UnsafeSearchTerm):
        HackerNewsCollector(
            _collector(Algolia())._http, queries=("dfinity",), ioc_values=["dfinity"]
        )


def test_one_page_by_default() -> None:
    api = Algolia(pages=3)
    fetches = list(_collector(api).collect([]))
    assert len(fetches) == 1
    f = fetches[0]
    assert f.source_name == "hackernews"
    assert f.request_meta == {
        "feed": "hackernews",
        "platform": "hn_algolia",
        "request": "hn_search",
        "query": "internet computer",
        "page": 0,
        "since": None,
        "redirects": [],
    }


def test_pages_until_nb_pages() -> None:
    api = Algolia(pages=2)
    fetches = list(_collector(api, pages=5).collect([]))
    assert [f.request_meta["page"] for f in fetches] == [0, 1]


def test_since_is_sent_as_numeric_filter() -> None:
    api = Algolia()
    since = datetime(2026, 3, 1, tzinfo=UTC)
    list(_collector(api, since=since).collect([]))
    assert api.requests[0].url.params["numericFilters"] == f"created_at_i>{int(since.timestamp())}"


@pytest.mark.parametrize("pages", [0, MAX_HN_PAGES + 1])
def test_page_bounds(pages: int) -> None:
    with pytest.raises(ValueError):
        _collector(Algolia(), pages=pages)


def test_targets_must_be_hackernews() -> None:
    with pytest.raises(ValueError, match="unknown"):
        list(_collector(Algolia()).collect(["reddit"]))
    assert len(list(_collector(Algolia()).collect(["hackernews"]))) == 1


def test_html_to_text() -> None:
    html = '<p>a <a href="https:&#x2F;&#x2F;x.example">link</a> &amp; <i>b</i></p><p>c&#x27;s</p>'
    assert html_to_text(html) == "a link & b c's"
    assert html_to_text("<script>alert(1)</script>x") == "alert(1) x"


def test_extract_hn_posts() -> None:
    posts = extract_hn_posts(fx.PAGE)
    assert posts is not None
    c, s1, s2 = posts
    assert (c.post_id, c.topic_id, c.post_number) == (9101, 9000, None)
    assert c.topic_title == "Synthetic story 9000" and c.username == "synthetic_user"
    assert fx.IOC_CANISTER in c.raw and "<a" not in c.raw and "&amp;" not in c.raw
    assert c.url == "https://news.ycombinator.com/item?id=9101"
    assert s1.topic_title == "Show HN: my Internet Computer dapp"
    assert s1.raw.startswith("Show HN: my Internet Computer dapp") and "demo" in s1.raw
    assert s2.raw == "Internet Computer tooling update"
    assert c.staff is False and c.created_at == "2026-04-16T00:40:00Z"


def test_extract_hn_posts_is_defensive() -> None:
    assert extract_hn_posts(b"x") is None
    assert extract_hn_posts(b'{"hits": 3}') is None
    assert extract_hn_posts(b'{"hits": [{"objectID": "nope"}, 5, {"objectID": "7"}]}') is not None
