"""Signals search: find older threat discussions on a forum through its own search.

Written against docs/sources/signals-feed.md (Discourse ``/search.json`` and topic JSON,
checked on forum.dfinity.org 2026-10-15). Per feed:

1. ``GET /search.json?q=<term> order:latest&page=N`` for each curated term. Discourse logs
   every search, so terms come only from ``signals_keywords.SEARCH_TERMS`` and pass
   ``check_search_term`` (no identifiers, no IOC values; ``tests/guardrails``). Searches are
   spaced ``search_interval`` seconds apart to stay under anonymous search limits.
2. ``GET /t/<id>.json?include_raw=true`` once per topic with a hit (at most ``max_topics``),
   which carries the topic's first 20 posts with their Markdown text.
3. ``GET /t/<id>/posts.json?post_ids[]=...&include_raw=true`` for hit posts beyond those 20,
   with the topic's title, slug and category carried in ``request_meta``.

Every response is yielded, errors included. Search pages are kept as evidence of what was
asked; the parser takes posts from the topic responses only (search blurbs are truncated).
"""

import json
import time
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlencode

from icp_threat_intel.collectors.signals_feed import (
    DEFAULT_FEEDS,
    SignalFeed,
    _now,
    extract_topic_posts,
    topic_meta,
    topic_stream,
)
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.http import SafeHttpClient
from icp_threat_intel.core.models import RawFetch
from icp_threat_intel.parsers.signals_keywords import (
    SEARCH_TERMS,
    UnsafeSearchTerm,
    check_search_term,
)

MAX_TOPICS = 500
MAX_SEARCH_PAGES = 5
TOPIC_CHUNK = 20  # posts per topic page, and post_ids per topic-posts request
SEARCH_INTERVAL_SECONDS = 5.0


def search_url(feed: SignalFeed, term: str, page: int = 1) -> str:
    query = urlencode({"q": f"{check_search_term(term)} order:latest", "page": page})
    return f"{feed.base_url.rstrip('/')}/search.json?{query}"


def topic_url(feed: SignalFeed, topic_id: int) -> str:
    return f"{feed.base_url.rstrip('/')}/t/{topic_id}.json?include_raw=true"


def topic_posts_url(feed: SignalFeed, topic_id: int, post_ids: Iterable[int]) -> str:
    query = urlencode([("post_ids[]", i) for i in post_ids] + [("include_raw", "true")])
    return f"{feed.base_url.rstrip('/')}/t/{topic_id}/posts.json?{query}"


@dataclass(frozen=True)
class SearchHit:
    post_id: int
    topic_id: int
    post_number: int | None


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def extract_search_hits(body: bytes) -> list[SearchHit] | None:
    """Hits of a ``/search.json`` body, or ``None`` if the body is unusable."""
    try:
        data = json.loads(body)
    except (UnicodeDecodeError, ValueError):
        return None
    items = data.get("posts") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return None
    hits = []
    for item in items:
        if not isinstance(item, dict):
            continue
        post_id, topic_id = _int(item.get("id")), _int(item.get("topic_id"))
        if post_id is not None and topic_id is not None:
            hits.append(SearchHit(post_id, topic_id, _int(item.get("post_number"))))
    return hits


def _more(body: bytes) -> bool:
    try:
        grouped = json.loads(body).get("grouped_search_result") or {}
    except (UnicodeDecodeError, ValueError, AttributeError):
        return False
    return isinstance(grouped, dict) and bool(grouped.get("more_full_page_results"))


class SignalsSearchCollector:
    """Collector for ``SourceType.SIGNALS_FEED`` searches (read-only GETs). Targets: feeds."""

    name = "signals_search"
    source_type = SourceType.SIGNALS_FEED

    def __init__(
        self,
        http: SafeHttpClient,
        *,
        feeds: Sequence[SignalFeed] = DEFAULT_FEEDS,
        terms: Sequence[str] = SEARCH_TERMS,
        ioc_values: Iterable[str] = (),
        search_pages: int = 1,
        max_topics: int = 50,
        search_interval: float = SEARCH_INTERVAL_SECONDS,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] = _now,
        synthetic: bool = False,
    ) -> None:
        values = tuple(ioc_values)
        for term in terms:
            if term not in SEARCH_TERMS:
                raise UnsafeSearchTerm(f"not a curated search term: {term!r}")
            check_search_term(term, values)
        if not 1 <= search_pages <= MAX_SEARCH_PAGES:
            raise ValueError(f"search_pages must be 1-{MAX_SEARCH_PAGES}")
        if not 1 <= max_topics <= MAX_TOPICS:
            raise ValueError(f"max_topics must be 1-{MAX_TOPICS}")
        self._http = http
        self._feeds = {f.name: f for f in feeds}
        self._terms = tuple(terms)
        self._search_pages = search_pages
        self._max_topics = max_topics
        self._interval = search_interval
        self._sleep = sleep
        self._clock = clock
        self._synthetic = synthetic

    @property
    def terms(self) -> tuple[str, ...]:
        return self._terms

    def collect(self, targets: Sequence[str]) -> Iterator[RawFetch]:
        """Search each named feed (all feeds when ``targets`` is empty)."""
        unknown = [t for t in targets if t not in self._feeds]
        if unknown:
            raise ValueError(f"unknown signals feed(s): {unknown}")
        for name in targets or list(self._feeds):
            feed = self._feeds[name]
            hits: dict[int, set[int]] = {}  # topic id -> hit post ids, in discovery order
            yield from self._search(feed, hits)
            for topic_id in list(hits)[: self._max_topics]:
                yield from self._topic(feed, topic_id, hits[topic_id])

    def _search(self, feed: SignalFeed, hits: dict[int, set[int]]) -> Iterator[RawFetch]:
        first = True
        for term in self._terms:
            for page in range(1, self._search_pages + 1):
                if not first:
                    self._sleep(self._interval)
                first = False
                meta = {"request": "search", "term": term, "page": page}
                fetch = self._get(feed, search_url(feed, term, page), meta)
                yield fetch
                found = extract_search_hits(fetch.body) if fetch.http_status == 200 else None
                for hit in found or ():
                    hits.setdefault(hit.topic_id, set()).add(hit.post_id)
                if not found or not _more(fetch.body):
                    break

    def _topic(self, feed: SignalFeed, topic_id: int, wanted: set[int]) -> Iterator[RawFetch]:
        fetch = self._get(
            feed, topic_url(feed, topic_id), {"request": "topic", "topic_id": topic_id}
        )
        yield fetch
        if fetch.http_status != 200:
            return
        have = {p.post_id for p in extract_topic_posts(fetch.body) or ()}
        missing = [i for i in topic_stream(fetch.body) if i in wanted and i not in have]
        meta: dict[str, Any] = {"request": "topic_posts", "topic_id": topic_id}
        meta |= topic_meta(fetch.body) or {}
        for start in range(0, len(missing), TOPIC_CHUNK):
            chunk = missing[start : start + TOPIC_CHUNK]
            url = topic_posts_url(feed, topic_id, chunk)
            yield self._get(feed, url, {**meta, "post_ids": chunk})

    def _get(self, feed: SignalFeed, url: str, meta: dict[str, Any]) -> RawFetch:
        response = self._http.get(url)
        return RawFetch(
            source_type=self.source_type,
            source_name=feed.name,
            url=url,
            fetched_at=self._clock(),
            body=response.body,
            truncated=response.truncated,
            http_status=response.status_code,
            content_type=response.headers.get("content-type"),
            headers=response.headers,
            synthetic=self._synthetic,
            request_meta={
                "feed": feed.name,
                "platform": feed.platform,
                **meta,
                "redirects": list(response.redirects),
            },
        )
