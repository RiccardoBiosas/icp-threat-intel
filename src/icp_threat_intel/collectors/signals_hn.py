"""Hacker News signals: ICP-related stories and comments through the Algolia HN Search API.

Written against docs/sources/hackernews.md (Status: VERIFIED for ``search_by_date`` and its
hit fields, checked 2026-10-16). Per curated query:
``GET https://hn.algolia.com/api/v1/search_by_date?query=<q>&tags=(story,comment)&hitsPerPage=100``
newest first, then later pages up to ``pages`` while Algolia reports more (``nbPages``).
``since`` is sent as ``numericFilters=created_at_i>..``.

* **Curated queries only.** Algolia logs queries, so only ``HN_QUERIES`` (ICP context such
  as "internet computer", "dfinity", campaign names) are sent, each passing
  ``check_search_term``; threat keywords are matched locally by the parser, never sent.
* **Data only.** Story and comment text arrives as HTML; ``html_to_text`` extracts the text
  with the standard-library parser (nothing is rendered or fetched) and links are never
  followed. Each hit becomes a ``ForumPost`` with its news.ycombinator.com permalink.
* **Exact words.** ``hn_query_text`` quotes ``HN_EXACT_PHRASES`` (``internet computer``)
  as a phrase and every other word on its own, which turns off Algolia's typo tolerance
  (unquoted, ``dfinity`` matched "infinity"-like words: 1,498 hits, none containing it).
* **ICP context.** Hacker News is not about ICP, so the parser keeps an item only when its
  text or story title clearly refers to ICP (``signals_keywords.has_icp_context``);
  general security words alone never make a signal.
* **Low authority.** Source type ``signals_feed``, ``sources`` row ``hackernews``.
* No credentials. The host is allowed only through ``hn_http`` (``extra_hosts``).
"""

import html
import json
import time
from collections.abc import Callable, Iterable, Iterator, Sequence
from datetime import datetime
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlencode

from icp_threat_intel.collectors.signals_feed import ForumPost, _now
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.http import SafeHttpClient
from icp_threat_intel.core.models import RawFetch
from icp_threat_intel.parsers.signals_keywords import (
    HN_EXACT_PHRASES,
    HN_QUERIES,
    UnsafeSearchTerm,
    check_search_term,
)

FEED_NAME = "hackernews"
HN_HOST = "hn.algolia.com"
HITS_PER_PAGE = 100
MAX_HN_PAGES = 10  # Algolia returns at most 1,000 hits per query
QUERY_INTERVAL_SECONDS = 1.0


def hn_http(contact: str, **kwargs: Any) -> SafeHttpClient:
    """A shared-client instance allowed to reach exactly the HN Search API host."""
    return SafeHttpClient(contact, extra_hosts=(HN_HOST,), **kwargs)


def hn_query_text(query: str) -> str:
    """The query as sent: exact phrases quoted whole, every other word quoted on its own.

    Quotes turn off Algolia's typo tolerance: unquoted, ``dfinity`` returned 1,498 hits and
    none of the first 50 contained the word; quoted, 189, all containing it (2026-10-16).
    """
    term = check_search_term(query)
    if term in HN_EXACT_PHRASES:
        return f'"{term}"'
    return " ".join(f'"{word}"' for word in term.split())


def hn_search_url(query: str, page: int = 0, since: int | None = None) -> str:
    params: list[tuple[str, str | int]] = [
        ("query", hn_query_text(query)),
        ("tags", "(story,comment)"),
        ("hitsPerPage", HITS_PER_PAGE),
        ("page", page),
    ]
    if since is not None:
        params.append(("numericFilters", f"created_at_i>{since}"))
    return f"https://{HN_HOST}/api/v1/search_by_date?{urlencode(params)}"


def hn_item_url(object_id: int) -> str:
    return f"https://news.ycombinator.com/item?id={object_id}"


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def html_to_text(value: str) -> str:
    """Plain text of an HN HTML fragment: tags dropped, entities decoded, whitespace collapsed."""
    extractor = _TextExtractor()
    extractor.feed(value.replace("<p>", " <p>"))
    extractor.close()
    return " ".join(html.unescape(" ".join(extractor.parts)).split())


def _int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _hit_post(hit: dict[str, Any]) -> ForumPost | None:
    object_id = _int(hit.get("objectID"))
    if object_id is None:
        return None
    title = _str(hit.get("title"))
    body = _str(hit.get("comment_text")) or _str(hit.get("story_text")) or ""
    text = " ".join(t for t in (title, html_to_text(body)) if t)
    return ForumPost(
        post_id=object_id,
        topic_id=_int(hit.get("story_id")),
        post_number=None,
        topic_slug=None,
        topic_title=title or _str(hit.get("story_title")),
        created_at=_str(hit.get("created_at")),
        username=_str(hit.get("author")),
        staff=False,
        category_id=None,
        raw=text,
        url=hn_item_url(object_id),
    )


def _json(body: bytes) -> dict[str, Any] | None:
    try:
        data = json.loads(body)
    except (UnicodeDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def extract_hn_posts(body: bytes) -> list[ForumPost] | None:
    """Posts of a ``search_by_date`` body, or ``None`` if the body is unusable."""
    data = _json(body)
    hits = data.get("hits") if data else None
    if not isinstance(hits, list):
        return None
    posts = (_hit_post(h) for h in hits if isinstance(h, dict))
    return [p for p in posts if p is not None]


def _has_more(body: bytes, page: int) -> bool:
    data = _json(body) or {}
    nb_pages = _int(data.get("nbPages"))
    return nb_pages is not None and page + 1 < nb_pages


class HackerNewsCollector:
    """Collector for ``SourceType.SIGNALS_FEED`` Hacker News searches. Target: ``hackernews``."""

    name = "signals_hn"
    source_type = SourceType.SIGNALS_FEED

    def __init__(
        self,
        http: SafeHttpClient,
        *,
        queries: Sequence[str] = HN_QUERIES,
        ioc_values: Iterable[str] = (),
        pages: int = 1,
        since: datetime | None = None,
        query_interval: float = QUERY_INTERVAL_SECONDS,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] = _now,
        synthetic: bool = False,
    ) -> None:
        values = tuple(ioc_values)
        for query in queries:
            if query not in HN_QUERIES:
                raise UnsafeSearchTerm(f"not a curated Hacker News query: {query!r}")
            check_search_term(query, values)
        if not 1 <= pages <= MAX_HN_PAGES:
            raise ValueError(f"pages must be 1-{MAX_HN_PAGES}")
        self._http = http
        self._queries = tuple(queries)
        self._pages = pages
        self._since = int(since.timestamp()) if since is not None else None
        self._interval = query_interval
        self._sleep = sleep
        self._clock = clock
        self._synthetic = synthetic

    @property
    def queries(self) -> tuple[str, ...]:
        return self._queries

    def collect(self, targets: Sequence[str]) -> Iterator[RawFetch]:
        unknown = [t for t in targets if t != FEED_NAME]
        if unknown:
            raise ValueError(f"unknown Hacker News feed(s): {unknown}")
        first = True
        for query in self._queries:
            for page in range(self._pages):
                if not first:
                    self._sleep(self._interval)
                first = False
                fetch = self._get(query, page)
                yield fetch
                if fetch.http_status != 200 or not _has_more(fetch.body, page):
                    break

    def _get(self, query: str, page: int) -> RawFetch:
        url = hn_search_url(query, page, self._since)
        response = self._http.get(url)
        return RawFetch(
            source_type=self.source_type,
            source_name=FEED_NAME,
            url=url,
            fetched_at=self._clock(),
            body=response.body,
            truncated=response.truncated,
            http_status=response.status_code,
            content_type=response.headers.get("content-type"),
            headers=response.headers,
            synthetic=self._synthetic,
            request_meta={
                "feed": FEED_NAME,
                "platform": "hn_algolia",
                "request": "hn_search",
                "query": query,
                "page": page,
                "since": self._since,
                "redirects": list(response.redirects),
            },
        )
