"""Signals-feed collector: low-authority community sources (forums), not vendor reporting.

Written against docs/sources/signals-feed.md (Status: VERIFIED for the DFINITY forum's
Discourse ``/posts.json``). Each feed is a forum; ``DEFAULT_FEEDS`` holds the DFINITY
developer forum. Adding a forum is one ``SignalFeed`` entry plus its note section.

Per feed: ``GET <base>/posts.json`` (the latest posts across all public categories), then up
to ``pages - 1`` older pages with ``?before=<lowest post id seen>`` (at most ``MAX_PAGES``,
or ``MAX_BACKFILL_PAGES`` with ``backfill``; ``since`` stops the walk once a page reaches
older posts). The latest-posts list is generic, so the forum learns nothing about what is
tracked; canister ids, keywords and IOC terms are matched locally by the parser. Forum
search lives in ``collectors/signals_search.py`` and sends only curated generic terms.

Feed hosts are allowed only through ``signals_http`` (``SafeHttpClient(extra_hosts=...)``),
never through the global ``ALLOWLIST``. Bodies are stored verbatim (redacted) and never
rendered; links in posts are never followed. Each feed is its own ``sources`` row, so a
forum's reliability can be tuned on its own.
"""

import json
import re
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlsplit

from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.http import SafeHttpClient
from icp_threat_intel.core.models import RawFetch

MAX_PAGES = 10
MAX_BACKFILL_PAGES = 200  # one-off history walk; at 2 req/s about 100 s
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


@dataclass(frozen=True)
class SignalFeed:
    name: str  # also the ``sources`` row name
    platform: Literal["discourse"]
    base_url: str  # https origin, no path

    def __post_init__(self) -> None:
        parts = urlsplit(self.base_url)
        if parts.scheme != "https" or not parts.hostname or parts.path not in ("", "/"):
            raise ValueError(f"feed base_url must be an https origin: {self.base_url!r}")
        if not _NAME_RE.match(self.name):
            raise ValueError(f"feed name must be lowercase kebab-case: {self.name!r}")

    @property
    def host(self) -> str:
        return str(urlsplit(self.base_url).hostname)


DFINITY_FORUM = SignalFeed("dfinity-forum", "discourse", "https://forum.dfinity.org")
DEFAULT_FEEDS: tuple[SignalFeed, ...] = (DFINITY_FORUM,)


def feed_hosts(feeds: Sequence[SignalFeed]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(f.host for f in feeds))


def signals_http(
    contact: str, feeds: Sequence[SignalFeed] = DEFAULT_FEEDS, **kwargs: Any
) -> SafeHttpClient:
    """A shared-client instance allowed to reach exactly the feeds' hosts."""
    return SafeHttpClient(contact, extra_hosts=feed_hosts(feeds), **kwargs)


def latest_posts_url(feed: SignalFeed, before: int | None = None) -> str:
    url = f"{feed.base_url.rstrip('/')}/posts.json"
    return url if before is None else f"{url}?before={before}"


@dataclass(frozen=True)
class ForumPost:
    post_id: int
    topic_id: int | None
    post_number: int | None
    topic_slug: str | None
    topic_title: str | None
    created_at: str | None
    username: str | None
    staff: bool
    category_id: int | None
    raw: str
    url: str | None = None  # set when the source has its own permalink (Hacker News)


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _post(item: dict[str, Any], topic: dict[str, Any] | None = None) -> ForumPost | None:
    """One post object; ``topic`` fills the fields topic JSON keeps at its top level."""
    post_id = _int(item.get("id"))
    if post_id is None:
        return None
    raw = item.get("raw")
    topic = topic or {}
    return ForumPost(
        post_id=post_id,
        topic_id=_int(item.get("topic_id")),
        post_number=_int(item.get("post_number")),
        topic_slug=_str(item.get("topic_slug")) or _str(topic.get("topic_slug")),
        topic_title=_str(item.get("topic_title")) or _str(topic.get("topic_title")),
        created_at=_str(item.get("created_at")),
        username=_str(item.get("username")),
        staff=any(item.get(k) is True for k in ("staff", "admin", "moderator")),
        category_id=_int(item.get("category_id")) or _int(topic.get("category_id")),
        raw=raw if isinstance(raw, str) else "",
    )


def extract_posts(body: bytes) -> list[ForumPost] | None:
    """Posts of a Discourse ``/posts.json`` body, or ``None`` if the body is unusable."""
    data = _json(body)
    items = data.get("latest_posts") if data else None
    if not isinstance(items, list):
        return None
    posts = (_post(i) for i in items if isinstance(i, dict))
    return [p for p in posts if p is not None]


def topic_meta(body: bytes) -> dict[str, Any] | None:
    """Title, slug and category of a ``/t/{id}.json`` body (keys as in ``request_meta``)."""
    data = _json(body)
    if data is None:
        return None
    return {
        "topic_title": _str(data.get("title")),
        "topic_slug": _str(data.get("slug")),
        "category_id": _int(data.get("category_id")),
    }


def extract_topic_posts(body: bytes, topic: dict[str, Any] | None = None) -> list[ForumPost] | None:
    """Posts in ``post_stream.posts`` of a topic or topic-posts body (with ``include_raw``)."""
    data = _json(body)
    stream = data.get("post_stream") if data else None
    items = stream.get("posts") if isinstance(stream, dict) else None
    if data is None or not isinstance(items, list):
        return None
    meta = {**(topic_meta(body) or {}), **{k: v for k, v in (topic or {}).items() if v}}
    posts = (_post(i, meta) for i in items if isinstance(i, dict))
    return [p for p in posts if p is not None]


def topic_stream(body: bytes) -> list[int]:
    """Every post id of a topic, in order (``post_stream.stream``)."""
    data = _json(body)
    stream = data.get("post_stream") if data else None
    ids = stream.get("stream") if isinstance(stream, dict) else None
    return [i for i in ids if _int(i) is not None] if isinstance(ids, list) else []


def _json(body: bytes) -> dict[str, Any] | None:
    try:
        data = json.loads(body)
    except (UnicodeDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _created(post: ForumPost) -> datetime | None:
    try:
        return datetime.fromisoformat(str(post.created_at).replace("Z", "+00:00"))
    except ValueError:
        return None


def _now() -> datetime:
    return datetime.now(UTC)


class SignalsFeedCollector:
    """Collector for ``SourceType.SIGNALS_FEED`` (read-only GETs). Targets are feed names."""

    name = "signals_feed"
    source_type = SourceType.SIGNALS_FEED

    def __init__(
        self,
        http: SafeHttpClient,
        *,
        feeds: Sequence[SignalFeed] = DEFAULT_FEEDS,
        pages: int = 1,
        backfill: bool = False,
        since: datetime | None = None,
        clock: Callable[[], datetime] = _now,
        synthetic: bool = False,
    ) -> None:
        limit = MAX_BACKFILL_PAGES if backfill else MAX_PAGES
        if not 1 <= pages <= limit:
            hint = "" if backfill else f" (up to {MAX_BACKFILL_PAGES} with --backfill)"
            raise ValueError(f"pages must be 1-{limit}{hint}")
        self._since = since
        self._http = http
        self._feeds = {f.name: f for f in feeds}
        self._pages = pages
        self._clock = clock
        self._synthetic = synthetic

    def collect(self, targets: Sequence[str]) -> Iterator[RawFetch]:
        """Poll each named feed (all feeds when ``targets`` is empty)."""
        unknown = [t for t in targets if t not in self._feeds]
        if unknown:
            raise ValueError(f"unknown signals feed(s): {unknown}")
        for name in targets or list(self._feeds):
            yield from self._walk(self._feeds[name])

    def _walk(self, feed: SignalFeed) -> Iterator[RawFetch]:
        before: int | None = None
        for page in range(1, self._pages + 1):
            fetch = self._get(feed, page, before)
            yield fetch
            posts = extract_posts(fetch.body) if fetch.http_status == 200 else None
            if not posts:
                return
            oldest = min(posts, key=lambda p: p.post_id)
            created = _created(oldest)
            if self._since is not None and created is not None and created < self._since:
                return  # this page already reaches back past ``since``
            before = oldest.post_id

    def _get(self, feed: SignalFeed, page: int, before: int | None) -> RawFetch:
        url = latest_posts_url(feed, before)
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
                "request": "latest_posts",
                "page": page,
                "before": before,
                "redirects": list(response.redirects),
            },
        )
