"""Parse signals-feed snapshots (``collectors/signals_feed.py``) into events. No I/O.

* every page gives ``signal.feed_polled`` (subject: the feed) with a parse status and the
  post-id range, so a failed poll is evidence rather than a silent gap;
* a post that names a canister id, a threat keyword or an IOC term gives
  ``signal.post_observed`` (subject ``<feed>:<post id>``); other posts give nothing. A post
  naming an IOC term is ``is_ioc``;
* each canister id named in a post gives ``signal.canister_reference`` (subject: the
  canister), which IOC membership enrichment then marks.

Post text is matched as plain text (the Markdown ``raw`` field, never the HTML) and only a
short excerpt is kept in the payload; the full body stays in the raw store. Keywords and
IOC terms are defined in ``parsers/signals_keywords.py``. IOC terms come from the ``iocs``
table: ingest passes them in with ``with_ioc_terms``, so parsing stays a pure function of
the snapshot and that term set.
"""

import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

from icp_threat_intel.collectors.signals_feed import ForumPost, extract_posts
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.models import Event, ParseResult, RawSnapshot
from icp_threat_intel.enrichment.ioc_join import CANISTER_ID_RE
from icp_threat_intel.parsers.base import canister_event
from icp_threat_intel.parsers.signals_keywords import IocTerm, find_ioc_terms, keywords_in

PARSER_NAME = "signals_feed"
EXCERPT_CHARS = 280
IC_HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)*(?:icp0\.io|ic0\.app|icp-api\.io)\b", re.IGNORECASE)


def _excerpt(text: str) -> str:
    return " ".join(text.split())[:EXCERPT_CHARS]


def _post_url(origin: str, post: ForumPost) -> str | None:
    if post.topic_id is None:
        return None
    slug = f"{post.topic_slug}/" if post.topic_slug else ""
    number = f"/{post.post_number}" if post.post_number is not None else ""
    return f"{origin}/t/{slug}{post.topic_id}{number}"


class SignalsFeedParser:
    source_type = SourceType.SIGNALS_FEED
    version = "2"  # 2: tightened keyword list, IOC terms

    def __init__(self, ioc_terms: Iterable[IocTerm] = ()) -> None:
        self._ioc_terms = tuple(sorted(set(ioc_terms), key=lambda t: (t.ioc_type, t.term)))

    def with_ioc_terms(self, ioc_terms: Iterable[IocTerm]) -> "SignalsFeedParser":
        """A parser that also matches these IOC values (from the ``iocs`` table)."""
        return SignalsFeedParser(ioc_terms)

    @property
    def parser_id(self) -> str:
        return f"{PARSER_NAME}@{self.version}"

    def _event(
        self, snapshot: RawSnapshot, kind: str, subject: tuple[str, str], payload: dict[str, Any]
    ) -> Event:
        return Event(
            kind=kind,
            subject_type=subject[0],
            subject_id=subject[1],
            observed_at=snapshot.fetched_at,
            source_type=snapshot.source_type,
            parser=self.parser_id,
            raw_snapshot_id=snapshot.id,
            payload={**payload, "synthetic": snapshot.synthetic},
        )

    def parse(self, snapshot: RawSnapshot) -> ParseResult:
        feed = str(snapshot.request_meta.get("feed") or snapshot.source_name)
        polled: dict[str, Any] = {"http_status": snapshot.http_status, "feed": feed}
        subject = ("signal_feed", feed)
        if snapshot.http_status != 200:
            event = self._event(
                snapshot, "signal.feed_polled", subject, {**polled, "status": "error"}
            )
            return ParseResult(events=(event,))
        posts = extract_posts(snapshot.body)
        if posts is None:
            payload = {**polled, "status": "unusable_body"}
            return ParseResult(
                events=(self._event(snapshot, "signal.feed_polled", subject, payload),)
            )
        parts = urlsplit(snapshot.url)
        origin = f"{parts.scheme}://{parts.netloc}"
        post_events: list[Event] = []
        matched = 0
        for post in posts:
            found = self._post_events(snapshot, feed, origin, post)
            matched += bool(found)
            post_events.extend(found)
        ids = [p.post_id for p in posts]
        summary = {
            **polled,
            "status": "ok",
            "posts": len(posts),
            "matched_posts": matched,
            "newest_post_id": max(ids, default=None),
            "oldest_post_id": min(ids, default=None),
        }
        first = self._event(snapshot, "signal.feed_polled", subject, summary)
        return ParseResult(events=(first, *post_events))

    def _post_events(
        self, snapshot: RawSnapshot, feed: str, origin: str, post: ForumPost
    ) -> list[Event]:
        keywords = keywords_in(post.raw)
        ioc_terms = find_ioc_terms(post.raw, self._ioc_terms)
        canister_ids = sorted(set(CANISTER_ID_RE.findall(post.raw)))
        if not keywords and not canister_ids and not ioc_terms:
            return []
        url = _post_url(origin, post)
        payload: dict[str, Any] = {
            "feed": feed,
            "post_id": post.post_id,
            "topic_id": post.topic_id,
            "post_number": post.post_number,
            "topic_title": post.topic_title,
            "url": url,
            "created_at": post.created_at,
            "author": post.username,
            "author_staff": post.staff,
            "category_id": post.category_id,
            "keywords": keywords,
            "ioc_terms": ioc_terms,
            "canister_ids": canister_ids,
            "ic_hosts": sorted({h.lower() for h in IC_HOST_RE.findall(post.raw)}),
            "excerpt": _excerpt(post.raw),
        }
        subject = ("signal_post", f"{feed}:{post.post_id}")
        post_event = self._event(snapshot, "signal.post_observed", subject, payload)
        if ioc_terms:
            post_event = post_event.model_copy(update={"is_ioc": True})
        events = [post_event]
        reference = {
            k: payload[k]
            for k in ("feed", "post_id", "url", "created_at", "author_staff", "keywords")
        }
        for canister_id in canister_ids:
            events.append(
                canister_event(
                    snapshot, self.parser_id, "signal.canister_reference", canister_id, reference
                )
            )
        return events
