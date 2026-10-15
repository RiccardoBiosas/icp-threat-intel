"""Parse signals-feed snapshots (``collectors/signals_feed.py``) into events. No I/O.

* every page gives ``signal.feed_polled`` (subject: the feed) with a parse status and the
  post-id range, so a failed poll is evidence rather than a silent gap;
* a post that names a canister id or a threat keyword gives ``signal.post_observed``
  (subject ``<feed>:<post id>``); posts with neither give nothing;
* each canister id named in a post gives ``signal.canister_reference`` (subject: the
  canister), which IOC membership enrichment then marks.

Post text is matched as plain text (the Markdown ``raw`` field, never the HTML) and only a
short excerpt is kept in the payload; the full body stays in the raw store.
"""

import re
from typing import Any
from urllib.parse import urlsplit

from icp_threat_intel.collectors.signals_feed import ForumPost, extract_posts
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.models import Event, ParseResult, RawSnapshot
from icp_threat_intel.enrichment.ioc_join import CANISTER_ID_RE
from icp_threat_intel.parsers.base import canister_event

PARSER_NAME = "signals_feed"
EXCERPT_CHARS = 280
IC_HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)*(?:icp0\.io|ic0\.app|icp-api\.io)\b", re.IGNORECASE)
# label -> whole-word pattern; labels are what rules and the digest see
KEYWORDS: dict[str, str] = {
    "malicious": r"malicious",
    "malware": r"malware",
    "phishing": r"phishing",
    "scam": r"scam(?:s|mer|mers|med)?",
    "exploit": r"exploit(?:s|ed)?",
    "backdoor": r"backdoor(?:s|ed)?",
    "c2": r"c2|command[- ]and[- ]control",
    "exfiltration": r"exfiltrat(?:e|ed|es|ing|ion)",
    "denylist": r"deny-?list(?:s|ed)?|block-?list(?:s|ed)?",
    "takedown": r"take-?down|taken down",
    "abuse": r"abuse|abusive",
    "compromised": r"compromised?",
    "worm": r"worm",
    "drainer": r"drainers?",
    "stolen": r"stolen|stole",
    "hacked": r"hacked|hack",
}
_KEYWORD_RES = {k: re.compile(rf"\b(?:{p})\b", re.IGNORECASE) for k, p in KEYWORDS.items()}


def _keywords(text: str) -> list[str]:
    return sorted(k for k, pattern in _KEYWORD_RES.items() if pattern.search(text))


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
    version = "1"

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
        keywords = _keywords(post.raw)
        canister_ids = sorted(set(CANISTER_ID_RE.findall(post.raw)))
        if not keywords and not canister_ids:
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
            "canister_ids": canister_ids,
            "ic_hosts": sorted({h.lower() for h in IC_HOST_RE.findall(post.raw)}),
            "excerpt": _excerpt(post.raw),
        }
        subject = ("signal_post", f"{feed}:{post.post_id}")
        events = [self._event(snapshot, "signal.post_observed", subject, payload)]
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
