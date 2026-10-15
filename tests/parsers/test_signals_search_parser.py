"""Signals parser on search pages and topic pages (``collectors/signals_search.py``)."""

from datetime import UTC, datetime
from typing import Any

from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.models import RawSnapshot
from icp_threat_intel.parsers.signals_feed import SignalsFeedParser
from tests.collectors import _signals_feed_fixtures as fx

T0 = datetime(2026, 10, 15, 6, 0, tzinfo=UTC)


def _snap(body: bytes, meta: dict[str, Any], status: int = 200) -> RawSnapshot:
    fields: dict[str, Any] = {
        "id": 9,
        "source_type": SourceType.SIGNALS_FEED,
        "source_name": "dfinity-forum",
        "url": "https://forum.dfinity.org/t/500.json?include_raw=true",
        "fetched_at": T0,
        "sha256": "0" * 64,
        "stored_sha256": "0" * 64,
        "body": body,
        "size_bytes": len(body),
        "http_status": status,
        "synthetic": True,
        "request_meta": {"feed": "dfinity-forum", **meta},
    }
    return RawSnapshot(**fields)


def test_search_page_gives_only_a_search_event() -> None:
    body = fx.search_body((1, 500, 1), (2, 500, 3), (3, 501, 1))
    (event,) = (
        SignalsFeedParser().parse(_snap(body, {"request": "search", "term": "phishing"})).events
    )
    assert event.kind == "signal.search_polled"
    assert (event.subject_type, event.subject_id) == ("signal_search", "dfinity-forum:phishing")
    assert event.payload["status"] == "ok"
    assert event.payload["term"] == "phishing"
    assert event.payload["hits"] == 3 and event.payload["topics"] == 2


def test_failed_search_page() -> None:
    (event,) = (
        SignalsFeedParser().parse(_snap(b"x", {"request": "search", "term": "scam"}, 429)).events
    )
    assert event.kind == "signal.search_polled" and event.payload["status"] == "error"


def test_topic_page_posts_are_parsed_like_latest_posts() -> None:
    body = fx.topic_body(
        500,
        fx.topic_post(5001, 500, 1, f"Phishing frontend calls {fx.IOC_CANISTER}"),
        fx.topic_post(5002, 500, 2, "thanks"),
    )
    events = SignalsFeedParser().parse(_snap(body, {"request": "topic", "topic_id": 500})).events
    assert [e.kind for e in events] == [
        "signal.feed_polled",
        "signal.post_observed",
        "signal.canister_reference",
    ]
    polled, post, _ = events
    assert polled.payload["request"] == "topic" and polled.payload["posts"] == 2
    assert post.subject_id == "dfinity-forum:5001"
    assert post.payload["topic_title"] == "Synthetic topic 500"
    assert post.payload["category_id"] == 14
    assert post.payload["url"] == "https://forum.dfinity.org/t/synthetic-topic-500/500/1"


def test_topic_posts_page_uses_metadata_from_the_request() -> None:
    body = fx.topic_posts_body(fx.topic_post(5025, 501, 25, "a wallet drainer"))
    meta = {
        "request": "topic_posts",
        "topic_id": 501,
        "topic_title": "Synthetic topic 501",
        "topic_slug": "synthetic-topic-501",
        "category_id": 14,
    }
    _, post = SignalsFeedParser().parse(_snap(body, meta)).events
    assert post.payload["keywords"] == ["drainer"]
    assert post.payload["topic_title"] == "Synthetic topic 501"
    assert post.payload["url"] == "https://forum.dfinity.org/t/synthetic-topic-501/501/25"


def test_same_post_from_latest_and_from_topic_shares_its_subject() -> None:
    latest = fx.body(fx.post(5001, "Phishing site", topic_id=500))
    topic = fx.topic_body(500, fx.topic_post(5001, 500, 1, "Phishing site"))
    a = SignalsFeedParser().parse(_snap(latest, {"request": "latest_posts"})).events[1]
    b = SignalsFeedParser().parse(_snap(topic, {"request": "topic"})).events[1]
    assert a.subject_id == b.subject_id == "dfinity-forum:5001"


def test_unusable_topic_body() -> None:
    (event,) = SignalsFeedParser().parse(_snap(b"[]", {"request": "topic"})).events
    assert event.kind == "signal.feed_polled" and event.payload["status"] == "unusable_body"
