"""Signals parser on Hacker News search pages: hits parsed like forum posts."""

from datetime import UTC, datetime
from typing import Any

from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.models import RawSnapshot
from icp_threat_intel.parsers.signals_feed import SignalsFeedParser
from tests.collectors import _hn_fixtures as fx

T0 = datetime(2026, 10, 16, 6, 0, tzinfo=UTC)
META = {
    "feed": "hackernews",
    "platform": "hn_algolia",
    "request": "hn_search",
    "query": "internet computer",
    "page": 0,
}


def _snap(body: bytes, status: int = 200) -> RawSnapshot:
    fields: dict[str, Any] = {
        "id": 21,
        "source_type": SourceType.SIGNALS_FEED,
        "source_name": "hackernews",
        "url": "https://hn.algolia.com/api/v1/search_by_date?query=internet+computer",
        "fetched_at": T0,
        "sha256": "0" * 64,
        "stored_sha256": "0" * 64,
        "body": body,
        "size_bytes": len(body),
        "http_status": status,
        "synthetic": True,
        "request_meta": META,
    }
    return RawSnapshot(**fields)


def test_page_events() -> None:
    events = SignalsFeedParser().parse(_snap(fx.PAGE)).events
    assert [e.kind for e in events] == [
        "signal.feed_polled",
        "signal.post_observed",  # 9101: c2, dead_drop + IOC canister
        "signal.canister_reference",
        "signal.post_observed",  # 9102: "malicious" (a known precision issue)
    ]  # 9103 has neither
    polled = events[0]
    assert (polled.subject_type, polled.subject_id) == ("signal_feed", "hackernews")
    assert polled.payload["request"] == "hn_search"
    assert polled.payload["query"] == "internet computer"
    assert polled.payload["posts"] == 3 and polled.payload["matched_posts"] == 2


def test_post_payload_uses_the_hn_permalink() -> None:
    post = SignalsFeedParser().parse(_snap(fx.PAGE)).events[1]
    assert post.subject_id == "hackernews:9101"
    assert post.payload["feed"] == "hackernews"
    assert post.payload["url"] == "https://news.ycombinator.com/item?id=9101"
    assert post.payload["keywords"] == ["c2", "dead_drop"]
    assert post.payload["canister_ids"] == [fx.IOC_CANISTER]
    assert post.payload["topic_title"] == "Synthetic story 9000"
    assert "<" not in post.payload["excerpt"] and "&amp;" not in post.payload["excerpt"]


def test_canister_reference_points_to_the_hn_item() -> None:
    ref = SignalsFeedParser().parse(_snap(fx.PAGE)).events[2]
    assert ref.canister_id == fx.IOC_CANISTER
    assert ref.payload["url"] == "https://news.ycombinator.com/item?id=9101"


def test_failed_and_unusable_pages() -> None:
    (err,) = SignalsFeedParser().parse(_snap(b"x", 429)).events
    assert err.kind == "signal.feed_polled" and err.payload["status"] == "error"
    (bad,) = SignalsFeedParser().parse(_snap(b"[]")).events
    assert bad.payload["status"] == "unusable_body"


def test_parser_version_is_3() -> None:
    assert SignalsFeedParser().parser_id == "signals_feed@3"


def test_general_security_talk_without_icp_context_is_ignored() -> None:
    events = SignalsFeedParser().parse(_snap(fx.OFF_TOPIC)).events
    assert [e.kind for e in events] == ["signal.feed_polled"]
    polled = events[0]
    assert polled.payload["posts"] == 3
    assert polled.payload["matched_posts"] == 0
    assert polled.payload["out_of_context"] == 3


def test_icp_story_title_gives_context_to_its_comments() -> None:
    _, post = SignalsFeedParser().parse(_snap(fx.ICP_THREAD)).events
    assert post.payload["keywords"] == ["malicious"]  # from the comment, not the title
    assert post.payload["topic_title"] == "Internet Computer canisters used as malware C2"


def test_forum_posts_are_not_gated() -> None:
    from tests.collectors import _signals_feed_fixtures as forum

    snap = _snap(forum.PAGE_2).model_copy(
        update={
            "request_meta": {"feed": "dfinity-forum", "request": "latest_posts"},
            "source_name": "dfinity-forum",
        }
    )
    events = SignalsFeedParser().parse(snap).events
    assert [e.kind for e in events] == ["signal.feed_polled", "signal.post_observed"]
    assert "out_of_context" not in events[0].payload
