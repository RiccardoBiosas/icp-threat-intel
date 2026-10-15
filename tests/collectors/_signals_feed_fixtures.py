"""Synthetic Discourse ``/posts.json`` bodies for the signals-feed collector and parser.

Shaped like the real endpoint (``docs/sources/signals-feed.md``) but every post, user and
topic is invented. The only real identifiers are public SPEC §3 canister ids.
"""

import json
from typing import Any

IOC_CANISTER = "tdtqy-oyaaa-aaaae-af2dq-cai"  # SPEC §3 seed IOC
OTHER_CANISTER = "rkp4c-7iaaa-aaaaa-aaaca-cai"  # Cycles Minting Canister, not an IOC


def post(
    post_id: int,
    raw: str,
    *,
    topic_id: int = 900,
    post_number: int = 1,
    staff: bool = False,
    username: str = "synthetic_user",
) -> dict[str, Any]:
    return {
        "id": post_id,
        "topic_id": topic_id,
        "topic_slug": f"synthetic-topic-{topic_id}",
        "topic_title": f"Synthetic topic {topic_id}",
        "post_number": post_number,
        "created_at": "2026-10-15T05:00:00.000Z",
        "username": username,
        "staff": staff,
        "admin": False,
        "moderator": False,
        "category_id": 14,
        "raw": raw,
        "cooked": f"<p>{raw}</p>",
    }


def body(*posts: dict[str, Any]) -> bytes:
    return json.dumps({"latest_posts": list(posts)}).encode()


PAGE_1 = body(
    post(
        103,
        f"Heads up: canister {IOC_CANISTER} looks malicious, it serves a C2 link.",
        staff=True,
        username="synthetic_staff",
    ),
    post(102, f"How do I top up {OTHER_CANISTER}? My dapp is on x.icp0.io", topic_id=901),
    post(101, "Motoko question about stable memory, nothing to see here.", topic_id=902),
)
PAGE_2 = body(post(100, "Phishing site copying the NNS frontend, beware.", topic_id=903))
EMPTY = body()


def search_body(*hits: tuple[int, int, int], more: bool = False) -> bytes:
    """``/search.json``: hits are (post_id, topic_id, post_number); blurbs are invented."""
    posts = [
        {
            "id": post_id,
            "topic_id": topic_id,
            "post_number": number,
            "created_at": "2026-04-01T10:00:00.000Z",
            "username": "synthetic_user",
            "blurb": "synthetic blurb",
        }
        for post_id, topic_id, number in hits
    ]
    topics = [{"id": t, "title": f"Synthetic topic {t}", "slug": f"synthetic-topic-{t}",
               "category_id": 14} for t in dict.fromkeys(h[1] for h in hits)]  # fmt: skip
    grouped = {"term": "synthetic", "more_full_page_results": True if more else None}
    return json.dumps({"posts": posts, "topics": topics, "grouped_search_result": grouped}).encode()


def topic_post(post_id: int, topic_id: int, number: int, raw: str) -> dict[str, Any]:
    item = post(post_id, raw, topic_id=topic_id, post_number=number)
    for key in ("topic_title", "category_id"):  # topic JSON keeps these at the top level
        item.pop(key)
    return item


def topic_body(topic_id: int, *posts: dict[str, Any], stream: tuple[int, ...] = ()) -> bytes:
    ids = stream or tuple(p["id"] for p in posts)
    return json.dumps(
        {
            "id": topic_id,
            "title": f"Synthetic topic {topic_id}",
            "slug": f"synthetic-topic-{topic_id}",
            "category_id": 14,
            "post_stream": {"posts": list(posts), "stream": list(ids)},
        }
    ).encode()


def topic_posts_body(*posts: dict[str, Any]) -> bytes:
    return json.dumps({"post_stream": {"posts": list(posts)}}).encode()
