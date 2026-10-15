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
