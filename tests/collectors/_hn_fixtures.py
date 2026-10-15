"""Synthetic Hacker News (Algolia) ``search_by_date`` bodies; every hit is invented."""

import json
from typing import Any

IOC_CANISTER = "tdtqy-oyaaa-aaaae-af2dq-cai"  # SPEC §3 seed IOC


def comment(
    object_id: int, html: str, *, story_id: int = 9000, at: int = 1776300000
) -> dict[str, Any]:
    return {
        "objectID": str(object_id),
        "created_at": "2026-04-16T00:40:00Z",
        "created_at_i": at,
        "author": "synthetic_user",
        "comment_text": html,
        "story_id": story_id,
        "parent_id": story_id,
        "story_title": f"Synthetic story {story_id}",
        "story_url": "https://example.org/story",
        "_tags": ["comment", "author_synthetic_user", f"story_{story_id}"],
    }


def story(
    object_id: int, title: str, text: str | None = None, *, at: int = 1776300000
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "objectID": str(object_id),
        "created_at": "2026-04-16T00:40:00Z",
        "created_at_i": at,
        "author": "synthetic_poster",
        "title": title,
        "story_id": object_id,
        "url": "https://example.org/post",
        "_tags": ["story", "author_synthetic_poster", f"story_{object_id}"],
    }
    if text is not None:
        item["story_text"] = text
    return item


def body(*hits: dict[str, Any], page: int = 0, nb_pages: int = 1) -> bytes:
    return json.dumps(
        {
            "hits": list(hits),
            "nbHits": len(hits),
            "page": page,
            "nbPages": nb_pages,
            "hitsPerPage": 100,
        }
    ).encode()


PAGE = body(
    comment(
        9101,
        "<p>This actor uses the Internet Computer as a C2 dead drop: "
        f'<a href="https:&#x2F;&#x2F;example.org">{IOC_CANISTER}</a> &amp; more</p>',
    ),
    story(9102, "Show HN: my Internet Computer dapp", "Nothing malicious here, just a demo."),
    story(9103, "Internet Computer tooling update"),
)
EMPTY = body()
