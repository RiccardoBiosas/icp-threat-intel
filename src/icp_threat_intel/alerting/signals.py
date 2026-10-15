"""Digest summary of the signals feed: recent community posts worth a look.

Low-authority context only: these posts never count as verification evidence
(``core/evidence.py``). A post is listed when it names a threat keyword, an IOC canister or
another IOC value (package, file path, systemd unit, URL; ``ioc_terms``); a bare canister
mention is common on developer forums and is left out. Posts naming an IOC come first, then
posts by forum staff, then the newest.

Titles come from the forum, so ``md_text`` turns them into inert text: no links, HTML or
table breaks in the digest. Post URLs are shown as code, not as links.
"""

import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from icp_threat_intel.core.models import Notification
from icp_threat_intel.db.models import EventRow
from icp_threat_intel.parsers.ingest import ioc_canisters

MAX_SIGNALS = 20
TITLE_CHARS = 80
_MARKUP = re.compile(r"[\[\]<>`*_]")


def md_text(value: str) -> str:
    """One line of plain text safe inside a Markdown table cell."""
    flat = " ".join(_MARKUP.sub(" ", value).split())
    return flat[:TITLE_CHARS].replace("|", "\\|")


def _code(value: str) -> str:
    """Content for an inline code span: no backticks, pipes or whitespace."""
    return re.sub(r"[`|\s]", "", value) or "-"


@dataclass(frozen=True)
class SignalPost:
    feed: str
    post_id: int
    url: str | None
    topic_title: str | None
    created_at: str | None
    author_staff: bool
    keywords: tuple[str, ...]
    canister_ids: tuple[str, ...]
    ioc_canisters: tuple[str, ...]
    ioc_terms: tuple[str, ...] = ()

    @property
    def names_ioc(self) -> bool:
        return bool(self.ioc_canisters or self.ioc_terms)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _strs(value: object) -> tuple[str, ...]:
    return tuple(v for v in value if isinstance(v, str)) if isinstance(value, list) else ()


def _post(payload: dict[str, Any], iocs: frozenset[str]) -> SignalPost:
    canisters = _strs(payload.get("canister_ids"))
    return SignalPost(
        feed=str(payload.get("feed")),
        post_id=int(payload.get("post_id", 0)),
        url=payload.get("url") if isinstance(payload.get("url"), str) else None,
        topic_title=payload.get("topic_title")
        if isinstance(payload.get("topic_title"), str)
        else None,
        created_at=payload.get("created_at")
        if isinstance(payload.get("created_at"), str)
        else None,
        author_staff=payload.get("author_staff") is True,
        keywords=_strs(payload.get("keywords")),
        canister_ids=canisters,
        ioc_canisters=tuple(c for c in canisters if c in iocs),
        ioc_terms=_strs(payload.get("ioc_terms")),
    )


def matched_signals(session: Session, since: datetime) -> list[SignalPost]:
    """Every post observed since ``since`` that names a keyword or an IOC, best first."""
    rows = session.scalars(
        select(EventRow)
        .where(EventRow.kind == "signal.post_observed", EventRow.observed_at >= since)
        .order_by(EventRow.observed_at, EventRow.id)
    )
    iocs = ioc_canisters(session)
    latest = {row.subject_id: _post(row.payload, iocs) for row in rows}  # re-polls collapse
    posts = [p for p in latest.values() if p.keywords or p.names_ioc]
    posts.sort(key=lambda p: p.created_at or "", reverse=True)
    posts.sort(key=lambda p: (not p.names_ioc, not p.author_staff))
    return posts


def recent_signals(
    session: Session, since: datetime, limit: int | None = MAX_SIGNALS
) -> list[SignalPost]:
    """The first ``limit`` of ``matched_signals`` (all of them when ``limit`` is ``None``)."""
    posts = matched_signals(session, since)
    return posts if limit is None else posts[:limit]


def left_out_note(shown: int, total: int | None) -> list[str]:
    """A line saying how many matched posts the digest leaves out, if any."""
    if total is None or total <= shown:
        return []
    return [
        "",
        f"Showing {shown} of {total} matched posts; the other {total - shown} are left out. "
        "Run `digest --limit N` or `digest --all` for more, or query the database.",
    ]


def signals_section(posts: Sequence[SignalPost], total: int | None = None) -> list[str]:
    lines = ["", "## Signals (low authority)", "",
             "Community forum posts naming a threat keyword or a known IOC. Context only: "
             "they never count as verification evidence.", "",
             "| Posted | Feed | Topic | Keywords | Indicators | Author | Post |",
             "|---|---|---|---|---|---|---|"]  # fmt: skip
    for p in posts:
        canisters = ", ".join(
            [f"**`{c}`** (IOC)" if c in p.ioc_canisters else f"`{c}`" for c in p.canister_ids]
            + [f"**`{_code(t)}`** (IOC)" for t in p.ioc_terms]
        )
        lines.append(
            f"| {md_text((p.created_at or '-')[:16])} | {p.feed} | "
            f"{md_text(p.topic_title or '-')} | "
            f"{', '.join(p.keywords) or '-'} | {canisters or '-'} | "
            f"{'staff' if p.author_staff else 'member'} | `{_code(p.url or '-')}` |"
        )
    return lines + left_out_note(len(posts), total)


def _signals_line(shown: int, total: int | None) -> str:
    if not shown and not total:
        return "Signals: none"
    if total is not None and total > shown:
        return f"Signals: {total} matched post(s), {shown} shown"
    return f"Signals: {shown} matched post(s)"


def build_signals_digest(
    posts: Sequence[SignalPost],
    *,
    period_start: datetime,
    period_end: datetime,
    total: int | None = None,
) -> Notification:
    """A digest with only the signals feed (``digest --signals-only``)."""
    title = f"icp-threat-intel signals digest {period_end.date().isoformat()}"
    lines = [
        f"# {title}",
        "",
        f"Period: {period_start.isoformat()} to {period_end.isoformat()}",
        "",
        _signals_line(len(posts), total),
    ]
    if posts:
        lines += signals_section(posts, total)
    data = {
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "signals_total": total if total is not None else len(posts),
        "signals": [p.to_dict() for p in posts],
    }
    return Notification(kind="digest", title=title, markdown="\n".join(lines) + "\n", data=data)
