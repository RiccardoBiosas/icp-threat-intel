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
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from icp_threat_intel.alerting.blocklisted import BlocklistedCanister, blocklisted_section
from icp_threat_intel.alerting.parses import newest_parse_only
from icp_threat_intel.core.models import Notification
from icp_threat_intel.db.models import EventRow
from icp_threat_intel.parsers.ingest import ioc_canisters
from icp_threat_intel.parsers.signals_keywords import KEYWORDS

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
    ).all()
    rows = newest_parse_only(session, rows)  # a stricter re-parse hides older matches
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


def known_feeds() -> tuple[str, ...]:
    """Every signals feed name: forums, Hacker News and blocklists."""
    from icp_threat_intel.collectors.signals_blocklist import DEFAULT_BLOCKLISTS
    from icp_threat_intel.collectors.signals_feed import DEFAULT_FEEDS
    from icp_threat_intel.collectors.signals_hn import FEED_NAME

    names = {f.name for f in DEFAULT_FEEDS} | {FEED_NAME} | {b.name for b in DEFAULT_BLOCKLISTS}
    return tuple(sorted(names))


def _names(entries: list[str], known: Iterable[str], what: str) -> tuple[str, ...]:
    """Comma-separated or repeated names, lower-cased, de-duplicated, checked against ``known``.

    Empty pieces are ignored, but entries with no name at all are refused.
    """
    allowed = sorted(known)
    pieces = (piece.strip().lower() for entry in entries for piece in entry.split(","))
    names = tuple(sorted({p for p in pieces if p}))
    if entries and not names:
        raise ValueError(f"no {what}s given; known: {', '.join(allowed)}")
    unknown = [n for n in names if n not in allowed]
    if unknown:
        raise ValueError(f"unknown {what}(s): {unknown}; known: {', '.join(allowed)}")
    return names


@dataclass(frozen=True)
class SignalFilter:
    """Which matched posts a digest keeps: from ``feeds``, with any of ``keywords`` (labels),
    IOC matches only. Every set criterion must hold."""

    keywords: tuple[str, ...] = ()
    ioc_only: bool = False
    feeds: tuple[str, ...] = ()

    @classmethod
    def create(
        cls,
        keywords: Iterable[str] = (),
        ioc_only: bool = False,
        feeds: Iterable[str] = (),
    ) -> "SignalFilter":
        """Validate keyword labels (``signals_keywords.KEYWORDS``) and feed names
        (``known_feeds``); refuse unknown ones.

        Each entry may hold several comma-separated names (``"phishing,drainer"``,
        ``"dfinity-forum,hackernews"``); entries from repeated flags are combined.
        """
        labels = _names(list(keywords), KEYWORDS, "keyword label")
        feed_names = _names(list(feeds), known_feeds(), "feed name")
        return cls(keywords=labels, ioc_only=ioc_only, feeds=feed_names)

    @property
    def active(self) -> bool:
        return bool(self.keywords) or self.ioc_only or bool(self.feeds)

    def matches(self, post: SignalPost) -> bool:
        if self.feeds and post.feed not in self.feeds:
            return False
        if self.ioc_only and not post.names_ioc:
            return False
        return not self.keywords or bool(set(self.keywords) & set(post.keywords))

    def describe(self) -> str:
        parts = [f"feeds {', '.join(self.feeds)}"] if self.feeds else []
        parts += [f"keywords {', '.join(self.keywords)}"] if self.keywords else []
        return "; ".join([*parts, *(["IOC matches only"] if self.ioc_only else [])])

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"keywords": list(self.keywords), "ioc_only": self.ioc_only}
        if self.feeds:
            data["feeds"] = list(self.feeds)
        return data


def filter_lines(signal_filter: SignalFilter | None) -> list[str]:
    if signal_filter is None or not signal_filter.active:
        return []
    return ["", f"Filter: {signal_filter.describe()}"]


def left_out_note(shown: int, total: int | None) -> list[str]:
    """A line saying how many matched posts the digest leaves out, if any."""
    if total is None or total <= shown:
        return []
    return [
        "",
        f"Showing {shown} of {total} matched posts; the other {total - shown} are left out. "
        "Run `digest --limit N` or `digest --all` for more, or query the database.",
    ]


def signals_section(
    posts: Sequence[SignalPost],
    total: int | None = None,
    signal_filter: SignalFilter | None = None,
) -> list[str]:
    lines = ["", "## Signals (low authority)", "",
             "Community forum posts naming a threat keyword or a known IOC. Context only: "
             "they never count as verification evidence.",
             *filter_lines(signal_filter), "",
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
    signal_filter: SignalFilter | None = None,
    blocklisted: Sequence[BlocklistedCanister] = (),
) -> Notification:
    """A digest with only the signals feed (``digest --signals-only``)."""
    title = f"icp-threat-intel signals digest {period_end.date().isoformat()}"
    lines = [
        f"# {title}",
        "",
        f"Period: {period_start.isoformat()} to {period_end.isoformat()}",
        "",
        _signals_line(len(posts), total),
        *filter_lines(signal_filter),
    ]
    if posts:
        lines += signals_section(posts, total)
    if blocklisted:
        lines += blocklisted_section(blocklisted)
    data: dict[str, Any] = {
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "signals_total": total if total is not None else len(posts),
        "signals": [p.to_dict() for p in posts],
    }
    if signal_filter is not None and signal_filter.active:
        data["signals_filter"] = signal_filter.to_dict()
    if blocklisted:
        data["blocklisted"] = [r.to_dict() for r in blocklisted]
    return Notification(kind="digest", title=title, markdown="\n".join(lines) + "\n", data=data)
