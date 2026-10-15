"""Digest "Signals" section: recent forum posts, IOC references first, rendered as inert text."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from icp_threat_intel.alerting.digest import build_digest
from icp_threat_intel.alerting.signals import MAX_SIGNALS, SignalPost, md_text, recent_signals
from icp_threat_intel.core.enums import IocType, SourceType
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import EventRow, Ioc, Source
from icp_threat_intel.db.session import make_engine, make_session_factory
from tests.collectors._signals_feed_fixtures import IOC_CANISTER, OTHER_CANISTER

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)
START = NOW - timedelta(hours=24)


@pytest.fixture
def session() -> Iterator[Session]:
    engine: Engine = make_engine("sqlite://")
    Base.metadata.create_all(engine)
    with make_session_factory(engine)() as s:
        yield s
    engine.dispose()


def _source(session: Session) -> Source:
    src = Source(
        name="dfinity-forum",
        source_type=SourceType.SIGNALS_FEED,
        base_url="https://forum.dfinity.org",
        reliability=40,
    )
    session.add(src)
    session.flush()
    return src


def _post(
    session: Session,
    src: Source,
    post_id: int,
    *,
    keywords: list[str],
    canisters: list[str] = (),  # type: ignore[assignment]
    staff: bool = False,
    observed: datetime = NOW,
    created: str = "2026-10-15T05:00:00.000Z",
    title: str = "Synthetic topic",
) -> None:
    payload: dict[str, Any] = {
        "feed": "dfinity-forum",
        "post_id": post_id,
        "url": f"https://forum.dfinity.org/t/synthetic/{post_id}/1",
        "topic_title": title,
        "created_at": created,
        "author_staff": staff,
        "keywords": keywords,
        "canister_ids": list(canisters),
    }
    session.add(
        EventRow(
            kind="signal.post_observed",
            subject_type="signal_post",
            subject_id=f"dfinity-forum:{post_id}",
            observed_at=observed,
            source_id=src.id,
            source_type=SourceType.SIGNALS_FEED,
            parser="signals_feed@1",
            weight=40,
            payload=payload,
            dedup_key=f"{post_id}-{observed.isoformat()}".ljust(64, "x")[:64],
        )
    )
    session.flush()


def _ioc(session: Session, src: Source) -> None:
    session.add(
        Ioc(
            ioc_type=IocType.CANISTER_ID,
            value=IOC_CANISTER,
            source_id=src.id,
            source_ref="seed",
            source_url="",
        )
    )
    session.flush()


def test_orders_ioc_then_staff_then_newest(session: Session) -> None:
    src = _source(session)
    _ioc(session, src)
    _post(session, src, 1, keywords=["scam"], created="2026-10-15T09:00:00.000Z")
    _post(session, src, 2, keywords=["malware"], staff=True, created="2026-10-15T01:00:00.000Z")
    _post(session, src, 3, keywords=[], canisters=[IOC_CANISTER])
    _post(session, src, 4, keywords=["phishing"], created="2026-10-15T10:00:00.000Z")
    posts = recent_signals(session, START)
    assert [p.post_id for p in posts] == [3, 2, 4, 1]
    assert posts[0].ioc_canisters == (IOC_CANISTER,)


def test_canister_mention_without_keyword_or_ioc_is_noise(session: Session) -> None:
    src = _source(session)
    _post(session, src, 1, keywords=[], canisters=[OTHER_CANISTER])
    assert recent_signals(session, START) == []


def test_window_and_dedup(session: Session) -> None:
    src = _source(session)
    _post(session, src, 1, keywords=["scam"], observed=START - timedelta(hours=1))
    _post(session, src, 2, keywords=["scam"], observed=NOW - timedelta(hours=2))
    _post(session, src, 2, keywords=["scam"], observed=NOW)  # re-polled page
    posts = recent_signals(session, START)
    assert [p.post_id for p in posts] == [2]


def test_bounded(session: Session) -> None:
    src = _source(session)
    for i in range(MAX_SIGNALS + 5):
        _post(session, src, i, keywords=["scam"])
    assert len(recent_signals(session, START)) == MAX_SIGNALS


def test_md_text_neutralises_markup() -> None:
    hostile = "Free [airdrop](https://evil.example) <img src=x> | `code`\nnext"
    out = md_text(hostile)
    assert "](" not in out and "<img" not in out and "\n" not in out
    assert "\\|" in out and "`" not in out
    assert len(md_text("x" * 500)) <= 80


def _signal(**kw: Any) -> SignalPost:
    base: dict[str, Any] = {
        "feed": "dfinity-forum",
        "post_id": 7,
        "url": "https://forum.dfinity.org/t/synthetic/7/1",
        "topic_title": "Is [this](https://evil.example) canister malicious?",
        "created_at": "2026-10-15T05:00:00.000Z",
        "author_staff": True,
        "keywords": ("malicious",),
        "canister_ids": (IOC_CANISTER,),
        "ioc_canisters": (IOC_CANISTER,),
    }
    return SignalPost(**(base | kw))


def test_digest_section_and_json() -> None:
    digest = build_digest([], period_start=START, period_end=NOW, signals=[_signal()])
    md = digest.markdown
    assert "## Signals (low authority)" in md
    assert "never count as verification evidence" in md
    row = next(line for line in md.splitlines() if line.startswith("| 2026-10-15"))
    assert f"**`{IOC_CANISTER}`** (IOC)" in row
    assert "staff" in row and "malicious" in row
    assert "](" not in row  # titles cannot inject links
    assert "`https://forum.dfinity.org/t/synthetic/7/1`" in row  # url shown as code
    assert digest.data["signals"][0]["post_id"] == 7


def test_digest_without_signals_has_no_section() -> None:
    digest = build_digest([], period_start=START, period_end=NOW)
    assert "Signals" not in digest.markdown
    assert digest.data["signals"] == []
