"""Digest signals limit: ``--limit N`` / ``--all``, and an explicit note when posts are left out."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import Session
from typer.testing import CliRunner

from icp_threat_intel.alerting.digest import build_digest
from icp_threat_intel.alerting.signals import (
    MAX_SIGNALS,
    SignalPost,
    build_signals_digest,
    matched_signals,
    recent_signals,
)
from icp_threat_intel.cli import publishing
from icp_threat_intel.cli.app import app
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import EventRow, Source
from icp_threat_intel.db.session import make_engine, make_session_factory

NOW = datetime(2026, 10, 16, 1, 0, 0, tzinfo=UTC)
START = NOW - timedelta(hours=24)
TOTAL = MAX_SIGNALS + 5
runner = CliRunner()


def _add_posts(session: Session, n: int) -> None:
    src = Source(
        name="dfinity-forum",
        source_type=SourceType.SIGNALS_FEED,
        base_url="https://forum.dfinity.org",
        reliability=40,
    )
    session.add(src)
    session.flush()
    for i in range(n):
        session.add(
            EventRow(
                kind="signal.post_observed",
                subject_type="signal_post",
                subject_id=f"dfinity-forum:{i}",
                observed_at=NOW - timedelta(minutes=1),
                source_id=src.id,
                source_type=SourceType.SIGNALS_FEED,
                parser="signals_feed@2",
                weight=40,
                payload={
                    "feed": "dfinity-forum",
                    "post_id": i,
                    "keywords": ["scam"],
                    "created_at": f"2026-10-15T{i % 24:02d}:00:00.000Z",
                },
                dedup_key=f"{i:064d}",
            )
        )
    session.flush()


@pytest.fixture
def session() -> Iterator[Session]:
    engine = make_engine("sqlite://")
    Base.metadata.create_all(engine)
    with make_session_factory(engine)() as s:
        yield s
    engine.dispose()


def test_matched_signals_returns_everything(session: Session) -> None:
    _add_posts(session, TOTAL)
    assert len(matched_signals(session, START)) == TOTAL
    assert len(recent_signals(session, START)) == MAX_SIGNALS
    assert len(recent_signals(session, START, limit=3)) == 3
    assert len(recent_signals(session, START, limit=None)) == TOTAL


def test_recent_is_the_head_of_matched(session: Session) -> None:
    _add_posts(session, TOTAL)
    assert recent_signals(session, START, limit=5) == matched_signals(session, START)[:5]


def _posts(n: int) -> list[SignalPost]:
    return [
        SignalPost(
            feed="dfinity-forum",
            post_id=i,
            url=None,
            topic_title="t",
            created_at=None,
            author_staff=False,
            keywords=("scam",),
            canister_ids=(),
            ioc_canisters=(),
        )
        for i in range(n)
    ]


def test_full_digest_says_when_posts_are_left_out() -> None:
    digest = build_digest(
        [], period_start=START, period_end=NOW, signals=_posts(2), signals_total=7
    )
    assert "Showing 2 of 7 matched posts" in digest.markdown
    assert "--limit" in digest.markdown and "--all" in digest.markdown
    assert digest.data["signals_total"] == 7 and len(digest.data["signals"]) == 2


def test_no_note_when_everything_is_shown() -> None:
    digest = build_digest([], period_start=START, period_end=NOW, signals=_posts(2))
    assert "Showing" not in digest.markdown
    assert digest.data["signals_total"] == 2


def test_signals_digest_header_counts_all_matches() -> None:
    digest = build_signals_digest(_posts(3), period_start=START, period_end=NOW, total=40)
    assert "Signals: 40 matched post(s), 3 shown" in digest.markdown
    assert "Showing 3 of 40 matched posts" in digest.markdown
    assert digest.data["signals_total"] == 40


def _db(tmp_path: Path) -> str:
    url = f"sqlite:///{tmp_path / 'd.db'}"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    with make_session_factory(engine)() as s, s.begin():
        _add_posts(s, TOTAL)
    engine.dispose()
    return url


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *extra: str) -> tuple[str, str]:
    monkeypatch.setattr(publishing, "_now", lambda: NOW)
    out = tmp_path / "digests"
    result = runner.invoke(
        app,
        ["digest", "--signals-only", "--out", str(out), *extra],
        env={"ICP_THREAT_INTEL_DATABASE_URL": _db(tmp_path)},
    )
    assert result.exit_code == 0, result.output
    (md,) = out.glob("*.md")
    return result.output, md.read_text(encoding="utf-8")


def test_cli_default_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output, md = _run(tmp_path, monkeypatch)
    assert f"{MAX_SIGNALS} of {TOTAL} signal(s)" in output
    assert f"Showing {MAX_SIGNALS} of {TOTAL} matched posts" in md


def test_cli_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output, md = _run(tmp_path, monkeypatch, "--limit", "5")
    assert f"5 of {TOTAL} signal(s)" in output
    assert md.count("| 2026-10-15") + md.count("| - |") >= 5


def test_cli_all(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output, md = _run(tmp_path, monkeypatch, "--all")
    assert f"signals digest: {TOTAL} signal(s)" in output  # nothing left out
    assert "Showing" not in md


def test_cli_full_digest_accepts_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(publishing, "_now", lambda: NOW)
    result = runner.invoke(
        app,
        ["digest", "--out", str(tmp_path / "d"), "--limit", "3"],
        env={"ICP_THREAT_INTEL_DATABASE_URL": _db(tmp_path)},
    )
    assert result.exit_code == 0, result.output
    assert f"3 of {TOTAL} signal(s)" in result.output
