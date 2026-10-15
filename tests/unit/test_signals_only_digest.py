"""``digest --signals-only``: a digest with just the signals feed, in its own files."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import Session
from typer.testing import CliRunner

from icp_threat_intel.alerting.digest import digest_stem
from icp_threat_intel.alerting.signals import SignalPost, build_signals_digest
from icp_threat_intel.cli import publishing
from icp_threat_intel.cli.app import app
from icp_threat_intel.core.enums import DetectionStatus, SourceType
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import EventRow, Source
from icp_threat_intel.db.session import make_engine, make_session_factory
from icp_threat_intel.verification.store import save_candidate
from tests.collectors._signals_feed_fixtures import IOC_CANISTER
from tests.exporters.conftest import verified_h1

END = datetime(2026, 10, 15, 16, 6, 52, tzinfo=UTC)
START = END - timedelta(hours=24)
runner = CliRunner()


def _post() -> SignalPost:
    return SignalPost(
        feed="dfinity-forum",
        post_id=7,
        url="https://forum.dfinity.org/t/synthetic/7/1",
        topic_title="Synthetic topic",
        created_at="2026-10-15T05:00:00.000Z",
        author_staff=False,
        keywords=("phishing",),
        canister_ids=(),
        ioc_canisters=(),
    )


def test_signals_digest_has_only_the_signals_section() -> None:
    digest = build_signals_digest([_post()], period_start=START, period_end=END)
    assert digest.kind == "digest"
    assert digest.title == "icp-threat-intel signals digest 2026-10-15"
    assert "## Signals (low authority)" in digest.markdown
    assert "Signals: 1 matched post(s)" in digest.markdown
    for other in ("Detections", "## Watched canisters", "## Census"):
        assert other not in digest.markdown
    assert set(digest.data) == {"period_start", "period_end", "signals"}
    assert digest.data["signals"][0]["post_id"] == 7


def test_empty_signals_digest_says_none() -> None:
    digest = build_signals_digest([], period_start=START, period_end=END)
    assert "Signals: none" in digest.markdown
    assert "## Signals" not in digest.markdown


def test_signals_digest_files_have_their_own_prefix() -> None:
    digest = build_signals_digest([], period_start=START, period_end=END)
    assert digest_stem(digest) == "icp-threat-intel_signals_digest_2026-10-15T160652Z"


def _db(tmp_path: Path) -> str:
    url = f"sqlite:///{tmp_path / 'd.db'}"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    with make_session_factory(engine)() as s, s.begin():
        save_candidate(
            s, verified_h1(IOC_CANISTER).model_copy(update={"status": DetectionStatus.CANDIDATE})
        )
        _signal_event(s)
    engine.dispose()
    return url


def _signal_event(s: Session) -> None:
    src = Source(
        name="dfinity-forum",
        source_type=SourceType.SIGNALS_FEED,
        base_url="https://forum.dfinity.org",
        reliability=40,
    )
    s.add(src)
    s.flush()
    s.add(
        EventRow(
            kind="signal.post_observed",
            subject_type="signal_post",
            subject_id="dfinity-forum:7",
            observed_at=END - timedelta(hours=1),
            source_id=src.id,
            source_type=SourceType.SIGNALS_FEED,
            parser="signals_feed@1",
            weight=40,
            payload={"feed": "dfinity-forum", "post_id": 7, "keywords": ["phishing"]},
            dedup_key="d" * 64,
        )
    )


def test_cli_signals_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(publishing, "_now", lambda: END)
    out = tmp_path / "digests"
    result = runner.invoke(
        app,
        ["digest", "--signals-only", "--out", str(out)],
        env={"ICP_THREAT_INTEL_DATABASE_URL": _db(tmp_path)},
    )
    assert result.exit_code == 0, result.output
    assert "signals digest: 1 signal(s)" in result.output
    md = out / "icp-threat-intel_signals_digest_2026-10-15T160652Z.md"
    assert md.is_file() and (out / f"{md.stem}.json").is_file()
    text = md.read_text(encoding="utf-8")
    assert "phishing" in text and "Detections" not in text  # the candidate is left out
