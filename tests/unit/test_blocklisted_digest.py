"""Digest section for ICP canisters named by community blocklists (PhishDestroy)."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import Session
from typer.testing import CliRunner

from icp_threat_intel.alerting.blocklisted import BlocklistedCanister, blocklisted_canisters
from icp_threat_intel.alerting.digest import build_digest
from icp_threat_intel.alerting.signals import build_signals_digest
from icp_threat_intel.cli import publishing
from icp_threat_intel.cli.app import app
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import EventRow, Source
from icp_threat_intel.db.session import make_engine, make_session_factory
from tests.collectors import _blocklist_fixtures as fx

NOW = datetime(2026, 10, 16, 6, 0, tzinfo=UTC)
START = NOW - timedelta(hours=24)
runner = CliRunner()


def _listed(
    s: Session,
    src: Source,
    canister: str,
    at: datetime,
    n: int,
    *,
    ioc: bool = False,
    hosts: tuple[str, ...] = (),
) -> None:
    s.add(
        EventRow(
            kind="signal.canister_listed",
            subject_type="canister",
            subject_id=canister,
            canister_id=canister,
            observed_at=at,
            source_id=src.id,
            source_type=SourceType.SIGNALS_FEED,
            parser="signals_feed@2",
            weight=40,
            is_ioc=ioc,
            payload={
                "feed": src.name,
                "list": "phishing_and_scam_domains",
                "hosts": list(hosts) or [f"{canister}.icp0.io"],
            },
            dedup_key=f"{n:064d}",
        )
    )


def _seed(s: Session) -> None:
    src = Source(
        name="phishdestroy", source_type=SourceType.SIGNALS_FEED, base_url="", reliability=40
    )
    s.add(src)
    s.flush()
    _listed(s, src, fx.CAN_B, NOW - timedelta(hours=30), 1)  # before the window
    _listed(s, src, fx.CAN_B, NOW - timedelta(hours=1), 2)  # listed again in the window
    _listed(
        s,
        src,
        fx.CAN_A,
        NOW - timedelta(hours=2),
        3,
        hosts=(f"{fx.CAN_A}.icp0.io", f"{fx.CAN_A}.raw.icp0.io"),
    )
    _listed(s, src, fx.IOC_CANISTER, NOW - timedelta(hours=2), 4, ioc=True)
    s.flush()


@pytest.fixture
def session() -> Iterator[Session]:
    engine = make_engine("sqlite://")
    Base.metadata.create_all(engine)
    with make_session_factory(engine)() as s:
        _seed(s)
        yield s
    engine.dispose()


def test_one_row_per_canister_ioc_first(session: Session) -> None:
    rows = blocklisted_canisters(session, START)
    assert [r.canister_id for r in rows] == [fx.IOC_CANISTER, *sorted([fx.CAN_A, fx.CAN_B])]
    assert rows[0].is_ioc and not rows[1].is_ioc


def test_first_listed_uses_the_whole_history(session: Session) -> None:
    by_id = {r.canister_id: r for r in blocklisted_canisters(session, START)}
    assert by_id[fx.CAN_B].first_listed == (NOW - timedelta(hours=30)).replace(tzinfo=UTC)
    assert by_id[fx.CAN_A].hosts == (f"{fx.CAN_A}.icp0.io", f"{fx.CAN_A}.raw.icp0.io")
    assert by_id[fx.CAN_A].feeds == ("phishdestroy",)


def test_window_excludes_canisters_not_seen_since(session: Session) -> None:
    assert blocklisted_canisters(session, NOW) == []


def test_ioc_only(session: Session) -> None:
    rows = blocklisted_canisters(session, START, ioc_only=True)
    assert [r.canister_id for r in rows] == [fx.IOC_CANISTER]


ROW = BlocklistedCanister(
    canister_id=fx.CAN_A,
    feeds=("phishdestroy",),
    hosts=(f"{fx.CAN_A}.icp0.io",),
    is_ioc=False,
    first_listed=NOW,
)


def test_signals_digest_section_and_json() -> None:
    digest = build_signals_digest([], period_start=START, period_end=NOW, blocklisted=[ROW])
    assert "## Blocklisted ICP canisters (low authority)" in digest.markdown
    assert f"`{fx.CAN_A}`" in digest.markdown and "phishdestroy" in digest.markdown
    assert "never visit" in digest.markdown
    assert digest.data["blocklisted"][0]["canister_id"] == fx.CAN_A


def test_full_digest_section() -> None:
    digest = build_digest([], period_start=START, period_end=NOW, blocklisted=[ROW])
    assert "## Blocklisted ICP canisters" in digest.markdown
    assert digest.data["blocklisted"][0]["feeds"] == ["phishdestroy"]


def test_no_section_or_key_without_rows() -> None:
    digest = build_signals_digest([], period_start=START, period_end=NOW)
    assert "Blocklisted" not in digest.markdown and "blocklisted" not in digest.data


def _db(tmp_path: Path) -> str:
    url = f"sqlite:///{tmp_path / 'd.db'}"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    with make_session_factory(engine)() as s, s.begin():
        _seed(s)
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
    return result.output, next(out.glob("*.md")).read_text(encoding="utf-8")


def test_cli_lists_blocklisted_canisters(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output, md = _run(tmp_path, monkeypatch)
    assert "3 blocklisted canister(s)" in output
    assert f"`{fx.CAN_B}`" in md


def test_cli_keyword_filter_leaves_blocklists_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, md = _run(tmp_path, monkeypatch, "--keyword", "phishing")
    assert "Blocklisted" not in md and "blocklisted" not in output


def test_cli_ioc_only_keeps_ioc_canisters(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output, md = _run(tmp_path, monkeypatch, "--ioc-only")
    assert "1 blocklisted canister(s)" in output
    assert f"`{fx.IOC_CANISTER}`" in md and f"`{fx.CAN_A}`" not in md
