"""``collect signals``: poll the signals feed into the raw store and parse it (network mocked)."""

from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import respx
from sqlalchemy import func, select
from typer.testing import CliRunner

from icp_threat_intel.cli.app import app
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import EventRow, RawSnapshotRow, Source
from icp_threat_intel.db.session import make_engine, make_session_factory
from tests.collectors import _signals_feed_fixtures as fx

runner = CliRunner()


@pytest.fixture
def db(tmp_path: Path) -> Iterator[str]:
    url = f"sqlite:///{tmp_path / 'signals.db'}"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    engine.dispose()
    yield url


def _forum(request: httpx.Request) -> httpx.Response:
    before = request.url.params.get("before")
    content = {None: fx.PAGE_1, "101": fx.PAGE_2}.get(before, fx.EMPTY)
    return httpx.Response(200, content=content, headers={"content-type": "application/json"})


@pytest.fixture
def forum() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as router:
        router.route(host="forum.dfinity.org").mock(side_effect=_forum)
        yield router


def _env(db: str, contact: str = "test@example.invalid") -> dict[str, str]:
    return {"ICP_THREAT_INTEL_DATABASE_URL": db, "ICP_THREAT_INTEL_CONTACT": contact}


def _count(db: str, model: type, *where: object) -> int:
    engine = make_engine(db)
    with make_session_factory(engine)() as s:
        n = int(s.scalar(select(func.count()).select_from(model).where(*where)) or 0)
    engine.dispose()
    return n


def test_collect_alone_is_still_a_stub() -> None:
    result = runner.invoke(app, ["collect"])
    assert result.exit_code == 2
    assert "collect signals" in result.output


def test_collect_lists_signals() -> None:
    result = runner.invoke(app, ["collect", "--help"], terminal_width=200)
    assert result.exit_code == 0 and "signals" in result.output


def test_needs_a_contact(db: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ICP_THREAT_INTEL_CONTACT", raising=False)
    result = runner.invoke(app, ["collect", "signals"], env={"ICP_THREAT_INTEL_DATABASE_URL": db})
    assert result.exit_code == 2
    assert "ICP_THREAT_INTEL_CONTACT" in result.output


def test_collects_and_parses(db: str, forum: respx.MockRouter) -> None:
    result = runner.invoke(app, ["collect", "signals", "--pages", "3"], env=_env(db))
    assert result.exit_code == 0, result.output
    assert "dfinity-forum: 3 page(s), 3 new snapshot(s)" in result.output
    assert "3 post(s) matched" in result.output
    assert "0 IOC canister reference(s)" in result.output  # no IOCs seeded
    assert _count(db, RawSnapshotRow) == 3
    assert _count(db, EventRow, EventRow.kind == "signal.post_observed") == 3
    assert _count(db, Source, Source.source_type == SourceType.SIGNALS_FEED) == 1
    assert [r.url.params.get("before") for r in (c.request for c in forum.calls)] == [
        None,
        "101",
        "100",
    ]


def test_second_run_adds_nothing(db: str, forum: respx.MockRouter) -> None:
    runner.invoke(app, ["collect", "signals"], env=_env(db))
    result = runner.invoke(app, ["collect", "signals"], env=_env(db))
    assert result.exit_code == 0, result.output
    assert "1 page(s), 0 new snapshot(s)" in result.output
    assert _count(db, RawSnapshotRow) == 1


def test_no_parse_only_stores(db: str, forum: respx.MockRouter) -> None:
    result = runner.invoke(app, ["collect", "signals", "--no-parse"], env=_env(db))
    assert result.exit_code == 0, result.output
    assert "not parsed" in result.output
    assert _count(db, RawSnapshotRow) == 1 and _count(db, EventRow) == 0


def test_unknown_feed_exits_two(db: str, forum: respx.MockRouter) -> None:
    result = runner.invoke(app, ["collect", "signals", "--feed", "nope"], env=_env(db))
    assert result.exit_code == 2
    assert "unknown signals feed" in result.output
    assert not forum.calls


def test_network_failure_exits_one(db: str) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.route(host="forum.dfinity.org").mock(side_effect=httpx.ConnectError("down"))
        result = runner.invoke(app, ["collect", "signals"], env=_env(db))
    assert result.exit_code == 1
    assert "collect signals failed" in result.output
