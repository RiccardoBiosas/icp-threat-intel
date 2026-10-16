"""``collect blocklists``: download PhishDestroy's list, store it, list ICP canisters (mocked)."""

from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import respx
from sqlalchemy import func, select
from typer.testing import CliRunner

from icp_threat_intel.cli.app import app
from icp_threat_intel.core.enums import IocType, SourceType
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import EventRow, Ioc, RawSnapshotRow, Source
from icp_threat_intel.db.session import make_engine, make_session_factory
from tests.collectors import _blocklist_fixtures as fx

runner = CliRunner()


@pytest.fixture
def db(tmp_path: Path) -> Iterator[str]:
    url = f"sqlite:///{tmp_path / 'b.db'}"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    with make_session_factory(engine)() as s, s.begin():
        src = Source(name="seed", source_type=SourceType.VENDOR_RSS, base_url="", reliability=60)
        s.add(src)
        s.flush()
        s.add(
            Ioc(
                ioc_type=IocType.CANISTER_ID,
                value=fx.IOC_CANISTER,
                source_id=src.id,
                source_ref="seed",
                source_url="",
            )
        )
    engine.dispose()
    yield url


@pytest.fixture
def gitlab() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as router:
        router.route(host="gitlab.com").mock(
            return_value=httpx.Response(
                200, content=fx.LIST, headers={"content-type": "text/plain"}
            )
        )
        yield router


def _env(db: str) -> dict[str, str]:
    return {"ICP_THREAT_INTEL_DATABASE_URL": db, "ICP_THREAT_INTEL_CONTACT": "test@example.invalid"}


def _count(db: str, model: type, *where: object) -> int:
    engine = make_engine(db)
    with make_session_factory(engine)() as s:
        n = int(s.scalar(select(func.count()).select_from(model).where(*where)) or 0)
    engine.dispose()
    return n


def test_listed_in_help() -> None:
    result = runner.invoke(app, ["collect", "--help"], terminal_width=200)
    assert result.exit_code == 0 and "blocklists" in result.output


def test_needs_a_contact(db: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ICP_THREAT_INTEL_CONTACT", raising=False)
    result = runner.invoke(
        app, ["collect", "blocklists"], env={"ICP_THREAT_INTEL_DATABASE_URL": db}
    )
    assert result.exit_code == 2 and "ICP_THREAT_INTEL_CONTACT" in result.output


def test_collects_and_parses(db: str, gitlab: respx.MockRouter) -> None:
    result = runner.invoke(app, ["collect", "blocklists"], env=_env(db))
    assert result.exit_code == 0, result.output
    assert "phishdestroy: 1 download(s), 1 new snapshot(s)" in result.output
    assert "4 ICP canister(s) listed (1 already an IOC)" in result.output
    assert [str(c.request.url) for c in gitlab.calls] == [
        "https://gitlab.com/phishdestroy/destroylist/-/raw/main/list.json"
    ]
    assert _count(db, RawSnapshotRow) == 1
    assert _count(db, EventRow, EventRow.kind == "signal.canister_listed") == 4


def test_unchanged_list_adds_nothing(db: str, gitlab: respx.MockRouter) -> None:
    runner.invoke(app, ["collect", "blocklists"], env=_env(db))
    result = runner.invoke(app, ["collect", "blocklists"], env=_env(db))
    assert result.exit_code == 0, result.output
    assert "1 download(s), 0 new snapshot(s)" in result.output
    assert _count(db, RawSnapshotRow) == 1


def test_no_parse(db: str, gitlab: respx.MockRouter) -> None:
    result = runner.invoke(app, ["collect", "blocklists", "--no-parse"], env=_env(db))
    assert result.exit_code == 0, result.output
    assert "not parsed" in result.output
    assert _count(db, EventRow) == 0


def test_network_failure_exits_one(db: str) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.route(host="gitlab.com").mock(side_effect=httpx.ConnectError("down"))
        result = runner.invoke(app, ["collect", "blocklists"], env=_env(db))
    assert result.exit_code == 1 and "collect blocklists failed" in result.output
