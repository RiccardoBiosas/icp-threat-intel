"""``collect hackernews``: curated ICP queries on HN Search, stored and parsed (mocked)."""

from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import respx
from sqlalchemy import func, select
from typer.testing import CliRunner

from icp_threat_intel.cli import collect as collect_cli
from icp_threat_intel.cli.app import app
from icp_threat_intel.collectors import signals_hn
from icp_threat_intel.core.enums import IocType, SourceType
from icp_threat_intel.core.ratelimit import HostRateLimiter
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import EventRow, Ioc, RawSnapshotRow, Source
from icp_threat_intel.db.session import make_engine, make_session_factory
from icp_threat_intel.parsers.signals_keywords import HN_QUERIES
from tests.collectors import _hn_fixtures as fx

runner = CliRunner()


@pytest.fixture
def db(tmp_path: Path) -> Iterator[str]:
    url = f"sqlite:///{tmp_path / 'hn.db'}"
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
def fast(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    pauses: list[float] = []
    monkeypatch.setattr(collect_cli, "_pause", pauses.append)
    real = signals_hn.hn_http
    limiter = HostRateLimiter(rate_per_second=1000.0, burst=1000, sleep=lambda _s: None)
    monkeypatch.setattr(signals_hn, "hn_http", lambda contact: real(contact, limiter=limiter))
    return pauses


def _algolia(request: httpx.Request) -> httpx.Response:
    q = request.url.params["query"]
    body = fx.PAGE if q == "internet computer" else fx.EMPTY
    return httpx.Response(200, content=body, headers={"content-type": "application/json"})


@pytest.fixture
def algolia() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as router:
        router.route(host="hn.algolia.com").mock(side_effect=_algolia)
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
    assert result.exit_code == 0 and "hackernews" in result.output


def test_needs_a_contact(db: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ICP_THREAT_INTEL_CONTACT", raising=False)
    result = runner.invoke(
        app, ["collect", "hackernews"], env={"ICP_THREAT_INTEL_DATABASE_URL": db}
    )
    assert result.exit_code == 2 and "ICP_THREAT_INTEL_CONTACT" in result.output


def test_collects_and_parses(db: str, algolia: respx.MockRouter, fast: list[float]) -> None:
    result = runner.invoke(app, ["collect", "hackernews"], env=_env(db))
    assert result.exit_code == 0, result.output
    assert f"searching {len(HN_QUERIES)} curated queries" in result.output
    assert "hackernews: 6 page(s), 6 new snapshot(s)" in result.output  # 1 with hits, 5 empty
    assert "2 post(s) matched" in result.output
    assert "1 IOC canister reference(s)" in result.output
    sent = [c.request.url.params["query"] for c in algolia.calls]
    assert sent == list(HN_QUERIES)
    assert len(fast) == len(HN_QUERIES) - 1
    assert _count(db, RawSnapshotRow) == 6
    assert _count(db, EventRow, EventRow.kind == "signal.post_observed") == 2


def test_since_and_pages(db: str, algolia: respx.MockRouter, fast: list[float]) -> None:
    result = runner.invoke(
        app,
        ["collect", "hackernews", "--since", "2026-03-01", "--pages", "3"],
        env=_env(db),
    )
    assert result.exit_code == 0, result.output
    params = algolia.calls[0].request.url.params
    assert params["numericFilters"].startswith("created_at_i>")


def test_bad_pages_exit_two(db: str, algolia: respx.MockRouter) -> None:
    result = runner.invoke(app, ["collect", "hackernews", "--pages", "11"], env=_env(db))
    assert result.exit_code == 2
    assert not algolia.calls


def test_no_parse(db: str, algolia: respx.MockRouter, fast: list[float]) -> None:
    result = runner.invoke(app, ["collect", "hackernews", "--no-parse"], env=_env(db))
    assert result.exit_code == 0, result.output
    assert "not parsed" in result.output and _count(db, EventRow) == 0
