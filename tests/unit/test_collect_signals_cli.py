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


def test_more_than_ten_pages_needs_backfill(db: str, forum: respx.MockRouter) -> None:
    result = runner.invoke(app, ["collect", "signals", "--pages", "11"], env=_env(db))
    assert result.exit_code == 2
    assert "--backfill" in result.output
    assert not forum.calls


def test_backfill_walks_until_the_forum_runs_out(db: str, forum: respx.MockRouter) -> None:
    result = runner.invoke(
        app, ["collect", "signals", "--backfill", "--pages", "150"], env=_env(db)
    )
    assert result.exit_code == 0, result.output
    assert "dfinity-forum: 3 page(s)" in result.output


def test_since_stops_the_backfill(db: str, forum: respx.MockRouter) -> None:
    result = runner.invoke(
        app,
        ["collect", "signals", "--backfill", "--pages", "150", "--since", "2026-10-16"],
        env=_env(db),
    )
    assert result.exit_code == 0, result.output
    assert "dfinity-forum: 1 page(s)" in result.output


def _search_forum(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/posts.json":
        return _forum(request)
    if path == "/search.json":
        q = request.url.params["q"]
        body = fx.search_body((7001, 700, 1)) if q.startswith("drainer") else fx.search_body()
    elif path == "/t/700.json":
        body = fx.topic_body(700, fx.topic_post(7001, 700, 1, "a wallet drainer on /tmp/pglog"))
    else:
        return httpx.Response(404, content=b"{}")
    return httpx.Response(200, content=body, headers={"content-type": "application/json"})


def test_search_collects_topics_and_never_sends_ioc_values(
    db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from icp_threat_intel.cli import collect as collect_cli
    from icp_threat_intel.collectors import signals_feed
    from icp_threat_intel.core.enums import IocType
    from icp_threat_intel.core.ratelimit import HostRateLimiter
    from icp_threat_intel.db.models import Ioc
    from icp_threat_intel.parsers.signals_keywords import SEARCH_TERMS

    pauses: list[float] = []
    monkeypatch.setattr(collect_cli, "_pause", pauses.append)
    real_http = signals_feed.signals_http
    fast = HostRateLimiter(rate_per_second=1000.0, burst=1000, sleep=lambda _s: None)
    monkeypatch.setattr(
        signals_feed, "signals_http", lambda contact: real_http(contact, limiter=fast)
    )
    engine = make_engine(db)
    with make_session_factory(engine)() as s, s.begin():
        src = Source(name="seed", source_type=SourceType.VENDOR_RSS, base_url="", reliability=60)
        s.add(src)
        s.flush()
        for ioc_type, value in ((IocType.FILE_PATH, "/tmp/pglog"),
                                (IocType.CANISTER_ID, fx.IOC_CANISTER)):  # fmt: skip
            s.add(Ioc(ioc_type=ioc_type, value=value, source_id=src.id, source_ref=value,
                      source_url=""))  # fmt: skip
    engine.dispose()
    with respx.mock(assert_all_called=False) as router:
        router.route(host="forum.dfinity.org").mock(side_effect=_search_forum)
        result = runner.invoke(app, ["collect", "signals", "--search"], env=_env(db))
        sent = [str(c.request.url) for c in router.calls]
    assert result.exit_code == 0, result.output
    assert f"searching {len(SEARCH_TERMS)} generic terms" in result.output
    assert "dfinity-forum search:" in result.output
    assert "1 post(s) matched (1 naming an IOC value)" in result.output
    searches = [u for u in sent if "/search.json" in u]
    assert len(searches) == len(SEARCH_TERMS)
    assert len(pauses) == len(SEARCH_TERMS) - 1
    for url in searches:
        assert "pglog" not in url and fx.IOC_CANISTER not in url
    assert any("/t/700.json" in u for u in sent)
