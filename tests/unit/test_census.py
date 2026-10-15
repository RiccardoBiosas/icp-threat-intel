"""Census: diff, walker (pagination, ceiling, failures), two-run persistence, inspect CLI."""

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker
from typer.testing import CliRunner

from icp_threat_intel.census.diff import CanisterState, diff_runs
from icp_threat_intel.census.run import previous_run, run_census
from icp_threat_intel.census.walker import CensusWalker
from icp_threat_intel.cli.app import app
from icp_threat_intel.core.enums import CanisterStatus
from icp_threat_intel.core.ic_encoding import principal_to_text
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import Canister, EventRow, RawSnapshotRow
from icp_threat_intel.db.models import CanisterSnapshot as SnapshotRow
from icp_threat_intel.db.session import make_engine, make_session_factory
from icp_threat_intel.raw_store.store import SqlRawStore
from tests.collectors._cassettes import SEED_CANISTERS, synthetic_principal
from tests.parsers.conftest import http_client

S1, S2 = sorted(principal_to_text(synthetic_principal(f"census-subnet-{i}")) for i in (1, 2))
T0 = datetime(2026, 10, 15, tzinfo=UTC)


def cid(n: int) -> str:
    return principal_to_text(n.to_bytes(8, "big") + b"\x01\x01")


def _state(n: int, subnet: str = S1, **kw: Any) -> CanisterState:
    return CanisterState(canister_id=cid(n), subnet=subnet, **kw)


# --- diff ---------------------------------------------------------------------------


def test_diff_added_removed_changed() -> None:
    prev = {
        cid(1): _state(1, module_hash="aa", controllers=("x", "y")),
        cid(2): _state(2),
        cid(3): _state(3, S2),
    }
    cur = {
        cid(1): _state(1, module_hash="bb", controllers=("y", "x"), status=CanisterStatus.RUNNING),
        cid(4): _state(4),
    }
    diff = diff_runs(prev, cur, frozenset({S1}))
    assert diff.added == (cid(4),)
    assert diff.removed == (cid(2),)  # cid(3)'s subnet S2 was not complete in both runs
    assert diff.changed == {cid(1): {"module_hash": {"from": "aa", "to": "bb"}}}


def test_diff_status_and_controller_set_changes() -> None:
    prev = {cid(1): _state(1, controllers=("x",), status=CanisterStatus.STOPPED)}
    cur = {cid(1): _state(1, controllers=("x", "z"), status=CanisterStatus.RUNNING, subnet=S2)}
    changes = diff_runs(prev, cur, frozenset()).changed[cid(1)]
    assert changes["status"] == {"from": "stopped", "to": "running"}
    assert changes["controllers"] == {"from": ["x"], "to": ["x", "z"]}
    assert changes["subnet"] == {"from": S1, "to": S2}


def test_partial_runs_never_report_removals() -> None:
    prev = {cid(i): _state(i) for i in range(5)}
    assert diff_runs(prev, {}, frozenset()).removed == ()


def test_first_run_reports_everything_added() -> None:
    diff = diff_runs({}, {cid(1): _state(1)}, frozenset())
    assert diff.added == (cid(1),) and diff.removed == () and diff.changed == {}


# --- fake Dashboard API ---------------------------------------------------------------


def dashboard(
    canisters: dict[str, list[dict[str, Any]]], *, fail: frozenset[str] = frozenset(), page: int = 2
) -> tuple[httpx.MockTransport, list[httpx.Request]]:
    """Subnet list plus per-subnet canister lists, ``page`` items per page."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        q = {k: v[0] for k, v in parse_qs(request.url.query.decode()).items()}
        assert request.url.host == "ic-api.internetcomputer.org" and request.method == "GET"
        if request.url.path == "/api/v4/subnets":
            return httpx.Response(200, json={"data": [{"subnet_id": s} for s in canisters]})
        assert request.url.path == "/api/v4/canisters"
        subnet = q["subnet_id"]
        if subnet in fail:
            return httpx.Response(503, json={"error": "upstream"})
        start = int(q.get("after", 0))
        items = canisters[subnet][start : start + page]
        nxt = str(start + page) if start + page < len(canisters[subnet]) else None
        return httpx.Response(200, json={"data": items, "next_cursor": nxt})

    return httpx.MockTransport(handler), seen


def item(n: int, subnet: str, **kw: Any) -> dict[str, Any]:
    return {"canister_id": cid(n), "subnet_id": subnet, "controllers": [], **kw}


@pytest.fixture
def sessions(tmp_path: Path) -> Iterator[sessionmaker[Session]]:
    engine = make_engine(f"sqlite:///{tmp_path / 'census.db'}")
    Base.metadata.create_all(engine)
    yield make_session_factory(engine)
    engine.dispose()


def _walker(
    sessions: sessionmaker[Session], transport: httpx.BaseTransport, *, ceiling: int = 100,
    run: str = "run-1", at: datetime = T0,
) -> CensusWalker:  # fmt: skip
    return CensusWalker(
        http_client(transport), SqlRawStore(sessions), ceiling=ceiling,
        clock=lambda: at, run_id=lambda: run, synthetic=True,
    )  # fmt: skip


# --- walker ---------------------------------------------------------------------------


def test_walker_pages_through_every_subnet_and_stores_pages(
    sessions: sessionmaker[Session],
) -> None:
    transport, seen = dashboard({S1: [item(i, S1) for i in range(5)], S2: [item(9, S2)]})
    walk = _walker(sessions, transport).walk()
    assert set(walk.states) == {cid(i) for i in (0, 1, 2, 3, 4, 9)}
    assert walk.complete_subnets == {S1, S2} and not walk.incomplete_subnets
    assert not walk.ceiling_hit
    assert walk.pages == len(seen) == 1 + 3 + 1  # subnets + 3 pages S1 + 1 page S2
    with sessions() as s:
        assert len(s.scalars(select(RawSnapshotRow)).all()) == walk.pages


def test_walker_ceiling_marks_remaining_subnets_incomplete(
    sessions: sessionmaker[Session],
) -> None:
    transport, _ = dashboard({S1: [item(i, S1) for i in range(5)], S2: [item(9, S2)]})
    walk = _walker(sessions, transport, ceiling=3).walk()
    assert len(walk.states) == 3 and walk.ceiling_hit
    assert walk.incomplete_subnets == {S1, S2} and not walk.complete_subnets


def test_failing_subnet_is_incomplete_and_does_not_abort(sessions: sessionmaker[Session]) -> None:
    transport, _ = dashboard({S1: [item(1, S1)], S2: [item(2, S2)]}, fail=frozenset({S1}))
    walk = _walker(sessions, transport).walk()
    assert walk.incomplete_subnets == {S1} and walk.complete_subnets == {S2}
    assert set(walk.states) == {cid(2)}


def test_ceiling_must_be_positive(sessions: sessionmaker[Session]) -> None:
    with pytest.raises(ValueError):
        _walker(sessions, dashboard({})[0], ceiling=0)


# --- run: persistence and diff against the previous run -------------------------------


def _events(sessions: sessionmaker[Session], kind: str) -> list[EventRow]:
    with sessions() as s:
        return list(s.scalars(select(EventRow).where(EventRow.kind == kind)).all())


def test_two_runs_persist_and_diff(sessions: sessionmaker[Session]) -> None:
    first = {S1: [item(1, S1, module_hash="aa"), item(2, S1)], S2: [item(3, S2)]}
    run_census(sessions, _walker(sessions, dashboard(first)[0]))
    assert len(_events(sessions, "census.canister_added")) == 3
    with sessions() as s:
        assert len(s.scalars(select(SnapshotRow)).all()) == 3
        assert s.get(Canister, cid(1)) is not None
        prev = previous_run(s)
        assert prev is not None and prev.run_id == "run-1"

    second = {S1: [item(1, S1, module_hash="bb")], S2: []}
    later = T0 + timedelta(days=7)
    walk, diff = run_census(
        sessions,
        _walker(sessions, dashboard(second, fail=frozenset({S2}))[0], run="run-2", at=later),
    )
    assert diff.removed == (cid(2),)  # S1 complete in both; S2 failed in run 2
    assert diff.changed == {cid(1): {"module_hash": {"from": "aa", "to": "bb"}}}
    (changed,) = _events(sessions, "census.canister_changed")
    assert changed.payload["changes"]["module_hash"] == {"from": "aa", "to": "bb"}
    (removed,) = _events(sessions, "census.canister_removed")
    assert removed.canister_id == cid(2)
    completed = _events(sessions, "census.run_completed")
    assert len(completed) == 2
    summary = max(completed, key=lambda e: e.id).payload
    assert summary["previous_run_id"] == "run-1" and summary["incomplete_subnets"] == [S2]
    assert summary["removed"] == 1 and summary["changed"] == 1 and walk.run_id == "run-2"
    with sessions() as s:
        canister = s.get(Canister, cid(1))
        assert canister is not None and canister.module_hash == "bb"


# --- canister inspect ---------------------------------------------------------------

runner = CliRunner()
TDTQY, CJN37 = SEED_CANISTERS


def _inspect(*args: str, env: dict[str, str] | None = None) -> Any:
    return runner.invoke(app, ["canister", "inspect", *args], env=env, terminal_width=200)


def test_inspect_offline_from_cassettes(tmp_path: Path) -> None:
    env = {"ICP_THREAT_INTEL_DATABASE_URL": f"sqlite:///{tmp_path / 'absent.db'}"}
    result = _inspect(TDTQY, "--offline", env=env)
    assert result.exit_code == 0, result.output
    out = result.output
    for needle in ("module hash:", "controllers:", "status:", "update_link", "query", "SYNTHETIC",
                   "raw.icp0.io", "class=url", "unverified:no_bls"):  # fmt: skip
        assert needle in out, needle
    assert not (tmp_path / "absent.db").exists()  # offline inspect never creates a database
    other = _inspect(CJN37, "--offline", env=env)
    assert other.exit_code == 0 and "candid:       absent" in other.output


def test_inspect_prefers_the_raw_store(sessions: sessionmaker[Session], tmp_path: Path) -> None:
    from icp_threat_intel.collectors.dashboard import DashboardCollector
    from icp_threat_intel.collectors.runner import collect_into
    from tests.collectors import _dashboard_cassettes as dash

    collector = DashboardCollector(http_client(dash.DashboardReplay(dash.load_all())))
    collect_into(collector, SqlRawStore(sessions), [TDTQY])
    env = {"ICP_THREAT_INTEL_DATABASE_URL": f"sqlite:///{tmp_path / 'census.db'}"}
    result = _inspect(TDTQY, "--offline", env=env)
    assert result.exit_code == 0, result.output
    assert "data:         raw store" in result.output
    assert "[dashboard_api]" in result.output and "candid:       not read" in result.output


@pytest.mark.parametrize(
    ("args", "code", "message"),
    [
        (["not-a-canister", "--offline"], 2, "not a canister id"),
        ([TDTQY], 2, "ICP_THREAT_INTEL_CONTACT"),
        ([cid(42), "--offline"], 1, "no offline data"),
    ],
)
def test_inspect_errors(tmp_path: Path, args: list[str], code: int, message: str) -> None:
    env = {
        "ICP_THREAT_INTEL_DATABASE_URL": f"sqlite:///{tmp_path / 'absent.db'}",
        "ICP_THREAT_INTEL_CONTACT": "",
    }
    result = _inspect(*args, env=env)
    assert result.exit_code == code and message in result.output


def test_inspect_survives_a_database_without_tables(tmp_path: Path) -> None:
    empty = tmp_path / "empty.db"
    empty.write_bytes(b"")
    result = _inspect(
        TDTQY, "--offline", env={"ICP_THREAT_INTEL_DATABASE_URL": f"sqlite:///{empty}"}
    )
    assert result.exit_code == 0 and "cassettes" in result.output


def test_census_payload_is_json_serialisable(sessions: sessionmaker[Session]) -> None:
    run_census(sessions, _walker(sessions, dashboard({S1: [item(1, S1)]})[0]))
    for row in _events(sessions, "census.run_completed"):
        json.dumps(row.payload)
