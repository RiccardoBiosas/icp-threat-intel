"""Live ``canister inspect``: collectors run into the raw store (network mocked by respx)."""

from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
import respx
from sqlalchemy import func, select
from typer.testing import CliRunner

from icp_threat_intel.cli.app import app
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import RawSnapshotRow
from icp_threat_intel.db.session import make_engine, make_session_factory
from tests.collectors import _cassettes as rs
from tests.collectors import _dashboard_cassettes as dash
from tests.collectors import _gateway_cassettes as gw

TDTQY = rs.SEED_CANISTERS[0]
runner = CliRunner()


@pytest.fixture
def db(tmp_path: Path) -> Iterator[str]:
    url = f"sqlite:///{tmp_path / 'live.db'}"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    engine.dispose()
    yield url


@pytest.fixture
def mocked_ic() -> Iterator[respx.MockRouter]:
    read_state = rs.ReplayTransport(
        {
            (d["metadata"]["canister_id"], d["metadata"]["request"]): d
            for d in (rs.load(p) for p in sorted(rs.CASSETTES.glob("read_state_*.json")))
        }
    )
    gateway = gw.GatewayReplay(gw.load_all())
    dashboard = dash.DashboardReplay(dash.load_all())

    def icp_api(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/read_state"):
            return read_state.handle_request(request)
        return gateway.handle_request(request)

    with respx.mock(assert_all_called=False) as router:
        router.route(host="icp-api.io").mock(side_effect=icp_api)
        router.route(host__regex=r".*\.raw\.(icp0\.io|ic0\.app)$").mock(
            side_effect=gateway.handle_request
        )
        router.route(host="ic-api.internetcomputer.org").mock(side_effect=dashboard.handle_request)
        yield router


def _env(db: str, contact: str = "test@example.invalid") -> dict[str, str]:
    return {"ICP_THREAT_INTEL_DATABASE_URL": db, "ICP_THREAT_INTEL_CONTACT": contact}


def test_live_inspect_collects_then_renders(db: str, mocked_ic: respx.MockRouter) -> None:
    result = runner.invoke(app, ["canister", "inspect", TDTQY], env=_env(db), terminal_width=200)
    assert result.exit_code == 0, result.output
    assert "data:         raw store" in result.output
    assert "module hash:" in result.output and "update_link" in result.output
    engine = make_engine(db)
    with make_session_factory(engine)() as s:
        stored = s.scalar(select(func.count()).select_from(RawSnapshotRow))
    engine.dispose()
    assert stored == 2 + 3 + 2  # read_state state/candid, gateway pre-check + 2 GETs, dashboard
    hosts = {call.request.url.host for call in mocked_ic.calls}
    assert hosts == {
        "icp-api.io", f"{TDTQY}.raw.icp0.io", f"{TDTQY}.raw.ic0.app",
        "ic-api.internetcomputer.org",
    }  # fmt: skip


def test_live_inspect_reports_a_failing_source_and_keeps_going(db: str) -> None:
    dashboard = dash.DashboardReplay(dash.load_all())
    with respx.mock(assert_all_called=False) as router:
        router.route(host="icp-api.io").mock(side_effect=httpx.ConnectError("down"))
        router.route(host__regex=r".*\.raw\..*").mock(side_effect=httpx.ConnectError("down"))
        router.route(host="ic-api.internetcomputer.org").mock(side_effect=dashboard.handle_request)
        result = runner.invoke(
            app, ["canister", "inspect", TDTQY], env=_env(db), terminal_width=200
        )
    assert result.exit_code == 0, result.output
    assert "ic_read_state: collection failed" in result.output
    assert "raw_gateway: collection failed" in result.output
    assert "[dashboard_api]" in result.output


def test_live_inspect_needs_contact(db: str) -> None:
    result = runner.invoke(app, ["canister", "inspect", TDTQY], env=_env(db, contact=""))
    assert result.exit_code == 2 and "ICP_THREAT_INTEL_CONTACT" in result.output


def test_live_inspect_without_tables_asks_for_migration(tmp_path: Path) -> None:
    empty = tmp_path / "empty.db"
    empty.write_bytes(b"")
    with respx.mock(assert_all_called=False):
        result = runner.invoke(
            app, ["canister", "inspect", TDTQY], env=_env(f"sqlite:///{empty}"), terminal_width=200
        )
    assert result.exit_code == 1 and "make migrate" in result.output
