"""Raw snapshots for parser tests: every T07-T09 cassette, collected into a SQLite raw store."""

from collections.abc import Iterator
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from icp_threat_intel.collectors.dashboard import DashboardCollector
from icp_threat_intel.collectors.raw_gateway import RawGatewayCollector
from icp_threat_intel.collectors.read_state import ReadStateCollector
from icp_threat_intel.collectors.runner import collect_into
from icp_threat_intel.core.http import SafeHttpClient
from icp_threat_intel.core.ic_client import IcClient
from icp_threat_intel.core.models import RawSnapshot
from icp_threat_intel.core.ratelimit import HostRateLimiter
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.session import make_engine, make_session_factory
from icp_threat_intel.raw_store.store import SqlRawStore
from tests.collectors import _cassettes as rs
from tests.collectors import _dashboard_cassettes as dash
from tests.collectors import _gateway_cassettes as gw

T0 = datetime(2026, 10, 15, 6, 0, tzinfo=UTC)


def http_client(transport: httpx.BaseTransport) -> SafeHttpClient:
    limiter = HostRateLimiter(rate_per_second=1000.0, burst=1000, sleep=lambda _s: None)
    return SafeHttpClient(
        "test@example.invalid", transport=transport, limiter=limiter, sleep=lambda _s: None
    )


@pytest.fixture
def engine() -> Iterator[Engine]:
    eng = make_engine("sqlite://")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def sessions(engine: Engine) -> sessionmaker[Session]:
    return make_session_factory(engine)


@pytest.fixture
def store(sessions: sessionmaker[Session]) -> SqlRawStore:
    return SqlRawStore(sessions)


def collect_all(store: SqlRawStore) -> list[RawSnapshot]:
    """Run the three collectors over their cassettes and return the stored snapshots."""
    targets = list(rs.SEED_CANISTERS)
    read_state = rs.ReplayTransport(
        {
            (d["metadata"]["canister_id"], d["metadata"]["request"]): d
            for d in (rs.load(p) for p in sorted(rs.CASSETTES.glob("read_state_*.json")))
        }
    )
    gateway_http = http_client(gw.GatewayReplay(gw.load_all()))
    collectors = [
        ReadStateCollector(IcClient(http_client(read_state)), clock=lambda: T0, synthetic=True),
        RawGatewayCollector(gateway_http, IcClient(gateway_http), clock=lambda: T0, synthetic=True),
        DashboardCollector(
            http_client(dash.DashboardReplay(dash.load_all())), clock=lambda: T0, synthetic=True
        ),
    ]
    refs = [ref for c in collectors for ref in collect_into(c, store, targets)]
    return [store.get(ref.id) for ref in refs]


@pytest.fixture
def snapshots(store: SqlRawStore) -> list[RawSnapshot]:
    return collect_all(store)
