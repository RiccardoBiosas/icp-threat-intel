"""Dashboard API collector: canister metadata, subnet membership and controllers."""

import base64
import json
from collections.abc import Iterator
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import Engine

from icp_threat_intel.collectors.dashboard import (
    DashboardCollector,
    canister_url,
    extract_canister,
    extract_subnet,
    subnet_url,
)
from icp_threat_intel.collectors.runner import collect_into
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.http import HostNotAllowed, SafeHttpClient
from icp_threat_intel.core.ic_encoding import principal_to_text
from icp_threat_intel.core.interfaces import Collector
from icp_threat_intel.core.ratelimit import HostRateLimiter
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.session import make_engine, make_session_factory
from icp_threat_intel.raw_store.store import SqlRawStore
from tests.collectors import _dashboard_cassettes as dash
from tests.collectors._cassettes import SEED_CANISTERS, synthetic_principal

T0 = datetime(2026, 10, 15, 6, 0, tzinfo=UTC)
TDTQY, CJN37 = SEED_CANISTERS


def _collector(transport: httpx.BaseTransport) -> DashboardCollector:
    limiter = HostRateLimiter(rate_per_second=1000.0, burst=1000, sleep=lambda _s: None)
    http = SafeHttpClient(
        "test@example.invalid", transport=transport, limiter=limiter, sleep=lambda _s: None
    )
    return DashboardCollector(http, clock=lambda: T0, synthetic=True)


@pytest.fixture
def replay() -> dash.DashboardReplay:
    return dash.DashboardReplay(dash.load_all())


@pytest.fixture
def engine() -> Iterator[Engine]:
    eng = make_engine("sqlite://")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


def test_cassettes_exist_for_both_seed_canisters() -> None:
    for canister_id in SEED_CANISTERS:
        for request in ("canister", "subnet"):
            meta = dash.load(dash.cassette_path(canister_id, request))["metadata"]
            assert isinstance(meta["synthetic"], bool)
            assert meta["url"].startswith("https://ic-api.internetcomputer.org/api/")
            assert meta["recorded_at"] and meta["note"]


def test_collector_protocol() -> None:
    assert isinstance(_collector(dash.DashboardReplay({})), Collector)


def test_collects_canister_then_its_subnet(replay: dash.DashboardReplay) -> None:
    fetches = list(_collector(replay).collect(list(SEED_CANISTERS)))
    assert [f.url for f in fetches] == [
        url
        for c in SEED_CANISTERS
        for url in (canister_url(c), subnet_url(dash.synthetic_subnet(c)))
    ]
    assert all(r.method == "GET" for r in replay.requests)
    assert {r.url.host for r in replay.requests} == {"ic-api.internetcomputer.org"}
    assert [f.request_meta["request"] for f in fetches] == ["canister", "subnet"] * 2
    for fetch in fetches:
        assert fetch.source_type is SourceType.DASHBOARD_API
        assert fetch.http_status == 200 and fetch.synthetic is True and fetch.fetched_at == T0


def test_canister_metadata_subnet_and_controllers(replay: dash.DashboardReplay) -> None:
    fetches = list(_collector(replay).collect([TDTQY]))
    canister = extract_canister(fetches[0].body)
    assert canister is not None
    assert canister.canister_id == TDTQY
    assert canister.subnet_id == dash.synthetic_subnet(TDTQY)
    controller = principal_to_text(synthetic_principal(f"controller:{TDTQY}"))
    assert canister.controllers == (controller,)
    assert canister.module_hash == "ab" * 32
    assert canister.canister_type == "dapp"
    assert canister.language is None and canister.name is None
    subnet = extract_subnet(fetches[1].body)
    assert subnet is not None
    assert subnet.subnet_id == canister.subnet_id
    assert (subnet.total_canisters, subnet.running_canisters, subnet.stopped_canisters) == (
        1000,
        990,
        10,
    )
    assert subnet.subnet_type == "application"


def test_missing_fields_stay_none_instead_of_guessed(replay: dash.DashboardReplay) -> None:
    canister = extract_canister(next(iter(_collector(replay).collect([CJN37]))).body)
    assert canister is not None
    assert canister.module_hash is None


def test_bodies_stored_through_raw_store(engine: Engine, replay: dash.DashboardReplay) -> None:
    store = SqlRawStore(make_session_factory(engine))
    refs = collect_into(_collector(replay), store, list(SEED_CANISTERS))
    assert len(refs) == 4
    snapshot = store.get(refs[0].id)
    assert snapshot.body == base64_body(canister_url(TDTQY))
    assert snapshot.request_meta["canister_id"] == TDTQY


def base64_body(url: str) -> bytes:
    return base64.b64decode(dash.load_all()[url]["response"]["body_b64"])


def test_not_found_is_stored_and_no_subnet_requested() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.startswith("/api/v3/canisters/")
        return httpx.Response(404, json={"code": 404, "message": "not found"})

    (fetch,) = list(_collector(httpx.MockTransport(handler)).collect([CJN37]))
    assert fetch.http_status == 404
    assert json.loads(fetch.body)["code"] == 404


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"[]",
        b"{}",
        json.dumps({"canister_id": "nonsense"}).encode(),
        b"\xff\xfe",
    ],
)
def test_unusable_canister_bodies(body: bytes) -> None:
    assert extract_canister(body) is None


def test_defensive_field_parsing() -> None:
    body = {
        "canister_id": TDTQY,
        "subnet_id": 42,
        "controllers": [CJN37, "garbage", 7],
        "module_hash": "",
        "canister_type": ["dapp"],
    }
    canister = extract_canister(json.dumps(body).encode())
    assert canister is not None
    assert canister.subnet_id is None
    assert canister.controllers == (CJN37,)
    assert canister.module_hash is None and canister.canister_type is None
    no_controllers = extract_canister(json.dumps({"canister_id": TDTQY}).encode())
    assert no_controllers is not None and no_controllers.controllers is None


def test_subnet_counts_parse_defensively() -> None:
    subnet_id = dash.synthetic_subnet(TDTQY)
    body = {"subnet_id": subnet_id, "total_canisters": 5, "running_canisters": True}
    subnet = extract_subnet(json.dumps(body).encode())
    assert subnet is not None
    assert subnet.total_canisters == 5 and subnet.running_canisters is None
    assert subnet.stopped_canisters is None
    assert extract_subnet(b"{}") is None and extract_subnet(b"nope") is None


@pytest.mark.parametrize("target", ["not-a-principal", "evil.example/x"])
def test_invalid_targets_refused_before_any_request(target: str) -> None:
    replay = dash.DashboardReplay({})
    with pytest.raises(ValueError):
        list(_collector(replay).collect([target]))
    assert replay.requests == []


def test_cross_host_redirect_is_refused() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://evil.example/"})

    with pytest.raises(HostNotAllowed):
        list(_collector(httpx.MockTransport(handler)).collect([TDTQY]))
