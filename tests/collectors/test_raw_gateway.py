"""Raw gateway fetcher: cassette replay, size cap, timeout, redirect refusal, upgrade guard."""

from collections.abc import Callable, Iterator
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import Engine

from icp_threat_intel.collectors.raw_gateway import DOMAINS, RawGatewayCollector
from icp_threat_intel.collectors.runner import collect_into
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.http import MAX_BODY_BYTES, SafeHttpClient
from icp_threat_intel.core.ic_client import IcClient
from icp_threat_intel.core.interfaces import Collector
from icp_threat_intel.core.models import RawFetch
from icp_threat_intel.core.ratelimit import HostRateLimiter
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.session import make_engine, make_session_factory
from icp_threat_intel.raw_store.store import SqlRawStore
from tests.collectors import _gateway_cassettes as gw
from tests.collectors._cassettes import SEED_CANISTERS, decode_cbor

T0 = datetime(2026, 10, 15, 6, 0, tzinfo=UTC)
TDTQY, CJN37 = SEED_CANISTERS
Handler = Callable[[httpx.Request], httpx.Response]


def _collector(transport: httpx.BaseTransport) -> RawGatewayCollector:
    limiter = HostRateLimiter(rate_per_second=1000.0, burst=1000, sleep=lambda _s: None)
    http = SafeHttpClient(
        "test@example.invalid", transport=transport, limiter=limiter, sleep=lambda _s: None
    )
    return RawGatewayCollector(http, IcClient(http), clock=lambda: T0, synthetic=True)


def _gateway(get: Handler, *, upgrade: bool | None = None) -> httpx.MockTransport:
    """Pre-check replies 200 with ``upgrade``; GETs go to ``get``."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "icp-api.io":
            candid = gw.encode_http_response(200, [], b"x", upgrade)
            return httpx.Response(200, content=gw.query_reply(candid))
        return get(request)

    return httpx.MockTransport(handler)


@pytest.fixture
def engine() -> Iterator[Engine]:
    eng = make_engine("sqlite://")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def replay() -> gw.GatewayReplay:
    return gw.GatewayReplay(gw.load_all())


def _gets(fetches: list[RawFetch]) -> list[RawFetch]:
    return [f for f in fetches if f.request_meta["request"] == "get"]


def test_cassettes_exist_for_both_seed_canisters() -> None:
    cassettes = gw.load_all()
    expected = {(c, r) for c in SEED_CANISTERS for r in (gw.PRECHECK, *DOMAINS)}
    assert set(cassettes) == expected
    for data in cassettes.values():
        meta = data["metadata"]
        assert isinstance(meta["synthetic"], bool)
        assert meta["url"].startswith("https://") and meta["recorded_at"] and meta["note"]


def test_collector_protocol() -> None:
    assert isinstance(_collector(gw.GatewayReplay({})), Collector)


def test_fetches_both_raw_domains_after_query_precheck(replay: gw.GatewayReplay) -> None:
    fetches = list(_collector(replay).collect(list(SEED_CANISTERS)))
    assert [(f.request_meta["canister_id"], f.request_meta["request"]) for f in fetches] == [
        (c, r) for c in SEED_CANISTERS for r in ("http_request_query", "get", "get")
    ]
    urls = [f.url for f in _gets(fetches)]
    assert urls == [f"https://{c}.{d}/" for c in SEED_CANISTERS for d in DOMAINS]
    methods = {(r.method, r.url.host == "icp-api.io") for r in replay.requests}
    assert methods == {("POST", True), ("GET", False)}
    precheck = decode_cbor(replay.requests[0].read())["content"]
    assert precheck["request_type"] == "query"
    assert precheck["method_name"] == "http_request"
    assert precheck["sender"] == b"\x04"


def test_bodies_are_stored_verbatim_through_raw_store(
    engine: Engine, replay: gw.GatewayReplay
) -> None:
    store = SqlRawStore(make_session_factory(engine))
    refs = collect_into(_collector(replay), store, [TDTQY, CJN37])
    assert len(refs) == 6 and all(r.created for r in refs)
    snapshots = [store.get(r.id) for r in refs]
    tdtqy_get = snapshots[1]
    assert tdtqy_get.source_type is SourceType.RAW_GATEWAY
    assert tdtqy_get.body == gw.SYNTHETIC_BODIES[TDTQY][1]
    assert tdtqy_get.http_status == 200
    assert tdtqy_get.synthetic is True
    assert tdtqy_get.url == f"https://{TDTQY}.raw.icp0.io/"
    assert snapshots[4].http_status == 404
    assert snapshots[0].request_meta["outcome"] == "ok"
    assert snapshots[0].request_meta["upgrade"] is None
    assert snapshots[0].request_meta["response_status_code"] == 200


def test_body_over_one_megabyte_is_capped_and_flagged() -> None:
    big = b"A" * (MAX_BODY_BYTES + 4096)
    fetches = list(
        _collector(_gateway(lambda _r: httpx.Response(200, content=big))).collect([TDTQY])
    )
    for fetch in _gets(fetches):
        assert fetch.truncated is True
        assert len(fetch.body) == MAX_BODY_BYTES == 1024 * 1024


def test_timeout_is_recorded_not_raised() -> None:
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    collector = _collector(_gateway(slow))
    fetches = list(collector.collect([TDTQY]))
    for fetch in _gets(fetches):
        assert fetch.request_meta["outcome"] == "timeout"
        assert fetch.request_meta["timeout_seconds"] == 10.0
        assert fetch.body == b"" and fetch.http_status is None


@pytest.mark.parametrize(
    "location",
    ["https://evil.example/stage2", "http://x.raw.icp0.io/", "https://pypi.org/simple/"],
)
def test_redirect_off_ic_domains_is_refused_and_recorded(location: str) -> None:
    seen: list[str] = []

    def get(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(302, headers={"Location": location})

    fetches = list(_collector(_gateway(get)).collect([TDTQY]))
    for fetch in _gets(fetches):
        assert fetch.request_meta["outcome"] == "redirect_refused"
        assert fetch.request_meta["location"] == location
    assert all(".raw." in url for url in seen) and len(seen) == 2


def test_only_one_redirect_hop_within_ic_domains() -> None:
    def get(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(308, headers={"Location": f"https://{TDTQY}.icp0.io/a"})
        if request.url.path == "/a":
            return httpx.Response(302, headers={"Location": f"https://{TDTQY}.icp0.io/b"})
        return httpx.Response(200, content=b"never")

    fetches = _gets(list(_collector(_gateway(get)).collect([TDTQY])))
    assert [f.request_meta["outcome"] for f in fetches] == ["too_many_redirects"] * 2

    def one_hop(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(308, headers={"Location": f"https://{TDTQY}.icp0.io/a"})
        return httpx.Response(200, content=b"moved")

    fetch = _gets(list(_collector(_gateway(one_hop)).collect([TDTQY])))[0]
    assert fetch.body == b"moved"
    assert fetch.request_meta["redirects"] == [f"https://{TDTQY}.icp0.io/a"]


@pytest.mark.parametrize("upgrade", [True])
def test_upgrade_request_skips_the_gateway_get(upgrade: bool) -> None:
    gets: list[httpx.Request] = []

    def get(request: httpx.Request) -> httpx.Response:
        gets.append(request)
        return httpx.Response(200)

    fetches = list(_collector(_gateway(get, upgrade=upgrade)).collect([TDTQY]))
    assert gets == []
    assert len(fetches) == 1
    assert fetches[0].request_meta["outcome"] == "upgrade_requested"


def test_explicit_upgrade_false_still_fetches() -> None:
    fetches = list(
        _collector(_gateway(lambda _r: httpx.Response(200), upgrade=False)).collect([TDTQY])
    )
    assert len(_gets(fetches)) == 2


def test_rejected_or_failed_precheck_skips_the_get() -> None:
    def reject(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "icp-api.io", "no GET may follow a rejected pre-check"
        body = {"status": "rejected", "reject_code": 3, "reject_message": "no http_request"}
        return httpx.Response(200, content=gw.cbor2.dumps(body))

    (fetch,) = list(_collector(httpx.MockTransport(reject)).collect([CJN37]))
    assert fetch.request_meta["outcome"] == "rejected"
    assert fetch.request_meta["reject_code"] == 3
    assert fetch.body == b"no http_request"

    def http_error(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "icp-api.io"
        return httpx.Response(400, content=b"bad request")

    (fetch,) = list(_collector(httpx.MockTransport(http_error)).collect([CJN37]))
    assert fetch.request_meta["outcome"] == "http_error"
    assert fetch.http_status == 400

    def garbage(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "icp-api.io"
        return httpx.Response(200, content=gw.query_reply(b"not candid"))

    (fetch,) = list(_collector(httpx.MockTransport(garbage)).collect([CJN37]))
    assert fetch.request_meta["outcome"] == "undecodable"


@pytest.mark.parametrize("target", ["aaaaa-aa", "evil.example#", "tdtqy-oyaaa-aaaae-af2dq-caj"])
def test_invalid_targets_are_refused_before_any_request(target: str) -> None:
    replay = gw.GatewayReplay({})
    with pytest.raises(ValueError):
        list(_collector(replay).collect([target]))
    assert replay.requests == []
