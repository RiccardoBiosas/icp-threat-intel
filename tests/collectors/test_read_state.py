"""read_state collector: cassette replay, raw storage, parsing into events and snapshots."""

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import cbor2
import httpx
import pytest
from sqlalchemy import Engine

from icp_threat_intel.collectors.read_state import ReadStateCollector, canister_paths
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.http import SafeHttpClient
from icp_threat_intel.core.ic_client import IcClient
from icp_threat_intel.core.ic_encoding import principal_to_text
from icp_threat_intel.core.interfaces import Collector, Parser
from icp_threat_intel.core.models import RawFetch
from icp_threat_intel.core.ratelimit import HostRateLimiter
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.session import make_engine, make_session_factory
from icp_threat_intel.parsers.read_state import ReadStateParser
from icp_threat_intel.raw_store.store import SqlRawStore
from tests.collectors import _cassettes as cas

T0 = datetime(2026, 10, 15, 6, 0, tzinfo=UTC)
TDTQY, CJN37 = cas.SEED_CANISTERS
CONTACT = "test@example.invalid"


def _cassettes() -> dict[tuple[str, str], dict[str, Any]]:
    out = {}
    for path in sorted(cas.CASSETTES.glob("read_state_*.json")):
        data = cas.load(path)
        meta = data["metadata"]
        out[(meta["canister_id"], meta["request"])] = data
    return out


def _http(transport: httpx.BaseTransport) -> SafeHttpClient:
    limiter = HostRateLimiter(rate_per_second=1000.0, burst=1000, sleep=lambda _s: None)
    return SafeHttpClient(CONTACT, transport=transport, limiter=limiter, sleep=lambda _s: None)


def _collector(transport: httpx.BaseTransport, *, synthetic: bool = True) -> ReadStateCollector:
    return ReadStateCollector(IcClient(_http(transport)), clock=lambda: T0, synthetic=synthetic)


@pytest.fixture
def engine() -> Iterator[Engine]:
    eng = make_engine("sqlite://")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def replay() -> cas.ReplayTransport:
    return cas.ReplayTransport(_cassettes())


@pytest.fixture
def fetches(replay: cas.ReplayTransport) -> list[RawFetch]:
    return list(_collector(replay).collect(list(cas.SEED_CANISTERS)))


def _parsed(engine: Engine, fetches: list[RawFetch]) -> dict[tuple[str, str], Any]:
    store = SqlRawStore(make_session_factory(engine))
    parser = ReadStateParser()
    out = {}
    for fetch in fetches:
        snapshot = store.get(store.save(fetch).id)
        out[(fetch.request_meta["canister_id"], fetch.request_meta["request"])] = parser.parse(
            snapshot
        )
    return out


def test_cassettes_exist_for_both_seed_canisters_with_metadata() -> None:
    cassettes = _cassettes()
    assert set(cassettes) == {(c, r) for c in cas.SEED_CANISTERS for r in ("state", "candid")}
    for (canister_id, request), data in cassettes.items():
        meta = data["metadata"]
        assert isinstance(meta["synthetic"], bool)
        assert meta["url"] == f"https://icp-api.io/api/v3/canister/{canister_id}/read_state"
        assert meta["paths"] and meta["recorded_at"] and meta["note"]
        assert cas.cassette_path(canister_id, request).exists()


def test_collector_satisfies_protocols() -> None:
    assert isinstance(_collector(cas.ReplayTransport({})), Collector)
    assert isinstance(ReadStateParser(), Parser)


def test_collector_sends_two_anonymous_v3_read_state_requests_per_canister(
    replay: cas.ReplayTransport, fetches: list[RawFetch]
) -> None:
    assert len(replay.requests) == 4
    for request in replay.requests:
        assert request.method == "POST"
        assert request.url.host == "icp-api.io"
        assert request.url.path.startswith("/api/v3/canister/")
        assert request.url.path.endswith("/read_state")
        assert request.headers["content-type"] == "application/cbor"
    assert [(f.request_meta["canister_id"], f.request_meta["request"]) for f in fetches] == [
        (TDTQY, "state"),
        (TDTQY, "candid"),
        (CJN37, "state"),
        (CJN37, "candid"),
    ]


def test_candid_request_is_sent_alone(replay: cas.ReplayTransport) -> None:
    list(_collector(replay).collect([TDTQY]))
    content = cas.decode_cbor(replay.requests[1].read())["content"]
    assert [list(p) for p in content["paths"]] == canister_paths(TDTQY, "candid")
    assert len(content["paths"]) == 1


def test_raw_fetch_holds_certificate_and_provenance(fetches: list[RawFetch]) -> None:
    fetch = fetches[0]
    assert fetch.source_type is SourceType.IC_READ_STATE
    assert fetch.http_status == 200
    assert fetch.synthetic is True
    assert fetch.fetched_at == T0
    assert fetch.url.endswith(f"/api/v3/canister/{TDTQY}/read_state#state")
    assert fetch.request_meta["paths"] == ["module_hash", "controllers"]
    cassette = _cassettes()[(TDTQY, "state")]
    assert fetch.body == bytes(cas.decode_cbor(cas.response_body(cassette))["certificate"])


def test_state_snapshot_has_module_hash_and_controllers(
    engine: Engine, fetches: list[RawFetch]
) -> None:
    result = _parsed(engine, fetches)[(TDTQY, "state")]
    (snapshot,) = result.canister_snapshots
    expected_hash = cas.hashlib.sha256(f"synthetic:module:{TDTQY}".encode()).hexdigest()
    assert snapshot.module_hash == expected_hash
    controller = principal_to_text(cas.synthetic_principal(f"controller:{TDTQY}"))
    assert snapshot.controllers == (controller,)
    assert snapshot.raw_snapshot_id is not None
    (event,) = result.events
    assert event.kind == "canister.state_read"
    assert event.payload["status"] == "ok"
    assert event.payload["verification"] == "unverified:no_bls"
    assert event.payload["cert_time"] == cas.SYNTHETIC_TIME.isoformat()
    assert event.payload["synthetic"] is True


def test_candid_is_parsed_with_query_and_update_annotation(
    engine: Engine, fetches: list[RawFetch]
) -> None:
    result = _parsed(engine, fetches)[(TDTQY, "candid")]
    assert result.canister_snapshots == ()
    (event,) = result.events
    assert event.kind == "canister.candid_read"
    assert event.payload["status"] == "ok"
    assert len(event.payload["candid_sha256"]) == 64
    methods = {m["name"]: m for m in event.payload["candid_methods"]}
    assert methods["get_latest_link"] == {
        "name": "get_latest_link",
        "args": [],
        "rets": ["text"],
        "mode": "query",
    }
    assert methods["update_link"]["mode"] == "update"
    assert methods["update_link"]["args"] == ["text"]
    assert methods["http_request"]["args"] == ["HttpRequest"]
    assert methods["http_request"]["mode"] == "query"


def test_missing_candid_section_is_reported_absent(engine: Engine, fetches: list[RawFetch]) -> None:
    (event,) = _parsed(engine, fetches)[(CJN37, "candid")].events
    assert event.payload["status"] == "absent"
    assert "candid_methods" not in event.payload


def test_rejected_candid_read_is_stored_as_evidence(engine: Engine) -> None:
    cassettes = _cassettes()

    def handler(request: httpx.Request) -> httpx.Response:
        content = cas.decode_cbor(request.read())["content"]
        if cas.request_kind(content["paths"]) == "candid":
            return httpx.Response(403, content=b"not authorized to read path")
        cassette = cassettes[(TDTQY, "state")]
        return httpx.Response(200, content=cas.response_body(cassette))

    fetches = list(_collector(httpx.MockTransport(handler)).collect([TDTQY]))
    candid = fetches[1]
    assert candid.http_status == 403
    assert candid.body == b"not authorized to read path"
    assert "403" in candid.request_meta["error"]
    (event,) = _parsed(engine, fetches)[(TDTQY, "candid")].events
    assert event.payload["status"] == "unreadable"
    assert event.payload["http_status"] == 403


def test_malformed_certificate_does_not_crash_the_parser(engine: Engine) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        body = cbor2.dumps(cbor2.CBORTag(55799, {"certificate": b"\xa1\x01\x02"}))
        return httpx.Response(200, content=body)

    fetches = list(_collector(httpx.MockTransport(handler)).collect([CJN37]))
    for result in _parsed(engine, fetches).values():
        assert result.events[0].payload["status"] == "malformed_certificate"
        assert result.canister_snapshots == ()


def test_parsing_is_deterministic(engine: Engine, fetches: list[RawFetch]) -> None:
    assert _parsed(engine, fetches) == _parsed(engine, fetches)


def test_management_canister_is_refused_before_any_request() -> None:
    replay = cas.ReplayTransport({})
    with pytest.raises(ValueError, match="management canister"):
        list(_collector(replay).collect(["aaaaa-aa"]))
    assert replay.requests == []
