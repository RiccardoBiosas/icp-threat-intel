"""Edge cases in the coverage-gated modules: IC client, raw store race, cassette loader, rules."""

import base64
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import cbor2
import httpx
import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.ic_client import IcClient, IcHttpError
from icp_threat_intel.core.models import RawFetch
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.session import make_engine, make_session_factory
from icp_threat_intel.raw_store import cassettes
from icp_threat_intel.raw_store.store import SqlRawStore
from icp_threat_intel.rules.base import BaseRule
from icp_threat_intel.rules.h4_cycles_funding import H4CyclesFunding
from tests.collectors import _gateway_cassettes as gw
from tests.parsers.conftest import http_client

CANISTER = "tdtqy-oyaaa-aaaae-af2dq-cai"


def _client(body: bytes) -> IcClient:
    return IcClient(http_client(httpx.MockTransport(lambda _r: httpx.Response(200, content=body))))


# --- IC client ------------------------------------------------------------------------


def test_query_with_unexpected_status_raises() -> None:
    body = cbor2.dumps(cbor2.CBORTag(55799, {"status": "processing"}))
    with pytest.raises(IcHttpError, match="unexpected query status"):
        _client(body).query(CANISTER, "get_link", b"DIDL\x00\x00")


def test_non_map_cbor_body_raises() -> None:
    with pytest.raises(IcHttpError, match="non-map"):
        _client(cbor2.dumps([1, 2, 3])).read_state(CANISTER, [[b"time"]])


# --- raw store: a concurrent writer stored the same content first ---------------------


@pytest.fixture
def sessions() -> Iterator[sessionmaker[Session]]:
    engine = make_engine("sqlite://")
    Base.metadata.create_all(engine)
    yield make_session_factory(engine)
    engine.dispose()


def _fetch() -> RawFetch:
    return RawFetch(
        source_type=SourceType.RAW_GATEWAY,
        source_name="raw_gateway",
        url=f"https://{CANISTER}.raw.icp0.io/",
        fetched_at=datetime(2026, 10, 15, tzinfo=UTC),
        body=b"https://example.invalid/x\n",
    )


def test_race_returns_the_row_the_other_writer_stored(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SqlRawStore(sessions)
    first = store.save(_fetch())
    real_find = SqlRawStore._find
    calls: list[int] = []

    def racy_find(session: Session, source_id: int, url: str, sha256: str) -> int | None:
        calls.append(1)
        # The first lookup misses (the other writer has not committed yet); the second sees it.
        return None if len(calls) == 1 else real_find(session, source_id, url, sha256)

    monkeypatch.setattr(SqlRawStore, "_find", staticmethod(racy_find))
    again = store.save(_fetch())
    assert again.id == first.id and again.created is False and len(calls) == 2


def test_race_without_a_visible_row_reraises(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SqlRawStore(sessions)
    store.save(_fetch())
    monkeypatch.setattr(SqlRawStore, "_find", staticmethod(lambda *_a: None))
    with pytest.raises(IntegrityError):
        store.save(_fetch())


# --- cassette loader branches ---------------------------------------------------------


def _write(tmp_path: Path, source: str, request: str, status: int, body: bytes) -> Path:
    path = tmp_path / f"x_{CANISTER}_{request}.json"
    data: dict[str, Any] = {
        "metadata": {"synthetic": True, "source": source, "canister_id": CANISTER,
                     "request": request, "url": "https://icp-api.io/api/v2/canister/x/query",
                     "recorded_at": "2026-10-15T00:00:00+00:00"},
        "response": {"status_code": status, "headers": {},
                     "body_b64": base64.b64encode(body).decode()},
    }  # fmt: skip
    path.write_text(json.dumps(data))
    return path


@pytest.mark.parametrize(
    ("status", "body", "outcome"),
    [
        (500, b"upstream", "http_error"),
        (
            200,
            cbor2.dumps({"status": "rejected", "reject_code": 3, "reject_message": "no"}),
            "rejected",
        ),
        (200, gw.query_reply(b"not candid"), "undecodable"),
        (200, gw.query_reply(gw.encode_http_response(200, [], b"x", True)), "upgrade_requested"),
    ],
)
def test_precheck_cassette_outcomes(tmp_path: Path, status: int, body: bytes, outcome: str) -> None:
    snap = cassettes.cassette_snapshot(
        _write(tmp_path, "raw_gateway", "http_request_query", status, body), -1
    )
    assert snap is not None and snap.request_meta["outcome"] == outcome


def test_unknown_cassette_source_is_ignored(tmp_path: Path) -> None:
    path = _write(tmp_path, "somewhere_else", "x", 200, b"{}")
    assert cassettes.cassette_snapshot(path, -1) is None
    assert cassettes.snapshots_for(tmp_path, CANISTER) == []


# --- rule base hooks ------------------------------------------------------------------


def test_base_rule_hooks_must_be_implemented() -> None:
    rule = BaseRule()
    with pytest.raises(NotImplementedError):
        rule.signals([])
    with pytest.raises(NotImplementedError):
        rule.assess({})


def test_stub_rule_has_no_signals() -> None:
    assert H4CyclesFunding().signals([]) == {}
