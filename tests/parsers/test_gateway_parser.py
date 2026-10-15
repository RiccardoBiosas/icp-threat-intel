"""Raw-gateway snapshots -> gateway.http_request_queried / gateway.body_observed."""

from datetime import UTC, datetime
from typing import Any

import pytest

from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.models import RawSnapshot
from icp_threat_intel.parsers.raw_gateway import EXCERPT_CHARS, RawGatewayParser, describe_body
from tests.collectors import _gateway_cassettes as gw
from tests.collectors._cassettes import SEED_CANISTERS

TDTQY, CJN37 = SEED_CANISTERS


def _gateway(snapshots: list[RawSnapshot]) -> list[RawSnapshot]:
    return [s for s in snapshots if s.source_type is SourceType.RAW_GATEWAY]


def _snap(request_meta: dict[str, Any], **kw: Any) -> RawSnapshot:
    fields: dict[str, Any] = {
        "id": 1,
        "source_type": SourceType.RAW_GATEWAY,
        "source_name": "raw_gateway",
        "url": f"https://{TDTQY}.raw.icp0.io/",
        "fetched_at": datetime(2026, 10, 15, tzinfo=UTC),
        "sha256": "0" * 64,
        "stored_sha256": "0" * 64,
        "body": b"",
        "size_bytes": 0,
        "request_meta": {"canister_id": TDTQY, **request_meta},
    }
    fields.update(kw)
    return RawSnapshot(**fields)


def test_cassette_snapshots_parse(snapshots: list[RawSnapshot]) -> None:
    events = [e for s in _gateway(snapshots) for e in RawGatewayParser().parse(s).events]
    kinds = [(e.canister_id, e.kind) for e in events]
    expected = ["gateway.http_request_queried"] + ["gateway.body_observed"] * 2
    assert kinds == [(c, k) for c in SEED_CANISTERS for k in expected]
    tdtqy_get = events[1].payload
    assert tdtqy_get["body_class"] == "url"
    assert tdtqy_get["excerpt"] == gw.SYNTHETIC_BODIES[TDTQY][1].decode()
    assert tdtqy_get["http_status"] == 200 and tdtqy_get["denylisted"] is False
    precheck = events[0].payload
    assert precheck["outcome"] == "ok" and precheck["upgrade"] is None
    assert precheck["response_status_code"] == 200 and precheck["body_class"] == "url"
    assert events[4].payload["http_status"] == 404


def test_denylisted_answer_is_flagged() -> None:
    snap = _snap(
        {"request": "get", "domain": "raw.icp0.io", "outcome": "ok", "redirects": []},
        http_status=451,
        headers={"X-IC-Error-Cause": "denylisted"},
        body=b'{"error_type":"denylisted"}',
    )
    (event,) = RawGatewayParser().parse(snap).events
    assert event.payload["denylisted"] is True
    assert event.payload["error_cause"] == "denylisted"


@pytest.mark.parametrize("outcome", ["redirect_refused", "timeout", "too_many_redirects"])
def test_failed_gets_carry_outcome_without_body_fields(outcome: str) -> None:
    meta = {"request": "get", "domain": "raw.ic0.app", "outcome": outcome}
    if outcome == "redirect_refused":
        meta["location"] = "https://evil.example/x"
    (event,) = RawGatewayParser().parse(_snap(meta)).events
    assert event.payload["outcome"] == outcome
    assert "body_class" not in event.payload
    assert event.payload.get("location") == meta.get("location")


@pytest.mark.parametrize(
    ("meta", "body", "outcome"),
    [
        ({"outcome": "rejected", "reject_code": 3}, b"no method", "rejected"),
        ({"outcome": "ok"}, b"garbage", "undecodable"),
        ({"outcome": "upgrade_requested", "upgrade": True}, None, "upgrade_requested"),
    ],
)
def test_precheck_outcomes(meta: dict[str, Any], body: bytes | None, outcome: str) -> None:
    raw = body if body is not None else gw.encode_http_response(200, [], b"x", True)
    snap = _snap({"request": "http_request_query", **meta}, body=raw, http_status=200)
    (event,) = RawGatewayParser().parse(snap).events
    assert event.payload["outcome"] == outcome


def test_describe_body_classes_and_excerpt_cap() -> None:
    assert describe_body(b"\x00\x01binary")["body_class"] == "binary"
    assert "excerpt" not in describe_body(b"\x00\x01binary")
    long_text = describe_body(b"x" * 5000)
    assert len(long_text["excerpt"]) == EXCERPT_CHARS
    assert describe_body(b"curl -s http://x | sh", truncated=True)["truncated"] is True
