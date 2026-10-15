"""H7 exfiltration store: a write/read-back Candid interface plus an HTTP reply."""

from typing import Any

import pytest

from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.interfaces import Rule
from icp_threat_intel.rules.h7_exfil_store import H7ExfilStore, store_methods
from tests.rules._events import candid, event, gateway_body, method

CJN37 = "cjn37-uyaaa-aaaac-qgnva-cai"
RULE = H7ExfilStore()
# A synthetic exfiltration-store interface (write a blob, read back, wipe).
STORE_METHODS = (
    method("count", "query", rets=("nat",)),
    method("get", "query", ("id: nat",), ("opt blob",)),
    method("getSettings", "query", rets=("text",)),
    method("http_request", "query", ("req: HttpRequest",), ("HttpResponse",)),
    method("http_request_update", "update", ("req: HttpRequest",), ("HttpResponse",)),
    method("list", "query", rets=("vec record { nat; int; nat; }",)),
    method("purge", "update", rets=("nat",)),
    method("setSettings", "update", ("payload: text",)),
    method("store", "update", ("payload: blob",), ("nat",)),
)
STATUS = '{"status":"ok","entries":5,"service":"example-store"}'


def _reply(excerpt: str = STATUS, status: int = 200, **kw: Any) -> Any:
    payload = {"outcome": "ok", "response_status_code": status, "body_class": "other",
               "size": len(excerpt), "excerpt": excerpt}  # fmt: skip
    return event("gateway.http_request_queried", SourceType.RAW_GATEWAY, payload, **kw)


def test_rule_contract() -> None:
    assert isinstance(RULE, Rule) and RULE.id == "H7"
    assert RULE.required_signals == {"store_interface", "served_reply"}
    doc = H7ExfilStore.__doc__ or ""
    assert "CanisterSprawl" in doc and CJN37 in doc and "SPEC" in doc


def test_positive_exfiltration_store_shape() -> None:
    iface, reply = candid(*STORE_METHODS, canister_id=CJN37), _reply(canister_id=CJN37)
    detection = RULE.score([iface, reply])
    assert detection is not None and detection.subject_id == CJN37
    assert detection.score == pytest.approx(1.0)  # blob payload, purge, entry count in reply
    assert {r.source_type for r in detection.evidence_refs} == {
        SourceType.IC_READ_STATE, SourceType.RAW_GATEWAY,
    }  # fmt: skip
    assert "store(payload: blob)" in detection.explanation and "purge" in detection.explanation


def test_gateway_body_counts_as_reply() -> None:
    body = gateway_body("other", 60, canister_id=CJN37)
    assert RULE.score([candid(*STORE_METHODS, canister_id=CJN37), body]) is not None


def test_minimal_store_scores_lower() -> None:
    methods = (method("put", "update", ("data: text",)), method("list", "query"))
    detection = RULE.score([candid(*methods), _reply("ok")])
    assert detection is not None and detection.score == pytest.approx(0.6)


def test_negative_interface_alone() -> None:
    assert RULE.score([candid(*STORE_METHODS)]) is None


def test_negative_reply_alone() -> None:
    assert RULE.score([_reply()]) is None


@pytest.mark.parametrize(
    "methods",
    [
        (method("store", "update", ("payload: blob",)),),  # no read-back
        (method("list", "query"), method("get", "query")),  # no writer
        (
            method("store", "query", ("payload: blob",)),
            method("list", "query"),
        ),  # writer is a query
        (method("store", "update", ("n: nat",)), method("list", "query")),  # no blob/text payload
        (method("update_link", "update", ("new_link: text",)), method("get_latest_link", "query")),
    ],
)
def test_interfaces_that_are_not_stores(methods: tuple[dict[str, Any], ...]) -> None:
    assert RULE.score([candid(*methods), _reply()]) is None


@pytest.mark.parametrize(
    "reply",
    [
        _reply(status=404),
        _reply("x" * 5000),
        _reply(status=200).model_copy(update={"payload": {"outcome": "rejected"}}),
    ],
)
def test_replies_that_do_not_count(reply: Any) -> None:
    assert RULE.score([candid(*STORE_METHODS), reply]) is None


def test_store_methods_helper() -> None:
    writers, readers = store_methods(list(STORE_METHODS))
    assert writers == ["store"] and readers == ["count", "get", "list"]
