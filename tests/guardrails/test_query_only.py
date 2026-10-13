"""Guardrail 1: the IC client can only make query and read_state requests.

Update calls, code installation, canister creation and ICP or cycles transfers must be
impossible through the public API.
"""

import inspect
import re

import cbor2
import httpx
import pytest

from icp_threat_intel.core import ic_client, ic_encoding
from icp_threat_intel.core.ic_client import IcClient, IcRequestRefused
from icp_threat_intel.core.ic_encoding import (
    ALLOWED_REQUEST_TYPES,
    ForbiddenRequestType,
    build_envelope,
)
from tests.guardrails._support import make_client, source_files

CANISTER = "tdtqy-oyaaa-aaaae-af2dq-cai"
FORBIDDEN_WORDS = (
    "call",
    "update",
    "install",
    "upgrade",
    "reinstall",
    "create",
    "transfer",
    "top_up",
    "topup",
    "deposit",
    "send",
    "sign",
    "uninstall",
    "delete",
    "stop",
    "start",
    "provisional",
)


def _cbor_reply(content: object) -> httpx.Response:
    return httpx.Response(
        200,
        content=cbor2.dumps(cbor2.CBORTag(55799, content)),
        headers={"Content-Type": "application/cbor"},
    )


def _handler(request: httpx.Request) -> httpx.Response:
    if request.url.path.endswith("/query"):
        return _cbor_reply({"status": "replied", "reply": {"arg": b"DIDL\x00\x00"}})
    if request.url.path.endswith("/read_state"):
        return _cbor_reply({"certificate": b"cert-bytes"})
    return httpx.Response(404)


def _client() -> tuple[IcClient, list[httpx.Request]]:
    http, recorder = make_client(_handler)
    return IcClient(http), recorder.requests


def test_public_surface_is_query_and_read_state_only() -> None:
    public = {
        name
        for name, member in inspect.getmembers(IcClient)
        if not name.startswith("_") and callable(member)
    }
    assert public == {"query", "read_state"}


@pytest.mark.parametrize("module", [ic_client, ic_encoding])
def test_modules_expose_no_mutating_names(module: object) -> None:
    for name in dir(module):
        if name.startswith("_") or name in {"ALLOWED_REQUEST_TYPES", "ForbiddenRequestType"}:
            continue
        lowered = name.lower()
        hits = [word for word in FORBIDDEN_WORDS if word in lowered]
        assert hits == [], f"{module}.{name} looks like a mutating API: {hits}"


def test_allowed_request_types() -> None:
    assert frozenset({"query", "read_state"}) == ALLOWED_REQUEST_TYPES


@pytest.mark.parametrize("request_type", ["call", "update", "install_code", "create_canister", ""])
def test_envelope_builder_rejects_other_request_types(request_type: str) -> None:
    with pytest.raises(ForbiddenRequestType):
        build_envelope(request_type, canister_id=CANISTER, fields={"method_name": "x", "arg": b""})


def test_query_hits_query_endpoint_with_anonymous_sender() -> None:
    client, requests = _client()
    reply = client.query(CANISTER, "get_link", b"DIDL\x00\x00")
    assert reply == b"DIDL\x00\x00"
    assert len(requests) == 1
    path = requests[0].url.path
    assert path.endswith(f"/canister/{CANISTER}/query")
    envelope = cbor2.loads(requests[0].content)
    if isinstance(envelope, cbor2.CBORTag):
        envelope = envelope.value
    content = envelope["content"]
    assert content["request_type"] == "query"
    assert content["sender"] == b"\x04"
    assert "sender_sig" not in envelope


def test_read_state_hits_read_state_endpoint() -> None:
    client, requests = _client()
    cert = client.read_state(CANISTER, [[b"canister", b"x", b"module_hash"]])
    assert cert == b"cert-bytes"
    assert requests[0].url.path.endswith(f"/canister/{CANISTER}/read_state")
    envelope = cbor2.loads(requests[0].content)
    if isinstance(envelope, cbor2.CBORTag):
        envelope = envelope.value
    assert envelope["content"]["request_type"] == "read_state"


@pytest.mark.parametrize(
    "method",
    [
        "install_code",
        "create_canister",
        "transfer",
        "icrc1_transfer",
        "icrc2_transfer_from",
        "notify_top_up",
        "notify_create_canister",
        "deposit_cycles",
        "update_settings",
        "update_link",
        "stop_canister",
        "delete_canister",
        "send_dfx",
    ],
)
def test_query_refuses_mutating_method_names(method: str) -> None:
    client, requests = _client()
    with pytest.raises(IcRequestRefused):
        client.query(CANISTER, method, b"DIDL\x00\x00")
    assert requests == []


def test_query_refuses_management_canister() -> None:
    client, requests = _client()
    with pytest.raises(IcRequestRefused):
        client.query("aaaaa-aa", "canister_status", b"DIDL\x00\x00")
    assert requests == []


def test_no_source_file_targets_the_update_endpoint() -> None:
    pattern = re.compile(r"""["'/]call["'/]|/api/v\d/canister/[^"']*/call""")
    offenders = [str(p) for p in source_files() if pattern.search(p.read_text(encoding="utf-8"))]
    assert offenders == []
