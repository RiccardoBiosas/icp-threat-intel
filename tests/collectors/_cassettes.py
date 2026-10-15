"""Cassette format, replay transport and synthetic read_state cassette builder.

A cassette is one JSON file under ``tests/cassettes/`` holding one HTTP exchange:
``metadata`` (``synthetic``, canister, request, paths, url, recorded_at, note) and
``response`` (status code, headers, base64 body). ``make record`` overwrites them with
live responses (``synthetic: false``); the builder below writes the synthetic ones
(SPEC D6). Run ``uv run python -m tests.collectors._cassettes`` to rebuild them.
"""

import base64
import hashlib
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import cbor2
import httpx

from icp_threat_intel.collectors.read_state import REQUESTS, path_names
from icp_threat_intel.core.ic_encoding import (
    SELF_DESCRIBE_TAG,
    decode_cbor,
    principal_from_text,
)

CASSETTES = Path(__file__).resolve().parents[1] / "cassettes"
SEED_CANISTERS = ("tdtqy-oyaaa-aaaae-af2dq-cai", "cjn37-uyaaa-aaaac-qgnva-cai")
SYNTHETIC_TIME = datetime(2026, 10, 15, tzinfo=UTC)
SYNTHETIC_NOTE = (
    "Synthetic: built from the IC interface spec (certification, read_state) because no "
    "ICP_THREAT_INTEL_CONTACT was configured for make record. Module hash, controllers, "
    "signature and delegation are placeholders, not observations of the canister. See "
    "OPEN_QUESTIONS.md (T07)."
)
# Method names confirmed by the CSA write-up cited in docs/sources/vendor-rss.md; the
# signatures are illustrative.
TDTQY_CANDID = """// synthetic interface for tests
type HttpRequest = record {
  url : text; method : text; body : blob; headers : vec record { text; text }
};
type HttpResponse = record {
  body : blob; headers : vec record { text; text }; status_code : nat16
};
service : {
  get_latest_link : () -> (text) query;
  http_request : (HttpRequest) -> (HttpResponse) query;
  update_link : (text) -> ();
}
"""


def cassette_path(canister_id: str, request: str) -> Path:
    return CASSETTES / f"read_state_{canister_id}_{request}.json"


def load(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def response_body(cassette: dict[str, Any]) -> bytes:
    return base64.b64decode(cassette["response"]["body_b64"])


def request_kind(paths: Sequence[Sequence[bytes]]) -> str:
    suffixes = {tuple(bytes(label) for label in path[2:]) for path in paths}
    for name, wanted in REQUESTS.items():
        if suffixes == set(wanted):
            return name
    raise AssertionError(f"unexpected read_state paths {paths!r}")


class ReplayTransport(httpx.BaseTransport):
    """Answers read_state POSTs from cassettes; anything else fails the test."""

    def __init__(self, cassettes: dict[tuple[str, str], dict[str, Any]]) -> None:
        self.cassettes = cassettes
        self.requests: list[httpx.Request] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        parts = request.url.path.split("/")
        assert parts[1:3] == ["api", "v3"] and parts[-1] == "read_state", request.url
        content = decode_cbor(request.read())["content"]
        assert content["request_type"] == "read_state"
        assert content["sender"] == b"\x04"
        key = (parts[4], request_kind(content["paths"]))
        cassette = self.cassettes[key]
        resp = cassette["response"]
        return httpx.Response(
            resp["status_code"], headers=resp["headers"], content=response_body(cassette)
        )


def write(
    canister_id: str,
    request: str,
    *,
    status_code: int,
    body: bytes,
    synthetic: bool,
    recorded_at: datetime,
    note: str,
    headers: dict[str, str] | None = None,
) -> Path:
    cassette = {
        "metadata": {
            "synthetic": synthetic,
            "source": "ic_read_state",
            "canister_id": canister_id,
            "request": request,
            "paths": path_names(request),
            "method": "POST",
            "url": f"https://icp-api.io/api/v3/canister/{canister_id}/read_state",
            "recorded_at": recorded_at.isoformat(),
            "note": note,
        },
        "response": {
            "status_code": status_code,
            "headers": headers or {"content-type": "application/cbor"},
            "body_b64": base64.b64encode(body).decode("ascii"),
        },
    }
    path = cassette_path(canister_id, request)
    path.write_text(json.dumps(cassette, indent=2) + "\n", encoding="utf-8")
    return path


# --- synthetic certificate construction (spec hash-tree encoding) ---------------------


def leb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte, value = value & 0x7F, value >> 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def labeled(label: bytes, tree: list[Any]) -> list[Any]:
    return [2, label, tree]


def fork_all(nodes: list[list[Any]]) -> list[Any]:
    """Balanced fork over nodes already sorted by label."""
    if not nodes:
        return [0]
    if len(nodes) == 1:
        return nodes[0]
    mid = len(nodes) // 2
    return [1, fork_all(nodes[:mid]), fork_all(nodes[mid:])]


def synthetic_principal(seed: str) -> bytes:
    """A self-authenticating-shaped principal (28-byte hash + 0x02) that is clearly fake."""
    return hashlib.sha224(f"synthetic:{seed}".encode()).digest() + b"\x02"


def certificate(canister_id: str, leaves: dict[bytes, list[Any]], time_ns: int) -> bytes:
    raw = principal_from_text(canister_id)
    canister_tree = fork_all([labeled(k, v) for k, v in sorted(leaves.items())])
    tree = fork_all(
        [
            labeled(b"canister", labeled(raw, canister_tree)),
            labeled(b"time", [3, leb128(time_ns)]),
        ]
    )
    cert = {
        "tree": tree,
        "signature": bytes(48),
        "delegation": {"subnet_id": synthetic_principal("subnet"), "certificate": b"synthetic"},
    }
    return cbor2.dumps(cbor2.CBORTag(SELF_DESCRIBE_TAG, cert))


def http_body(cert: bytes) -> bytes:
    return cbor2.dumps(cbor2.CBORTag(SELF_DESCRIBE_TAG, {"certificate": cert}))


def build_synthetic() -> list[Path]:
    time_ns = int(SYNTHETIC_TIME.timestamp()) * 1_000_000_000
    written = []
    for canister_id in SEED_CANISTERS:
        controllers = cbor2.dumps([synthetic_principal(f"controller:{canister_id}")])
        module_hash = hashlib.sha256(f"synthetic:module:{canister_id}".encode()).digest()
        state = {b"controllers": [3, controllers], b"module_hash": [3, module_hash]}
        candid: dict[bytes, list[Any]] = {}
        if canister_id == SEED_CANISTERS[0]:
            candid = {
                b"metadata": labeled(b"candid:service", [3, TDTQY_CANDID.encode()]),
            }
        for request, leaves in (("state", state), ("candid", candid)):
            body = http_body(certificate(canister_id, leaves, time_ns))
            written.append(
                write(
                    canister_id,
                    request,
                    status_code=200,
                    body=body,
                    synthetic=True,
                    recorded_at=SYNTHETIC_TIME,
                    note=SYNTHETIC_NOTE,
                )
            )
    return written


if __name__ == "__main__":
    for written_path in build_synthetic():
        print(written_path.relative_to(CASSETTES.parent.parent))
