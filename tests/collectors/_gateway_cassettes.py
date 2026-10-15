"""Raw-gateway cassettes: format, replay transport and synthetic builder (SPEC D6).

Per seed canister there are three cassettes: the ``http_request`` query pre-check
(``raw_gateway_<id>_http_request_query.json``) and one GET per raw domain
(``raw_gateway_<id>_raw.icp0.io.json``, ``raw_gateway_<id>_raw.ic0.app.json``). The
format matches ``_cassettes.py``. Rebuild with
``uv run python -m tests.collectors._gateway_cassettes``.
"""

import base64
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import cbor2
import httpx

from icp_threat_intel.collectors.raw_gateway import DOMAINS
from icp_threat_intel.core.candid_wire import (
    BOOL,
    NAT8,
    NAT16,
    OPT,
    RECORD,
    TEXT,
    VEC,
    field_hash,
    sleb,
    uleb,
)
from icp_threat_intel.core.ic_encoding import SELF_DESCRIBE_TAG
from tests.collectors._cassettes import CASSETTES, SEED_CANISTERS, SYNTHETIC_TIME, load

PRECHECK = "http_request_query"
SYNTHETIC_NOTE = (
    "Synthetic: built from docs/sources/raw-gateway.md (HTTP gateway spec, ic-gateway "
    "error map) because no ICP_THREAT_INTEL_CONTACT was configured for make record. "
    "Bodies are placeholders, not observations of the canister. See OPEN_QUESTIONS.md."
)
SYNTHETIC_BODIES = {
    SEED_CANISTERS[0]: (200, b"https://example.invalid/synthetic-stage2.bin\n"),
    SEED_CANISTERS[1]: (404, b"Not found"),
}


def cassette_path(canister_id: str, request: str) -> Path:
    return CASSETTES / f"raw_gateway_{canister_id}_{request}.json"


def _text(value: str | bytes) -> bytes:
    raw = value.encode() if isinstance(value, str) else value
    return uleb(len(raw)) + raw


def encode_http_response(
    status: int, headers: list[tuple[str, str]], body: bytes, upgrade: bool | None = None
) -> bytes:
    """Candid ``(record { status_code; headers; body; upgrade : opt bool })``."""
    fields = sorted(
        [("status_code", NAT16), ("headers", 1), ("body", 2), ("upgrade", 4)],
        key=lambda f: field_hash(f[0]),
    )
    table = [
        sleb(RECORD)
        + uleb(len(fields))
        + b"".join(uleb(field_hash(n)) + sleb(t) for n, t in fields),
        sleb(VEC) + sleb(3),
        sleb(VEC) + sleb(NAT8),
        sleb(RECORD) + uleb(2) + uleb(0) + sleb(TEXT) + uleb(1) + sleb(TEXT),
        sleb(OPT) + sleb(BOOL),
    ]
    values = {
        "status_code": status.to_bytes(2, "little"),
        "headers": uleb(len(headers)) + b"".join(_text(k) + _text(v) for k, v in headers),
        "body": _text(body),
        "upgrade": b"\x00" if upgrade is None else b"\x01" + (b"\x01" if upgrade else b"\x00"),
    }
    payload = b"".join(values[n] for n, _ in fields)
    return b"DIDL" + uleb(len(table)) + b"".join(table) + uleb(1) + sleb(0) + payload


def query_reply(candid: bytes) -> bytes:
    reply = {"status": "replied", "reply": {"arg": candid}}
    return cbor2.dumps(cbor2.CBORTag(SELF_DESCRIBE_TAG, reply))


def write(
    canister_id: str,
    request: str,
    *,
    url: str,
    method: str,
    status_code: int,
    headers: dict[str, str],
    body: bytes,
    synthetic: bool,
    recorded_at: datetime,
    note: str,
) -> Path:
    cassette = {
        "metadata": {
            "synthetic": synthetic,
            "source": "raw_gateway",
            "canister_id": canister_id,
            "request": request,
            "method": method,
            "url": url,
            "recorded_at": recorded_at.isoformat(),
            "note": note,
        },
        "response": {
            "status_code": status_code,
            "headers": headers,
            "body_b64": base64.b64encode(body).decode("ascii"),
        },
    }
    path = cassette_path(canister_id, request)
    path.write_text(json.dumps(cassette, indent=2) + "\n", encoding="utf-8")
    return path


def load_all() -> dict[tuple[str, str], dict[str, Any]]:
    out = {}
    for path in sorted(CASSETTES.glob("raw_gateway_*.json")):
        data = load(path)
        out[(data["metadata"]["canister_id"], data["metadata"]["request"])] = data
    return out


class GatewayReplay(httpx.BaseTransport):
    """Serves the pre-check query and both raw GETs from cassettes; nothing else."""

    def __init__(self, cassettes: dict[tuple[str, str], dict[str, Any]]) -> None:
        self.cassettes = cassettes
        self.requests: list[httpx.Request] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        host, path = request.url.host, request.url.path
        if host == "icp-api.io":
            assert request.method == "POST" and path.endswith("/query"), request.url
            key = (path.split("/")[4], PRECHECK)
        else:
            assert request.method == "GET", request.url
            canister_id, _, domain = host.partition(".")
            assert domain in DOMAINS and path == "/", request.url
            key = (canister_id, domain)
        resp = self.cassettes[key]["response"]
        body = base64.b64decode(resp["body_b64"])
        return httpx.Response(resp["status_code"], headers=resp["headers"], content=body)


def build_synthetic() -> list[Path]:
    written = []
    for canister_id, (status, body) in SYNTHETIC_BODIES.items():
        headers = [("content-type", "text/plain")]
        reply = query_reply(encode_http_response(status, headers, body))
        common = {"synthetic": True, "recorded_at": SYNTHETIC_TIME, "note": SYNTHETIC_NOTE}
        written.append(
            write(
                canister_id,
                PRECHECK,
                url=f"https://icp-api.io/api/v2/canister/{canister_id}/query",
                method="POST",
                status_code=200,
                headers={"content-type": "application/cbor"},
                body=reply,
                **common,  # type: ignore[arg-type]
            )
        )
        for domain in DOMAINS:
            written.append(
                write(
                    canister_id,
                    domain,
                    url=f"https://{canister_id}.{domain}/",
                    method="GET",
                    status_code=status,
                    headers={"content-type": "text/plain", "x-ic-canister-id": canister_id},
                    body=body,
                    **common,  # type: ignore[arg-type]
                )
            )
    return written


if __name__ == "__main__":
    for written_path in build_synthetic():
        print(written_path.relative_to(CASSETTES.parent.parent))
