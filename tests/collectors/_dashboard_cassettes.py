"""Dashboard API cassettes: format, replay transport and synthetic builder (SPEC D6).

Per seed canister: ``dashboard_<id>_canister.json`` (``GET /api/v3/canisters/{id}``) and
``dashboard_<id>_subnet.json`` (``GET /api/v4/subnets/{subnet}``). The canister field
names are UNVERIFIED (docs/sources/dashboard-api.md); the synthetic bodies use the names
the note infers. Rebuild with ``uv run python -m tests.collectors._dashboard_cassettes``.
"""

import base64
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from icp_threat_intel.collectors.dashboard import canister_url, subnet_url
from icp_threat_intel.core.ic_encoding import principal_to_text
from tests.collectors._cassettes import (
    CASSETTES,
    SEED_CANISTERS,
    SYNTHETIC_TIME,
    load,
    synthetic_principal,
)

SYNTHETIC_NOTE = (
    "Synthetic: built from docs/sources/dashboard-api.md (OpenAPI paths; canister fields "
    "inferred, UNVERIFIED) because no ICP_THREAT_INTEL_CONTACT was configured for make "
    "record. Values are placeholders, not observations. See OPEN_QUESTIONS.md."
)


def cassette_path(canister_id: str, request: str) -> Path:
    return CASSETTES / f"dashboard_{canister_id}_{request}.json"


def synthetic_subnet(canister_id: str) -> str:
    return principal_to_text(synthetic_principal(f"subnet:{canister_id}"))


def write(
    canister_id: str,
    request: str,
    *,
    url: str,
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
            "source": "dashboard_api",
            "canister_id": canister_id,
            "request": request,
            "method": "GET",
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


def load_all() -> dict[str, dict[str, Any]]:
    """Cassettes keyed by request URL."""
    out = {}
    for path in sorted(CASSETTES.glob("dashboard_*.json")):
        data = load(path)
        out[data["metadata"]["url"]] = data
    return out


class DashboardReplay(httpx.BaseTransport):
    def __init__(self, cassettes: dict[str, dict[str, Any]]) -> None:
        self.cassettes = cassettes
        self.requests: list[httpx.Request] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.method == "GET", request
        resp = self.cassettes[str(request.url)]["response"]
        body = base64.b64decode(resp["body_b64"])
        return httpx.Response(resp["status_code"], headers=resp["headers"], content=body)


def _canister_body(canister_id: str) -> dict[str, Any]:
    body: dict[str, Any] = {
        "canister_id": canister_id,
        "subnet_id": synthetic_subnet(canister_id),
        "controllers": [principal_to_text(synthetic_principal(f"controller:{canister_id}"))],
        "canister_type": "dapp",
        "language": None,
        "name": None,
        "updated_at": SYNTHETIC_TIME.isoformat(),
    }
    if canister_id == SEED_CANISTERS[0]:  # one cassette also carries a module hash
        body["module_hash"] = "0x" + "ab" * 32
    return body


def _subnet_body(subnet_id: str) -> dict[str, Any]:
    return {
        "subnet_id": subnet_id,
        "subnet_type": "application",
        "subnet_authorization": "public",
        "total_canisters": "1000",
        "running_canisters": "990",
        "stopped_canisters": "10",
    }


def build_synthetic() -> list[Path]:
    common: dict[str, Any] = {
        "synthetic": True,
        "recorded_at": SYNTHETIC_TIME,
        "note": SYNTHETIC_NOTE,
        "status_code": 200,
        "headers": {"content-type": "application/json"},
    }
    written = []
    for canister_id in SEED_CANISTERS:
        subnet = synthetic_subnet(canister_id)
        for request, url, body in (
            ("canister", canister_url(canister_id), _canister_body(canister_id)),
            ("subnet", subnet_url(subnet), _subnet_body(subnet)),
        ):
            written.append(
                write(canister_id, request, url=url, body=json.dumps(body).encode(), **common)
            )
    return written


if __name__ == "__main__":
    for written_path in build_synthetic():
        print(written_path.relative_to(CASSETTES.parent.parent))
