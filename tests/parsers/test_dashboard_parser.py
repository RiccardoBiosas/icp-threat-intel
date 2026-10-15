"""Dashboard snapshots -> canister.state_observed / canister.subnet_observed."""

from datetime import UTC, datetime
from typing import Any

from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.models import RawSnapshot
from icp_threat_intel.parsers.dashboard import DashboardParser
from tests.collectors import _dashboard_cassettes as dash
from tests.collectors._cassettes import SEED_CANISTERS

TDTQY, CJN37 = SEED_CANISTERS


def _snap(body: bytes, status: int = 200, request: str = "canister") -> RawSnapshot:
    fields: dict[str, Any] = {
        "id": 7,
        "source_type": SourceType.DASHBOARD_API,
        "source_name": "dashboard_api",
        "url": "https://ic-api.internetcomputer.org/api/v3/canisters/x",
        "fetched_at": datetime(2026, 10, 15, tzinfo=UTC),
        "sha256": "0" * 64,
        "stored_sha256": "0" * 64,
        "body": body,
        "size_bytes": len(body),
        "http_status": status,
        "request_meta": {"canister_id": CJN37, "request": request},
    }
    return RawSnapshot(**fields)


def test_cassette_snapshots_parse(snapshots: list[RawSnapshot]) -> None:
    dash_snaps = [s for s in snapshots if s.source_type is SourceType.DASHBOARD_API]
    results = [DashboardParser().parse(s) for s in dash_snaps]
    kinds = [r.events[0].kind for r in results]
    assert kinds == ["canister.state_observed", "canister.subnet_observed"] * 2
    tdtqy = results[0]
    (canister,) = tdtqy.canister_snapshots
    assert canister.subnet == dash.synthetic_subnet(TDTQY)
    assert canister.module_hash == "ab" * 32
    assert canister.controllers is not None and len(canister.controllers) == 1
    assert tdtqy.events[0].payload["controllers"] == list(canister.controllers)
    subnet = results[1].events[0].payload
    assert subnet["status"] == "ok" and subnet["total_canisters"] == 1000
    assert results[2].canister_snapshots[0].module_hash is None


def test_error_and_unusable_bodies_still_emit_events() -> None:
    parser = DashboardParser()
    assert parser.parse(_snap(b"{}", status=404)).events[0].payload["status"] == "error"
    unusable = parser.parse(_snap(b"not json"))
    assert unusable.events[0].payload["status"] == "unusable_body"
    assert unusable.canister_snapshots == ()
    other = parser.parse(_snap(b'{"canister_id": "tdtqy-oyaaa-aaaae-af2dq-cai"}'))
    assert other.events[0].payload["status"] == "unusable_body"  # body names another canister
    assert parser.parse(_snap(b"x", 500, "subnet")).events[0].payload["status"] == "error"
    assert parser.parse(_snap(b"{}", 200, "subnet")).events[0].payload["status"] == "unusable_body"


def test_controllers_unknown_stays_none() -> None:
    (canister,) = (
        DashboardParser().parse(_snap(f'{{"canister_id": "{CJN37}"}}'.encode())).canister_snapshots
    )
    assert canister.controllers is None and canister.subnet is None
