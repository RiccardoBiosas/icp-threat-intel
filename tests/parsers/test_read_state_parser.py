"""read_state snapshots -> canister.state_observed / canister.candid_observed."""

from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.models import RawSnapshot
from icp_threat_intel.parsers.read_state import ReadStateParser
from tests.collectors._cassettes import SEED_CANISTERS

TDTQY, CJN37 = SEED_CANISTERS


def _by(snapshots: list[RawSnapshot], canister: str, request: str) -> RawSnapshot:
    (snap,) = [
        s
        for s in snapshots
        if s.source_type is SourceType.IC_READ_STATE
        and s.request_meta["canister_id"] == canister
        and s.request_meta["request"] == request
    ]
    return snap


def test_state_snapshot_becomes_event_and_canister_snapshot(snapshots: list[RawSnapshot]) -> None:
    snap = _by(snapshots, TDTQY, "state")
    result = ReadStateParser().parse(snap)
    (event,) = result.events
    assert event.kind == "canister.state_observed"
    assert event.subject_type == "canister" and event.subject_id == TDTQY
    assert event.raw_snapshot_id == snap.id
    assert event.observed_at == snap.fetched_at
    assert event.parser == "read_state@1"
    (canister,) = result.canister_snapshots
    assert canister.module_hash == event.payload["module_hash"]
    assert list(canister.controllers or ()) == event.payload["controllers"]


def test_candid_snapshot_lists_methods_with_modes(snapshots: list[RawSnapshot]) -> None:
    (event,) = ReadStateParser().parse(_by(snapshots, TDTQY, "candid")).events
    assert event.kind == "canister.candid_observed"
    modes = {m["name"]: m["mode"] for m in event.payload["candid_methods"]}
    assert modes == {"get_latest_link": "query", "http_request": "query", "update_link": "update"}


def test_absent_candid(snapshots: list[RawSnapshot]) -> None:
    (event,) = ReadStateParser().parse(_by(snapshots, CJN37, "candid")).events
    assert event.payload["status"] == "absent"
