"""Parse Dashboard API snapshots (``collectors/dashboard.py``) into events. No I/O.

* a canister body gives ``canister.state_observed`` and a ``CanisterSnapshot`` (subnet,
  controllers, module hash). Fields the API did not return stay ``None``;
* a subnet body gives ``canister.subnet_observed`` for the canister that led to it.

Non-200 answers and unusable bodies still produce an event with a status, so a missing
canister is evidence rather than a silent gap.
"""

from dataclasses import asdict
from typing import Any

from icp_threat_intel.collectors.dashboard import extract_canister, extract_subnet
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.models import CanisterSnapshot, ParseResult, RawSnapshot
from icp_threat_intel.parsers.base import canister_event

PARSER_NAME = "dashboard"


class DashboardParser:
    source_type = SourceType.DASHBOARD_API
    version = "1"

    @property
    def parser_id(self) -> str:
        return f"{PARSER_NAME}@{self.version}"

    def parse(self, snapshot: RawSnapshot) -> ParseResult:
        meta = snapshot.request_meta
        canister_id = str(meta["canister_id"])
        if meta.get("request") == "subnet":
            return self._subnet(snapshot, canister_id)
        return self._canister(snapshot, canister_id)

    def _event(
        self, snapshot: RawSnapshot, kind: str, canister_id: str, payload: dict[str, Any]
    ) -> ParseResult:
        payload = {"http_status": snapshot.http_status, **payload}
        event = canister_event(snapshot, self.parser_id, kind, canister_id, payload)
        return ParseResult(events=(event,))

    def _canister(self, snapshot: RawSnapshot, canister_id: str) -> ParseResult:
        kind = "canister.state_observed"
        if snapshot.http_status != 200:
            return self._event(snapshot, kind, canister_id, {"status": "error"})
        found = extract_canister(snapshot.body)
        if found is None or found.canister_id != canister_id:
            return self._event(snapshot, kind, canister_id, {"status": "unusable_body"})
        fields = asdict(found)
        fields["canister_status"] = fields.pop("status")  # "status" is the parse status
        if found.controllers is not None:
            fields["controllers"] = list(found.controllers)
        result = self._event(snapshot, kind, canister_id, {"status": "ok", **fields})
        canister = CanisterSnapshot(
            canister_id=canister_id,
            observed_at=snapshot.fetched_at,
            source_type=self.source_type,
            subnet=found.subnet_id,
            controllers=found.controllers,
            module_hash=found.module_hash,
            raw_snapshot_id=snapshot.id,
        )
        return ParseResult(events=result.events, canister_snapshots=(canister,))

    def _subnet(self, snapshot: RawSnapshot, canister_id: str) -> ParseResult:
        kind = "canister.subnet_observed"
        if snapshot.http_status != 200:
            return self._event(snapshot, kind, canister_id, {"status": "error"})
        found = extract_subnet(snapshot.body)
        if found is None:
            return self._event(snapshot, kind, canister_id, {"status": "unusable_body"})
        return self._event(snapshot, kind, canister_id, {"status": "ok", **asdict(found)})
