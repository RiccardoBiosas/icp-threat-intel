"""Parse stored read_state certificates into events and canister snapshots (no I/O).

One raw snapshot holds one request from ``collectors/read_state.py``:

* ``state`` gives a ``CanisterSnapshot`` (module hash, controllers) and a
  ``canister.state_observed`` event;
* ``candid`` gives a ``canister.candid_observed`` event with the parsed method list, or a
  status saying why no interface was read (absent, unreadable, unparseable).

Every payload carries ``verification`` (currently always ``unverified:no_bls``) and the
certificate time, so later stages can tell what kind of evidence they hold.
"""

import hashlib
from datetime import UTC, datetime
from typing import Any

from icp_threat_intel.collectors.candid import CandidParseError, parse_service
from icp_threat_intel.collectors.read_state import canister_paths
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.ic_certificate import (
    Certificate,
    CertificateError,
    Lookup,
    decode_certificate,
    decode_principal_list,
)
from icp_threat_intel.core.ic_encoding import principal_to_text
from icp_threat_intel.core.models import CanisterSnapshot, ParseResult, RawSnapshot
from icp_threat_intel.parsers.base import canister_event

PARSER_NAME = "read_state"


def _cert_time(cert: Certificate) -> str | None:
    ns = cert.time_ns()
    return None if ns is None else datetime.fromtimestamp(ns / 1e9, UTC).isoformat()


class ReadStateParser:
    source_type = SourceType.IC_READ_STATE
    version = "1"

    def parse(self, snapshot: RawSnapshot) -> ParseResult:
        meta = snapshot.request_meta
        canister_id = str(meta["canister_id"])
        request = str(meta["request"])
        base: dict[str, Any] = {"request": request, "http_status": snapshot.http_status}
        if snapshot.http_status != 200:
            status = "unreadable" if request == "candid" else "error"
            return self._result(snapshot, canister_id, request, {**base, "status": status})
        try:
            cert = decode_certificate(snapshot.body)
            base |= {"verification": cert.verification, "cert_time": _cert_time(cert)}
            if request == "state":
                return self._state(snapshot, canister_id, cert, base)
            return self._candid(snapshot, canister_id, cert, base)
        except CertificateError as exc:
            payload = {**base, "status": "malformed_certificate", "error": str(exc)}
            return self._result(snapshot, canister_id, request, payload)

    def _state(
        self, snapshot: RawSnapshot, canister_id: str, cert: Certificate, base: dict[str, Any]
    ) -> ParseResult:
        mh_path, ctl_path = canister_paths(canister_id, "state")
        module = cert.lookup(mh_path)
        controllers = cert.lookup(ctl_path)
        module_hash = module.value.hex() if module.value is not None else None
        principals = (
            [principal_to_text(p) for p in decode_principal_list(controllers.value)]
            if controllers.value is not None
            else None
        )
        payload = {
            **base,
            "status": "ok",
            "module_hash": module_hash,
            "module_hash_lookup": module.status.value,
            "controllers": principals,
            "controllers_lookup": controllers.status.value,
        }
        canister = CanisterSnapshot(
            canister_id=canister_id,
            observed_at=snapshot.fetched_at,
            source_type=self.source_type,
            controllers=tuple(principals or ()),
            module_hash=module_hash,
            raw_snapshot_id=snapshot.id,
        )
        return self._result(snapshot, canister_id, "state", payload, canister)

    def _candid(
        self, snapshot: RawSnapshot, canister_id: str, cert: Certificate, base: dict[str, Any]
    ) -> ParseResult:
        found = cert.lookup(canister_paths(canister_id, "candid")[0])
        if found.status is not Lookup.FOUND or found.value is None:
            status = "absent" if found.status is Lookup.ABSENT else "unknown"
            return self._result(snapshot, canister_id, "candid", {**base, "status": status})
        payload = {**base, "candid_sha256": hashlib.sha256(found.value).hexdigest()}
        try:
            methods = parse_service(found.value.decode("utf-8"))
        except (CandidParseError, UnicodeDecodeError) as exc:
            payload |= {"status": "unparseable", "error": str(exc)}
        else:
            payload |= {"status": "ok", "candid_methods": [m.to_dict() for m in methods]}
        return self._result(snapshot, canister_id, "candid", payload)

    def _result(
        self,
        snapshot: RawSnapshot,
        canister_id: str,
        request: str,
        payload: dict[str, Any],
        canister: CanisterSnapshot | None = None,
    ) -> ParseResult:
        kind = "canister.state_observed" if request == "state" else "canister.candid_observed"
        event = canister_event(
            snapshot, f"{PARSER_NAME}@{self.version}", kind, canister_id, payload
        )
        return ParseResult(events=(event,), canister_snapshots=(canister,) if canister else ())
