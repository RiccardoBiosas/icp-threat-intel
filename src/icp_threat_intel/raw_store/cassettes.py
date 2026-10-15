"""Read recorded cassettes (``tests/cassettes/*.json``) as in-memory raw snapshots.

Offline mode (``canister inspect --offline``) uses this when the raw store holds nothing
for a canister. Each cassette becomes the ``RawSnapshot`` its collector would have stored:
the read_state body is the certificate, the gateway pre-check body is the Candid reply,
and ``request_meta`` matches what the collectors write. Nothing touches the network and
nothing is written anywhere.
"""

import base64
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from icp_threat_intel.core.candid_wire import CandidDecodeError, decode, field_hash
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.ic_encoding import decode_cbor
from icp_threat_intel.core.models import RawSnapshot

_SOURCES = {
    "ic_read_state": SourceType.IC_READ_STATE,
    "raw_gateway": SourceType.RAW_GATEWAY,
    "dashboard_api": SourceType.DASHBOARD_API,
}
_PATHS = {"state": ["module_hash", "controllers"], "candid": ["metadata/candid:service"]}


def _read_state(meta: dict[str, Any], status: int, body: bytes) -> tuple[bytes, dict[str, Any]]:
    request = meta["request"]
    out = {"canister_id": meta["canister_id"], "request": request, "paths": _PATHS[request]}
    if status == 200:
        body = bytes(decode_cbor(body)["certificate"])
    return body, out


def _precheck(meta: dict[str, Any], status: int, body: bytes) -> tuple[bytes, dict[str, Any]]:
    out: dict[str, Any] = {"canister_id": meta["canister_id"], "request": "http_request_query"}
    if status != 200:
        return body, out | {"outcome": "http_error"}
    reply = decode_cbor(body)
    if reply.get("status") != "replied":
        out |= {"outcome": "rejected", "reject_code": reply.get("reject_code")}
        return str(reply.get("reject_message", "")).encode(), out
    arg = bytes(reply["reply"]["arg"])
    try:
        record = decode(arg)[0]
    except (CandidDecodeError, ValueError, IndexError):
        return arg, out | {"outcome": "undecodable"}
    upgrade = record.get(field_hash("upgrade")) if isinstance(record, dict) else None
    status_code = record.get(field_hash("status_code")) if isinstance(record, dict) else None
    outcome = "upgrade_requested" if upgrade is True else "ok"
    return arg, out | {"outcome": outcome, "upgrade": upgrade, "response_status_code": status_code}


def cassette_snapshot(path: Path, snapshot_id: int) -> RawSnapshot | None:
    """The raw snapshot a cassette stands for, or ``None`` for an unknown source."""
    data = json.loads(path.read_text(encoding="utf-8"))
    meta, response = data["metadata"], data["response"]
    source_type = _SOURCES.get(meta.get("source", ""))
    if source_type is None:
        return None
    status = int(response["status_code"])
    body = base64.b64decode(response["body_b64"])
    url = str(meta["url"])
    headers = {str(k): str(v) for k, v in response.get("headers", {}).items()}
    if source_type is SourceType.IC_READ_STATE:
        body, request_meta = _read_state(meta, status, body)
        url = f"{url}#{meta['request']}"
    elif meta["request"] == "http_request_query":
        body, request_meta = _precheck(meta, status, body)
        url = f"{url}#http_request"
    elif source_type is SourceType.RAW_GATEWAY:
        request_meta = {"canister_id": meta["canister_id"], "request": "get",
                        "domain": meta["request"], "outcome": "ok", "redirects": []}  # fmt: skip
    else:
        request_meta = {"canister_id": meta["canister_id"], "request": meta["request"]}
    digest = hashlib.sha256(body).hexdigest()
    return RawSnapshot(
        id=snapshot_id,
        source_type=source_type,
        source_name=str(meta["source"]),
        url=url,
        fetched_at=datetime.fromisoformat(meta["recorded_at"]),
        sha256=digest,
        stored_sha256=digest,
        body=body,
        size_bytes=len(body),
        http_status=status,
        content_type=headers.get("content-type"),
        headers=headers,
        synthetic=bool(meta.get("synthetic", True)),
        request_meta=request_meta,
    )


def snapshots_for(cassette_dir: Path, canister_id: str) -> list[RawSnapshot]:
    """Every cassette snapshot about ``canister_id``, ids counted from -1 downwards."""
    snapshots: list[RawSnapshot] = []
    for path in sorted(cassette_dir.glob(f"*_{canister_id}_*.json")):
        snap = cassette_snapshot(path, -(len(snapshots) + 1))
        if snap is not None and snap.request_meta.get("canister_id") == canister_id:
            snapshots.append(snap)
    return snapshots
