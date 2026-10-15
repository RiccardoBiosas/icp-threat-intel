"""Synthetic event builders for rule tests."""

from datetime import UTC, datetime, timedelta
from itertools import count
from typing import Any

from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.models import Event
from icp_threat_intel.core.trust import default_reliability

T0 = datetime(2026, 3, 20, 12, 0, tzinfo=UTC)
TDTQY = "tdtqy-oyaaa-aaaae-af2dq-cai"
_ids = count(1)


def event(
    kind: str,
    source_type: SourceType,
    payload: dict[str, Any],
    *,
    canister_id: str = TDTQY,
    minutes: int = 0,
    is_ioc: bool = False,
    event_id: int | None = -1,
) -> Event:
    return Event(
        id=next(_ids) if event_id == -1 else event_id,
        kind=kind,
        subject_type="canister",
        subject_id=canister_id,
        canister_id=canister_id,
        observed_at=T0 + timedelta(minutes=minutes),
        source_type=source_type,
        parser="synthetic@1",
        weight=default_reliability(source_type),
        is_ioc=is_ioc,
        payload=payload,
    )


def method(
    name: str, mode: str, args: tuple[str, ...] = (), rets: tuple[str, ...] = ()
) -> dict[str, Any]:
    return {"name": name, "args": list(args), "rets": list(rets), "mode": mode}


def candid(*methods: dict[str, Any], **kw: Any) -> Event:
    payload = {"status": "ok", "candid_methods": list(methods), "candid_sha256": "0" * 64}
    return event("canister.candid_observed", SourceType.IC_READ_STATE, payload, **kw)


def gateway_body(
    body_class: str = "url",
    size: int = 45,
    *,
    status: int = 200,
    truncated: bool = False,
    **kw: Any,
) -> Event:
    payload = {
        "outcome": "ok",
        "http_status": status,
        "body_class": body_class,
        "size": size,
        "truncated": truncated,
        "domain": "raw.icp0.io",
    }
    return event("gateway.body_observed", SourceType.RAW_GATEWAY, payload, **kw)
