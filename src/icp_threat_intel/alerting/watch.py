"""Monitoring summaries for the digest: watched IOC canisters and the latest census run.

A watched canister is any IOC canister (``canisters.is_ioc`` or named in the ``iocs``
table). For each, the digest shows the latest observation and whether anything changed
between the last two observations of each kind. "Unchanged" is evidence too: it says the
canister was looked at again and found the same.

The raw store keeps one copy of an identical body, so an unchanged gateway answer produces
no new event; the gateway status therefore carries the time it was first seen ("since").
"""

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from icp_threat_intel.db.models import EventRow
from icp_threat_intel.parsers.ingest import ioc_canisters


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


@dataclass(frozen=True)
class WatchedCanister:
    canister_id: str
    observations: int  # read_state state observations
    last_observed: datetime | None
    module_hash: str | None
    controllers: tuple[str, ...] | None
    candid_sha256: str | None
    gateway: str  # e.g. "451 denylisted", "200 url", "not fetched"
    gateway_since: datetime | None
    changes: tuple[str, ...]  # fields that differ between the last two observations

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for key in ("last_observed", "gateway_since"):
            data[key] = data[key].isoformat() if data[key] else None
        data["controllers"] = list(self.controllers) if self.controllers is not None else None
        data["changes"] = list(self.changes)
        return data


@dataclass(frozen=True)
class CensusSummary:
    run_id: str
    observed_at: datetime
    canisters: int
    complete_subnets: int
    incomplete_subnets: int
    ceiling_hit: bool
    added: int
    removed: int
    changed: int

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "observed_at": self.observed_at.isoformat()}


def _changed(events: Sequence[EventRow], *fields: str) -> bool:
    """True when the last two events differ in any of ``fields``."""
    if len(events) < 2:
        return False
    before, after = events[-2].payload, events[-1].payload
    return any(before.get(f) != after.get(f) for f in fields)


def _gateway_label(event: EventRow) -> str:
    p = event.payload
    if p.get("outcome") != "ok":
        return str(p.get("outcome"))
    return f"{p.get('http_status')} {'denylisted' if p.get('denylisted') else p.get('body_class')}"


def _watch(canister_id: str, events: Sequence[EventRow]) -> WatchedCanister:
    by_kind: dict[tuple[str, str], list[EventRow]] = defaultdict(list)
    gateway: dict[str, list[EventRow]] = defaultdict(list)
    for e in events:
        if e.kind == "gateway.body_observed":
            gateway[str(e.payload.get("domain"))].append(e)
        else:
            by_kind[(e.kind, str(e.source_type))].append(e)
    state = by_kind[("canister.state_observed", "ic_read_state")]
    candid = by_kind[("canister.candid_observed", "ic_read_state")]
    queried = by_kind[("gateway.http_request_queried", "raw_gateway")]
    changes = [f for f in ("module_hash", "controllers") if _changed(state, f)]
    if _changed(candid, "candid_sha256", "status"):
        changes.append("candid")
    if any(_changed(evs, "http_status", "body_sha256", "outcome") for evs in gateway.values()):
        changes.append("gateway")
    if _changed(queried, "response_status_code", "body_sha256", "outcome"):
        changes.append("http_request_reply")
    latest_gw = [evs[-1] for _domain, evs in sorted(gateway.items())]
    labels = sorted({_gateway_label(e) for e in latest_gw})
    last_state = state[-1].payload if state else {}
    controllers = last_state.get("controllers")
    return WatchedCanister(
        canister_id=canister_id,
        observations=len(state),
        last_observed=max((_aware(e.observed_at) for e in events), default=None),
        module_hash=last_state.get("module_hash"),
        controllers=tuple(controllers) if isinstance(controllers, list) else None,
        candid_sha256=candid[-1].payload.get("candid_sha256") if candid else None,
        gateway=" / ".join(labels) if labels else "not fetched",
        gateway_since=max((_aware(e.observed_at) for e in latest_gw), default=None),
        changes=tuple(changes),
    )


def watched_canisters(session: Session) -> list[WatchedCanister]:
    """One summary per IOC canister, in canister-id order."""
    watched = sorted(ioc_canisters(session))
    if not watched:
        return []
    rows = session.scalars(
        select(EventRow)
        .where(EventRow.canister_id.in_(watched))
        .order_by(EventRow.observed_at, EventRow.id)
    ).all()
    grouped: dict[str, list[EventRow]] = defaultdict(list)
    for row in rows:
        grouped[str(row.canister_id)].append(row)
    return [_watch(cid, grouped[cid]) for cid in watched]


def latest_census(session: Session) -> CensusSummary | None:
    row = session.scalar(
        select(EventRow)
        .where(EventRow.kind == "census.run_completed")
        .order_by(EventRow.observed_at.desc(), EventRow.id.desc())
        .limit(1)
    )
    if row is None:
        return None
    p = row.payload
    return CensusSummary(
        run_id=str(p.get("run_id")),
        observed_at=_aware(row.observed_at),
        canisters=int(p.get("canisters", 0)),
        complete_subnets=len(p.get("complete_subnets", [])),
        incomplete_subnets=len(p.get("incomplete_subnets", [])),
        ceiling_hit=bool(p.get("ceiling_hit")),
        added=int(p.get("added", 0)),
        removed=int(p.get("removed", 0)),
        changed=int(p.get("changed", 0)),
    )
