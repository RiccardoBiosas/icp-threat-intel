"""Census orchestration: walk, diff against the previous run, persist (PLAN steps 5-8).

For every canister observed this writes a ``canister_snapshots`` row tagged with the run id
and upserts ``canisters``; it emits ``census.canister_added``, ``census.canister_removed``
and ``census.canister_changed`` (payload ``changes = {field: {from, to}}``, the shape H2
reads) and one ``census.run_completed`` event. The previous run is the latest
``census.run_completed`` event; the first run reports everything as added.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from icp_threat_intel.census.diff import CanisterState, CensusDiff, diff_runs
from icp_threat_intel.census.walker import CensusWalker, WalkResult
from icp_threat_intel.collectors.dashboard import BASE_URL
from icp_threat_intel.core.enums import CanisterStatus, SourceType
from icp_threat_intel.core.models import Event
from icp_threat_intel.db.models import Canister, EventRow, Source
from icp_threat_intel.db.models import CanisterSnapshot as SnapshotRow
from icp_threat_intel.parsers.base import dedup_key
from icp_threat_intel.raw_store.store import get_or_create_source

PARSER = "census@1"


@dataclass(frozen=True)
class PreviousRun:
    run_id: str
    states: dict[str, CanisterState]
    complete_subnets: frozenset[str]


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def previous_run(session: Session) -> PreviousRun | None:
    row = session.scalar(
        select(EventRow)
        .where(EventRow.kind == "census.run_completed")
        .order_by(EventRow.observed_at.desc(), EventRow.id.desc())
        .limit(1)
    )
    if row is None:
        return None
    run_id = str(row.payload["run_id"])
    snaps = session.scalars(select(SnapshotRow).where(SnapshotRow.census_run_id == run_id))
    states = {
        s.canister_id: CanisterState(
            canister_id=s.canister_id,
            subnet=s.subnet,
            controllers=tuple(s.controllers) if s.controllers is not None else None,
            module_hash=s.module_hash,
            status=s.status,
            candid_sha256=s.candid_sha256,
        )
        for s in snaps
    }
    return PreviousRun(run_id, states, frozenset(row.payload.get("complete_subnets", [])))


def _event(
    source: Source, kind: str, subject: tuple[str, str], at: datetime, payload: dict[str, Any]
) -> EventRow:
    subject_type, subject_id = subject
    model = Event(
        kind=kind,
        subject_type=subject_type,
        subject_id=subject_id,
        canister_id=subject_id if subject_type == "canister" else None,
        observed_at=at,
        source_type=SourceType.DASHBOARD_API,
        parser=PARSER,
        weight=source.reliability,
        payload=payload,
    )
    return EventRow(
        kind=model.kind,
        subject_type=model.subject_type,
        subject_id=model.subject_id,
        canister_id=model.canister_id,
        observed_at=model.observed_at,
        source_id=source.id,
        source_type=model.source_type,
        parser=model.parser,
        weight=model.weight,
        is_ioc=False,
        payload=model.payload,
        dedup_key=dedup_key(model),
    )


def persist(session: Session, walk: WalkResult, diff: CensusDiff, prev: PreviousRun | None) -> None:
    source = get_or_create_source(session, "dashboard_api", SourceType.DASHBOARD_API, BASE_URL)
    at, run_id = walk.started_at, walk.run_id
    for cid, state in sorted(walk.states.items()):
        canister = session.get(Canister, cid)
        if canister is None:
            canister = Canister(id=cid, first_seen=at, last_seen=at)
            session.add(canister)
        canister.last_seen = max(_aware(canister.last_seen), at)
        canister.subnet = state.subnet or canister.subnet
        if state.controllers is not None:
            canister.controllers = list(state.controllers)
        canister.module_hash = state.module_hash or canister.module_hash
        if state.status is not CanisterStatus.UNKNOWN:
            canister.status = state.status
        session.flush()
        session.add(
            SnapshotRow(
                canister_id=cid,
                observed_at=at,
                source_id=source.id,
                census_run_id=run_id,
                subnet=state.subnet,
                controllers=list(state.controllers or ()),
                module_hash=state.module_hash,
                status=state.status,
            )
        )
    for cid in diff.added:
        payload: dict[str, Any] = {"run_id": run_id, "subnet": walk.states[cid].subnet}
        session.add(_event(source, "census.canister_added", ("canister", cid), at, payload))
    for cid in diff.removed:
        subnet = prev.states[cid].subnet if prev else None
        payload = {"run_id": run_id, "subnet": subnet}
        session.add(_event(source, "census.canister_removed", ("canister", cid), at, payload))
    for cid, changes in diff.changed.items():
        payload = {"run_id": run_id, "changes": changes}
        session.add(_event(source, "census.canister_changed", ("canister", cid), at, payload))
    summary = {
        "run_id": run_id,
        "previous_run_id": prev.run_id if prev else None,
        "canisters": len(walk.states),
        "added": len(diff.added),
        "removed": len(diff.removed),
        "changed": len(diff.changed),
        "pages": walk.pages,
        "ceiling_hit": walk.ceiling_hit,
        "complete_subnets": sorted(walk.complete_subnets),
        "incomplete_subnets": sorted(walk.incomplete_subnets),
    }
    session.add(_event(source, "census.run_completed", ("census_run", run_id), at, summary))
    session.flush()


def run_census(
    sessions: sessionmaker[Session], walker: CensusWalker
) -> tuple[WalkResult, CensusDiff]:
    walk = walker.walk()
    with sessions() as session, session.begin():
        prev = previous_run(session)
        previous_states = prev.states if prev else {}
        complete = frozenset(walk.complete_subnets) & (
            prev.complete_subnets if prev else frozenset()
        )
        diff = diff_runs(previous_states, walk.states, complete)
        persist(session, walk, diff, prev)
    return walk, diff
