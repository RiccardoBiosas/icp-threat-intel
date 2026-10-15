"""Ingest: parse raw snapshots, enrich at ingest, persist events and canister snapshots.

Idempotent: events are keyed by ``parsers.base.dedup_key`` and canister snapshots by
``(canister_id, raw_snapshot_id)``, so re-running over the same raw snapshots writes
nothing new. Trust weights come from each snapshot's ``sources`` row; IOC membership from
the ``iocs`` table and ``canisters.is_ioc``.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.interfaces import Parser
from icp_threat_intel.core.models import CanisterSnapshot, Event, RawSnapshot
from icp_threat_intel.db.models import Canister, EventRow, Ioc, Source
from icp_threat_intel.db.models import CanisterSnapshot as CanisterSnapshotRow
from icp_threat_intel.enrichment.ioc_join import IocJoinEnricher, canister_ids_in
from icp_threat_intel.enrichment.trust import TrustEnricher
from icp_threat_intel.parsers.base import dedup_key
from icp_threat_intel.parsers.dashboard import DashboardParser
from icp_threat_intel.parsers.raw_gateway import RawGatewayParser
from icp_threat_intel.parsers.read_state import ReadStateParser
from icp_threat_intel.parsers.signals_feed import SignalsFeedParser

log = structlog.get_logger(__name__)

PARSERS: Mapping[SourceType, Parser] = {
    SourceType.IC_READ_STATE: ReadStateParser(),
    SourceType.RAW_GATEWAY: RawGatewayParser(),
    SourceType.DASHBOARD_API: DashboardParser(),
    SourceType.SIGNALS_FEED: SignalsFeedParser(),
}


@dataclass
class IngestResult:
    events_created: int = 0
    events_existing: int = 0
    snapshots_created: int = 0
    snapshots_existing: int = 0
    unparsed: int = 0


def _aware(value: datetime) -> datetime:
    """SQLite drops the timezone on read; all stored times are UTC."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def ioc_canisters(session: Session) -> frozenset[str]:
    flagged = session.scalars(select(Canister.id).where(Canister.is_ioc.is_(True)))
    named = canister_ids_in(session.scalars(select(Ioc.value)))
    return frozenset(flagged) | named


class Ingestor:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        parsers: Mapping[SourceType, Parser] = PARSERS,
    ) -> None:
        self._sessions = session_factory
        self._parsers = parsers

    def ingest(self, snapshots: Iterable[RawSnapshot]) -> IngestResult:
        result = IngestResult()
        with self._sessions() as session, session.begin():
            ioc_join = IocJoinEnricher(ioc_canisters(session))
            for snapshot in snapshots:
                parser = self._parsers.get(snapshot.source_type)
                if parser is None:
                    result.unparsed += 1
                    continue
                source = session.scalar(select(Source).where(Source.name == snapshot.source_name))
                if source is None:
                    raise ValueError(f"raw snapshot {snapshot.id} has no source row")
                parsed = parser.parse(snapshot)
                trust = TrustEnricher({snapshot.source_type: source.reliability})
                for snap in parsed.canister_snapshots:
                    self._store_snapshot(session, source, snap, result)
                for event in ioc_join.enrich(trust.enrich(parsed.events)):
                    self._store_event(session, source, event, result)
        log.info("ingest_done", **result.__dict__)
        return result

    @staticmethod
    def _canister(session: Session, canister_id: str, snap_time: datetime) -> Canister:
        row = session.get(Canister, canister_id)
        if row is None:
            row = Canister(id=canister_id, first_seen=snap_time, last_seen=snap_time)
            session.add(row)
            session.flush()
        return row

    def _store_snapshot(
        self, session: Session, source: Source, snap: CanisterSnapshot, result: IngestResult
    ) -> None:
        canister = self._canister(session, snap.canister_id, snap.observed_at)
        canister.first_seen = min(_aware(canister.first_seen), snap.observed_at)
        canister.last_seen = max(_aware(canister.last_seen), snap.observed_at)
        if snap.subnet is not None:
            canister.subnet = snap.subnet
        if snap.controllers is not None:
            canister.controllers = list(snap.controllers)
        if snap.module_hash is not None:
            canister.module_hash = snap.module_hash
        exists = session.scalar(
            select(CanisterSnapshotRow.id).where(
                CanisterSnapshotRow.canister_id == snap.canister_id,
                CanisterSnapshotRow.raw_snapshot_id == snap.raw_snapshot_id,
                CanisterSnapshotRow.source_id == source.id,
            )
        )
        if exists is not None:
            result.snapshots_existing += 1
            return
        session.add(
            CanisterSnapshotRow(
                canister_id=snap.canister_id,
                observed_at=snap.observed_at,
                source_id=source.id,
                raw_snapshot_id=snap.raw_snapshot_id,
                census_run_id=snap.census_run_id,
                subnet=snap.subnet,
                controllers=list(snap.controllers or ()),
                module_hash=snap.module_hash,
                status=snap.status,
                candid_methods=list(snap.candid_methods) if snap.candid_methods else None,
                candid_sha256=snap.candid_sha256,
            )
        )
        result.snapshots_created += 1

    def _store_event(
        self, session: Session, source: Source, event: Event, result: IngestResult
    ) -> None:
        if event.kind == "canister.candid_observed" and event.payload.get("status") == "ok":
            canister = self._canister(session, str(event.canister_id), event.observed_at)
            canister.candid_methods = event.payload.get("candid_methods")
            canister.candid_sha256 = event.payload.get("candid_sha256")
        key = dedup_key(event)
        if session.scalar(select(EventRow.id).where(EventRow.dedup_key == key)) is not None:
            result.events_existing += 1
            return
        session.add(
            EventRow(
                kind=event.kind,
                subject_type=event.subject_type,
                subject_id=event.subject_id,
                canister_id=event.canister_id,
                observed_at=event.observed_at,
                source_id=source.id,
                source_type=event.source_type,
                raw_snapshot_id=event.raw_snapshot_id,
                parser=event.parser,
                weight=event.weight,
                is_ioc=event.is_ioc,
                payload=event.payload,
                dedup_key=key,
            )
        )
        session.flush()
        result.events_created += 1
