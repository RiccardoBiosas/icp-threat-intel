"""Re-parsing and re-ingesting the same raw snapshots gives identical events, no duplicates."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from icp_threat_intel.core.enums import IocType, SourceType
from icp_threat_intel.core.models import RawSnapshot
from icp_threat_intel.core.trust import default_reliability
from icp_threat_intel.db.models import Canister, EventRow, Ioc, Source
from icp_threat_intel.db.models import CanisterSnapshot as CanisterSnapshotRow
from icp_threat_intel.parsers.base import dedup_key
from icp_threat_intel.parsers.ingest import PARSERS, Ingestor
from icp_threat_intel.raw_store.store import SqlRawStore
from tests.collectors._cassettes import SEED_CANISTERS
from tests.parsers.conftest import collect_all

TDTQY, CJN37 = SEED_CANISTERS


def _count(sessions: sessionmaker[Session], model: type) -> int:
    with sessions() as s:
        return int(s.scalar(select(func.count()).select_from(model)) or 0)


def test_parsing_twice_gives_identical_events(snapshots: list[RawSnapshot]) -> None:
    for snap in snapshots:
        parser = PARSERS[snap.source_type]
        first, second = parser.parse(snap), parser.parse(snap)
        assert first == second
        assert [dedup_key(e) for e in first.events] == [dedup_key(e) for e in second.events]


def test_ingest_is_idempotent(
    sessions: sessionmaker[Session], snapshots: list[RawSnapshot]
) -> None:
    ingestor = Ingestor(sessions)
    first = ingestor.ingest(snapshots)
    assert first.events_created == len(snapshots) == 14
    assert first.snapshots_created == 4  # read_state state + dashboard canister, x2
    events_before = _count(sessions, EventRow)
    second = ingestor.ingest(snapshots)
    assert second.events_created == 0 and second.events_existing == 14
    assert second.snapshots_created == 0 and second.snapshots_existing == 4
    assert _count(sessions, EventRow) == events_before
    assert _count(sessions, CanisterSnapshotRow) == 4


def test_recollecting_identical_bodies_adds_nothing(
    sessions: sessionmaker[Session], store: SqlRawStore, snapshots: list[RawSnapshot]
) -> None:
    Ingestor(sessions).ingest(snapshots)
    again = collect_all(store)  # raw store returns the existing rows
    assert [s.id for s in again] == [s.id for s in snapshots]
    assert Ingestor(sessions).ingest(again).events_created == 0


def test_trust_weights_applied_at_ingest(
    sessions: sessionmaker[Session], snapshots: list[RawSnapshot]
) -> None:
    with sessions() as s, s.begin():
        gateway = s.scalar(select(Source).where(Source.name == "raw_gateway"))
        assert gateway is not None
        gateway.reliability = 33  # operator override on the sources row
    Ingestor(sessions).ingest(snapshots)
    with sessions() as s:
        weights = {(row.source_type, row.weight) for row in s.scalars(select(EventRow)).all()}
    assert weights == {
        (SourceType.IC_READ_STATE, default_reliability(SourceType.IC_READ_STATE)),
        (SourceType.RAW_GATEWAY, 33),
        (SourceType.DASHBOARD_API, default_reliability(SourceType.DASHBOARD_API)),
    }


def test_ioc_membership_and_canister_projection(
    sessions: sessionmaker[Session], snapshots: list[RawSnapshot]
) -> None:
    with sessions() as s, s.begin():
        threatfox = Source(
            name="threatfox",
            source_type=SourceType.THREATFOX,
            base_url="https://threatfox.abuse.ch",
            reliability=default_reliability(SourceType.THREATFOX),
        )
        s.add(threatfox)
        s.flush()
        s.add(
            Ioc(
                ioc_type=IocType.URL,
                value=f"https://{TDTQY}.raw.icp0.io/",
                source_id=threatfox.id,
                source_ref="1781006",
                source_url="https://threatfox.abuse.ch/ioc/1781006/",
            )
        )
    Ingestor(sessions).ingest(snapshots)
    with sessions() as s:
        rows = s.scalars(select(EventRow)).all()
        assert {r.canister_id for r in rows if r.is_ioc} == {TDTQY}
        canister = s.get(Canister, TDTQY)
        assert canister is not None
        assert canister.subnet is not None and canister.module_hash is not None
        assert canister.controllers and canister.candid_sha256
        assert {m["name"] for m in canister.candid_methods or []} >= {"update_link"}
        other = s.get(Canister, CJN37)
        assert other is not None and other.candid_methods is None


def test_unknown_source_types_are_counted_not_parsed(
    sessions: sessionmaker[Session], snapshots: list[RawSnapshot]
) -> None:
    result = Ingestor(sessions, parsers={}).ingest(snapshots)
    assert result.unparsed == len(snapshots) and result.events_created == 0
