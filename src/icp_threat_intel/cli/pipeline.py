"""Pipeline CLI commands: ``parse``, ``enrich``, ``score``, ``verify`` and ``census``."""

from typing import Annotated

import typer

from icp_threat_intel.core.enums import DetectionStatus
from icp_threat_intel.core.evidence import InsufficientEvidence
from icp_threat_intel.verification.state_machine import IllegalTransition
from icp_threat_intel.verification.store import DetectionNotFound, transition_row


def verify(
    detection_id: Annotated[int, typer.Argument(help="Detection id.")],
    to: Annotated[DetectionStatus, typer.Option("--to", help="Target status.")],
    actor: Annotated[str, typer.Option("--actor", help="Who decides (recorded).")],
    reason: Annotated[str, typer.Option("--reason", help="Why (recorded).")] = "",
    explicit: Annotated[
        bool, typer.Option("--explicit", help="Required to dismiss a verified detection.")
    ] = False,
) -> None:
    """Move a detection through the two-signal verification state machine."""
    from icp_threat_intel.db.session import make_engine, make_session_factory

    engine = make_engine()
    try:
        with make_session_factory(engine)() as session, session.begin():
            updated = transition_row(
                session, detection_id, to, actor=actor, reason=reason, explicit=explicit
            )
    except DetectionNotFound:
        typer.echo(f"detection {detection_id} not found", err=True)
        raise typer.Exit(code=1) from None
    except (IllegalTransition, InsufficientEvidence) as exc:
        typer.echo(f"refused: {exc}", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(f"detection {detection_id}: {updated.status_history[-1]['from']} -> {to.value}")


def census(
    ceiling: Annotated[
        int | None, typer.Option("--ceiling", help="Max canisters (default from settings).")
    ] = None,
) -> None:
    """Walk subnets via the Dashboard API and diff against the previous run."""
    from icp_threat_intel.census.run import run_census
    from icp_threat_intel.census.walker import CensusWalker
    from icp_threat_intel.core.config import Settings
    from icp_threat_intel.core.http import SafeHttpClient
    from icp_threat_intel.db.session import make_engine, make_session_factory
    from icp_threat_intel.raw_store.store import SqlRawStore

    settings = Settings.from_env()
    if not settings.contact:
        typer.echo("census needs ICP_THREAT_INTEL_CONTACT (sent in the User-Agent)", err=True)
        raise typer.Exit(code=2)
    sessions = make_session_factory(make_engine())
    with SafeHttpClient(settings.contact) as http:
        walker = CensusWalker(
            http, SqlRawStore(sessions), ceiling=ceiling or settings.census_max_canisters
        )
        walk, diff = run_census(sessions, walker)
    typer.echo(
        f"census {walk.run_id}: {len(walk.states)} canisters, +{len(diff.added)} "
        f"-{len(diff.removed)} ~{len(diff.changed)}, complete subnets "
        f"{len(walk.complete_subnets)}, incomplete {len(walk.incomplete_subnets)}, "
        f"ceiling hit: {walk.ceiling_hit}"
    )


def parse() -> None:
    """Parse raw snapshots into normalized events (trust weights and IOC flags at ingest)."""
    from icp_threat_intel.core.enums import SourceType
    from icp_threat_intel.db.session import make_engine, make_session_factory
    from icp_threat_intel.parsers.ingest import PARSERS, Ingestor
    from icp_threat_intel.raw_store.store import SqlRawStore

    sessions = make_session_factory(make_engine())
    store = SqlRawStore(sessions)
    snapshots = [s for t in SourceType if t in PARSERS for s in store.iter_snapshots(t)]
    result = Ingestor(sessions).ingest(snapshots)
    typer.echo(
        f"parse: {len(snapshots)} snapshot(s): {result.events_created} new event(s), "
        f"{result.snapshots_created} new canister snapshot(s) "
        f"({result.events_existing} event(s) already stored)"
    )


def enrich() -> None:
    """Re-apply IOC membership to stored events (after IOCs were added or removed)."""
    from icp_threat_intel.db.session import make_engine, make_session_factory
    from icp_threat_intel.enrichment.refresh import refresh_ioc_flags

    with make_session_factory(make_engine())() as session, session.begin():
        marked, unmarked = refresh_ioc_flags(session)
    typer.echo(f"enrich: {marked} event(s) marked IOC, {unmarked} unmarked")


def score() -> None:
    """Run detection rules H1-H6 over stored events and record candidate detections."""
    from sqlalchemy import func, select

    from icp_threat_intel.db.models import EventRow
    from icp_threat_intel.db.session import make_engine, make_session_factory
    from icp_threat_intel.verification.scoring import score_stored_events

    with make_session_factory(make_engine())() as session, session.begin():
        events = session.scalar(select(func.count()).select_from(EventRow)) or 0
        results = score_stored_events(session)
    new = [(d, det_id) for d, det_id, created in results if created]
    typer.echo(
        f"score: {events} event(s), {len(results)} detection(s), "
        f"{len(new)} new candidate detection(s)"
    )
    for detection, det_id in new:
        typer.echo(
            f"  #{det_id} {detection.rule_id}  {detection.subject_id}  "
            f"score={detection.score:.2f} confidence={detection.weighted_confidence:.2f}"
        )
