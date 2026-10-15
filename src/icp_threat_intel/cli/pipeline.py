"""Pipeline CLI commands built so far: ``census`` and ``verify``."""

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
