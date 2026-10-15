"""Pipeline CLI commands built so far: ``verify``."""

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
