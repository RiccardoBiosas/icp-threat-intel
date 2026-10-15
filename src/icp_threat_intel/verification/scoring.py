"""Score stored events with the registered rules and save candidate detections.

The rules stay pure (``rules/``); this module does the database side: load events, run
``rules.engine.run_rules`` and persist each detection as a ``candidate`` through
``verification.store.record_detection`` (one per rule and subject, evidence merged).
"""

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from icp_threat_intel.core.interfaces import Rule
from icp_threat_intel.core.models import Detection, Event
from icp_threat_intel.db.models import EventRow
from icp_threat_intel.rules import all_rules
from icp_threat_intel.rules.engine import run_rules
from icp_threat_intel.verification.store import Outcome, record_detection


def _aware(value: datetime) -> datetime:
    """SQLite drops the timezone on read; stored times are UTC."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def event_from_row(row: EventRow) -> Event:
    return Event(
        id=row.id,
        kind=row.kind,
        subject_type=row.subject_type,
        subject_id=row.subject_id,
        canister_id=row.canister_id,
        observed_at=_aware(row.observed_at),
        source_type=row.source_type,
        parser=row.parser,
        raw_snapshot_id=row.raw_snapshot_id,
        weight=row.weight,
        is_ioc=row.is_ioc,
        payload=row.payload,
    )


def score_stored_events(
    session: Session, rules: Sequence[Rule] | None = None
) -> list[tuple[Detection, int, Outcome]]:
    """Run the rules over every stored event; (detection, row id, outcome) for each.

    One detection is kept per rule and subject (``record_detection``): re-scoring after
    new observations adds evidence to the existing detection instead of duplicating it.
    """
    events = [event_from_row(r) for r in session.scalars(select(EventRow).order_by(EventRow.id))]
    # BaseRule declares id/hypothesis/required_signals as ClassVars, which mypy does not
    # match to the Rule protocol's attributes; tests/rules/test_stubs.py checks
    # isinstance(rule, Rule) for every registered rule at runtime.
    chosen = rules if rules is not None else cast(Sequence[Rule], all_rules())
    detections = run_rules(chosen, events)
    return [(d, *record_detection(session, d)) for d in detections]
