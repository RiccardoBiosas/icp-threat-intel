"""Group events by subject and run rules over each group. Pure: no I/O, no clock.

Persisting the resulting candidate detections is the caller's job (CLI ``score``).
"""

from collections.abc import Iterable, Sequence

from icp_threat_intel.core.interfaces import Rule
from icp_threat_intel.core.models import Detection, Event


def group_by_subject(events: Iterable[Event]) -> dict[tuple[str, str], list[Event]]:
    groups: dict[tuple[str, str], list[Event]] = {}
    for event in events:
        groups.setdefault((event.subject_type, event.subject_id), []).append(event)
    for group in groups.values():
        group.sort(key=lambda e: (e.observed_at, e.id or 0, e.kind))
    return dict(sorted(groups.items()))


def run_rules(rules: Sequence[Rule], events: Iterable[Event]) -> list[Detection]:
    """Every (rule, subject) pair that yields a detection, in a stable order."""
    detections = []
    for _subject, group in group_by_subject(events).items():
        for rule in rules:
            detection = rule.score(group)
            if detection is not None:
                detections.append(detection)
    return detections
