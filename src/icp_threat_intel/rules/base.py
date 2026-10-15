"""Shared rule machinery: the rule contract, evidence references and detections.

Rules are pure (PLAN "Rule interface"): they get every enriched event for one subject,
never touch the network, the database or the clock, and only ever emit ``candidate``
detections. ``score`` returns a detection only when every required signal has support.
"""

import re
from collections.abc import Sequence
from typing import ClassVar

from icp_threat_intel.core.models import Detection, Event, EvidenceRef
from icp_threat_intel.core.trust import weighted_confidence

CANISTER_ID_RE = re.compile(r"\b(?:[a-z2-7]{5}-){4}cai\b")


def evidence_ref(event: Event) -> EvidenceRef | None:
    """Point at the stored event, else at its raw snapshot; ``None`` if neither exists."""
    if event.id is not None:
        return EvidenceRef(ref_type="event", id=event.id, source_type=event.source_type)
    if event.raw_snapshot_id is not None:
        return EvidenceRef(
            ref_type="raw_snapshot", id=event.raw_snapshot_id, source_type=event.source_type
        )
    return None


class BaseRule:
    id: ClassVar[str]
    hypothesis: ClassVar[str]
    required_signals: ClassVar[frozenset[str]]
    version: ClassVar[str] = "1"

    def signals(self, events: Sequence[Event]) -> dict[str, list[Event]]:
        """Signal name -> supporting events (only signals with support appear)."""
        raise NotImplementedError

    def assess(self, support: dict[str, list[Event]]) -> tuple[float, str]:
        """Score (0-1) and explanation, called only when all required signals hold."""
        raise NotImplementedError

    def score(self, events: Sequence[Event]) -> Detection | None:
        support = {name: evs for name, evs in self.signals(events).items() if evs}
        if not self.required_signals <= set(support):
            return None
        supporting = sorted(
            {id(e): e for evs in support.values() for e in evs}.values(),
            key=lambda e: (e.observed_at, e.id or 0, e.kind),
        )
        refs = tuple(r for r in (evidence_ref(e) for e in supporting) if r is not None)
        subject = supporting[-1]
        score, explanation = self.assess(support)
        return Detection(
            rule_id=self.id,
            rule_version=self.version,
            subject_type=subject.subject_type,
            subject_id=subject.subject_id,
            canister_id=subject.canister_id,
            score=round(min(max(score, 0.0), 1.0), 6),
            weighted_confidence=weighted_confidence((e.source_type, e.weight) for e in supporting),
            signals=frozenset(support),
            evidence_refs=refs,
            explanation=explanation,
        )
