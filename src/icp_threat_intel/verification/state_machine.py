"""Guarded detection status transitions with the two-signal rule and an audit trail.

Allowed:

* ``candidate -> verified``: at least two evidence refs from different source types
  (``core.evidence``); otherwise ``InsufficientEvidence``.
* ``candidate -> dismissed``: always, with a reason.
* ``verified -> dismissed``: only with ``explicit=True`` and a non-empty reason (an
  audited reversal).

Every other transition raises ``IllegalTransition``, including anything out of
``dismissed`` and staying in place. Each accepted transition appends an entry to
``status_history`` (from, to, actor, reason, at, explicit).
"""

from collections.abc import Callable
from datetime import UTC, datetime

from icp_threat_intel.core.enums import DetectionStatus
from icp_threat_intel.core.evidence import InsufficientEvidence, require_two_signals
from icp_threat_intel.core.models import Detection

__all__ = ["IllegalTransition", "InsufficientEvidence", "VerificationStateMachine"]

C, V, D = DetectionStatus.CANDIDATE, DetectionStatus.VERIFIED, DetectionStatus.DISMISSED
ALLOWED = frozenset({(C, V), (C, D), (V, D)})


class IllegalTransition(ValueError):
    """The requested status change is not allowed from the current status."""


def _now() -> datetime:
    return datetime.now(UTC)


class VerificationStateMachine:
    """Implements the ``Verifier`` protocol."""

    def __init__(self, clock: Callable[[], datetime] = _now) -> None:
        self._clock = clock

    def transition(
        self,
        detection: Detection,
        to: DetectionStatus,
        *,
        actor: str,
        reason: str,
        explicit: bool = False,
    ) -> Detection:
        current = detection.status
        if (current, to) not in ALLOWED:
            raise IllegalTransition(f"{current} -> {to} is not allowed")
        if not actor.strip():
            raise IllegalTransition("an actor is required for every transition")
        if to is D and not reason.strip():
            raise IllegalTransition("dismissal needs a reason")
        if (current, to) == (V, D) and not explicit:
            raise IllegalTransition("verified is terminal; dismissing it needs explicit=True")
        if to is V:
            require_two_signals(detection.evidence_refs)
        entry = {
            "from": current.value,
            "to": to.value,
            "actor": actor,
            "reason": reason,
            "at": self._clock().isoformat(),
            "explicit": explicit,
        }
        return detection.model_copy(
            update={"status": to, "status_history": (*detection.status_history, entry)}
        )
