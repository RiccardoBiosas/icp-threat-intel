"""Persist detections and apply state-machine transitions to stored rows."""

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.orm import Session, object_session

from icp_threat_intel.core.enums import DetectionStatus
from icp_threat_intel.core.models import Detection, EvidenceRef
from icp_threat_intel.db.models import DetectionRow
from icp_threat_intel.verification.state_machine import VerificationStateMachine


class DetectionNotFound(KeyError):
    """No detection has the requested id."""


def detection_key(detection: Detection) -> str:
    """Stable identity: rule, version, subject and the set of evidence refs."""
    refs = sorted((r.ref_type, r.id, str(r.source_type)) for r in detection.evidence_refs)
    material = json.dumps(
        [detection.rule_id, detection.rule_version, detection.subject_type,
         detection.subject_id, refs]
    )  # fmt: skip
    return hashlib.sha256(material.encode()).hexdigest()


def to_model(row: DetectionRow) -> Detection:
    return Detection(
        id=row.id,
        rule_id=row.rule_id,
        rule_version=row.rule_version,
        subject_type=row.subject_type,
        subject_id=row.subject_id,
        canister_id=row.canister_id,
        score=row.score,
        weighted_confidence=row.weighted_confidence,
        signals=frozenset(row.signals),
        evidence_refs=tuple(EvidenceRef.model_validate(r) for r in row.evidence_refs),
        explanation=str((row.status_history or [{}])[0].get("explanation", "")),
        status=row.status,
        status_history=tuple(row.status_history),
    )


Outcome = Literal["created", "updated", "unchanged"]


def _ref_key(ref: Mapping[str, Any]) -> tuple[str, int, str]:
    return (str(ref["ref_type"]), int(ref["id"]), str(ref["source_type"]))


def _merge(row: DetectionRow, detection: Detection, refs: list[dict[str, Any]]) -> Outcome:
    known = {_ref_key(r) for r in row.evidence_refs}
    added = [r for r in refs if _ref_key(r) not in known]
    if not added:
        return "unchanged"
    row.evidence_refs = [*row.evidence_refs, *added]
    row.score = max(row.score, detection.score)
    row.weighted_confidence = max(row.weighted_confidence, detection.weighted_confidence)
    row.signals = sorted(set(row.signals) | detection.signals)
    entry = {"event": "evidence_added", "added": added, "at": datetime.now(UTC).isoformat()}
    row.status_history = [*row.status_history, entry]
    session = object_session(row)
    if session is not None:
        session.flush()
    return "updated"


def record_detection(session: Session, detection: Detection) -> tuple[int, Outcome]:
    """Store a rule's candidate, keeping one detection per rule and subject.

    * An open (candidate or verified) detection for the same rule and subject absorbs the
      new evidence refs; its status never changes here. Returns ``"updated"``, or
      ``"unchanged"`` when every ref was already known.
    * If only dismissed detections exist, the new one is ignored unless it brings
      evidence none of them had; then it becomes a new candidate (``"created"``).
    """
    if detection.status is not DetectionStatus.CANDIDATE:
        raise ValueError("rules only emit candidates; use transition() to change status")
    rows = session.scalars(
        select(DetectionRow)
        .where(
            DetectionRow.rule_id == detection.rule_id,
            DetectionRow.subject_type == detection.subject_type,
            DetectionRow.subject_id == detection.subject_id,
        )
        .order_by(DetectionRow.id)
    ).all()
    refs = [r.model_dump(mode="json") for r in detection.evidence_refs]
    live = [r for r in rows if r.status is not DetectionStatus.DISMISSED]
    if live:
        return live[0].id, _merge(live[0], detection, refs)
    if rows:
        dismissed = {_ref_key(r) for row in rows for r in row.evidence_refs}
        if all(_ref_key(r) in dismissed for r in refs):
            return rows[-1].id, "unchanged"
    row = DetectionRow(
        rule_id=detection.rule_id,
        rule_version=detection.rule_version,
        subject_type=detection.subject_type,
        subject_id=detection.subject_id,
        canister_id=detection.canister_id,
        score=detection.score,
        weighted_confidence=detection.weighted_confidence,
        signals=sorted(detection.signals),
        evidence_refs=refs,
        status=DetectionStatus.CANDIDATE,
        status_history=[{"to": "candidate", "explanation": detection.explanation}],
        dedup_key=detection_key(detection),
    )
    session.add(row)
    session.flush()
    return row.id, "created"


def save_candidate(session: Session, detection: Detection) -> tuple[int, bool]:
    """``record_detection`` reduced to (id, created) for callers that only need that."""
    det_id, outcome = record_detection(session, detection)
    return det_id, outcome == "created"


def transition_row(
    session: Session,
    detection_id: int,
    to: DetectionStatus,
    *,
    actor: str,
    reason: str,
    explicit: bool = False,
    machine: VerificationStateMachine | None = None,
) -> Detection:
    """Load, transition through the state machine, write back. Raises on refusal."""
    row = session.get(DetectionRow, detection_id)
    if row is None:
        raise DetectionNotFound(detection_id)
    machine = machine or VerificationStateMachine()
    updated = machine.transition(to_model(row), to, actor=actor, reason=reason, explicit=explicit)
    at = datetime.fromisoformat(updated.status_history[-1]["at"])
    row.status = updated.status
    row.status_history = list(updated.status_history)
    if to is DetectionStatus.VERIFIED:
        row.verified_at = at
    if to is DetectionStatus.DISMISSED:
        row.dismissed_at = at
    session.flush()
    return updated
