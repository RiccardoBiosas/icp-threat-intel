"""Persist detections and apply state-machine transitions to stored rows."""

import hashlib
import json
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

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


def save_candidate(session: Session, detection: Detection) -> tuple[int, bool]:
    """Insert a candidate detection unless an identical one exists; (id, created)."""
    if detection.status is not DetectionStatus.CANDIDATE:
        raise ValueError("rules only emit candidates; use transition() to change status")
    key = detection_key(detection)
    existing = session.scalar(select(DetectionRow.id).where(DetectionRow.dedup_key == key))
    if existing is not None:
        return existing, False
    row = DetectionRow(
        rule_id=detection.rule_id,
        rule_version=detection.rule_version,
        subject_type=detection.subject_type,
        subject_id=detection.subject_id,
        canister_id=detection.canister_id,
        score=detection.score,
        weighted_confidence=detection.weighted_confidence,
        signals=sorted(detection.signals),
        evidence_refs=[r.model_dump(mode="json") for r in detection.evidence_refs],
        status=DetectionStatus.CANDIDATE,
        status_history=[{"to": "candidate", "explanation": detection.explanation}],
        dedup_key=key,
    )
    session.add(row)
    session.flush()
    return row.id, True


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
