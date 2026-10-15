"""Guardrail 8: a detection reaches ``verified`` only with two different source types.

Checked at every layer that can set the status: the state machine, the ``Detection``
model and the ``detections`` table.
"""

from collections.abc import Iterator

import pytest
from pydantic import ValidationError
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from icp_threat_intel.core.enums import DetectionStatus, SourceType
from icp_threat_intel.core.evidence import InsufficientEvidence
from icp_threat_intel.core.models import Detection, EvidenceRef
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import DetectionRow
from icp_threat_intel.db.session import make_engine, make_session_factory
from icp_threat_intel.verification.state_machine import VerificationStateMachine

CANISTER = "tdtqy-oyaaa-aaaae-af2dq-cai"


def _ref(i: int, source_type: SourceType) -> EvidenceRef:
    return EvidenceRef(ref_type="event", id=i, source_type=source_type)


def _candidate(*refs: EvidenceRef) -> Detection:
    return Detection(
        rule_id="H1",
        subject_type="canister",
        subject_id=CANISTER,
        canister_id=CANISTER,
        score=0.9,
        signals=frozenset({"setter_getter_pair", "small_text_body"}),
        evidence_refs=refs,
        explanation="test",
    )


SINGLE_SIGNAL = (_ref(1, SourceType.IC_READ_STATE),)
TWO_REFS_SAME_SOURCE = (_ref(1, SourceType.RAW_GATEWAY), _ref(2, SourceType.RAW_GATEWAY))
NO_EVIDENCE: tuple[EvidenceRef, ...] = ()
TWO_SOURCES = (_ref(1, SourceType.IC_READ_STATE), _ref(2, SourceType.RAW_GATEWAY))
INSUFFICIENT = [SINGLE_SIGNAL, TWO_REFS_SAME_SOURCE, NO_EVIDENCE]


@pytest.fixture
def session() -> Iterator[Session]:
    engine: Engine = make_engine("sqlite://")
    Base.metadata.create_all(engine)
    with make_session_factory(engine)() as s:
        yield s
    engine.dispose()


@pytest.mark.parametrize("refs", INSUFFICIENT, ids=["single", "same-source", "none"])
def test_state_machine_refuses_to_verify(refs: tuple[EvidenceRef, ...]) -> None:
    detection = _candidate(*refs)
    with pytest.raises(InsufficientEvidence):
        VerificationStateMachine().transition(
            detection, DetectionStatus.VERIFIED, actor="analyst", reason="looks bad"
        )
    assert detection.status is DetectionStatus.CANDIDATE


def test_many_refs_from_one_source_type_still_refused() -> None:
    refs = tuple(_ref(i, SourceType.THREATFOX) for i in range(10))
    with pytest.raises(InsufficientEvidence):
        VerificationStateMachine().transition(
            _candidate(*refs), DetectionStatus.VERIFIED, actor="analyst", reason="x"
        )


def test_two_different_source_types_verify() -> None:
    verified = VerificationStateMachine().transition(
        _candidate(*TWO_SOURCES), DetectionStatus.VERIFIED, actor="analyst", reason="confirmed"
    )
    assert verified.status is DetectionStatus.VERIFIED


@pytest.mark.parametrize("refs", INSUFFICIENT, ids=["single", "same-source", "none"])
def test_model_cannot_be_built_as_verified(refs: tuple[EvidenceRef, ...]) -> None:
    with pytest.raises(ValidationError):
        Detection.model_validate(_candidate(*refs).model_dump() | {"status": "verified"})


@pytest.mark.parametrize("refs", INSUFFICIENT, ids=["single", "same-source", "none"])
def test_model_copy_cannot_skip_to_verified(refs: tuple[EvidenceRef, ...]) -> None:
    with pytest.raises(InsufficientEvidence):
        _candidate(*refs).model_copy(update={"status": DetectionStatus.VERIFIED})


@pytest.mark.parametrize("refs", INSUFFICIENT, ids=["single", "same-source", "none"])
def test_database_refuses_verified_row(session: Session, refs: tuple[EvidenceRef, ...]) -> None:
    row = DetectionRow(
        rule_id="H1",
        subject_type="canister",
        subject_id=CANISTER,
        score=0.9,
        evidence_refs=[r.model_dump(mode="json") for r in refs],
        status=DetectionStatus.VERIFIED,
        dedup_key="k" * 64,
    )
    session.add(row)
    with pytest.raises(InsufficientEvidence):
        session.flush()


def test_database_refuses_update_to_verified(session: Session) -> None:
    row = DetectionRow(
        rule_id="H1",
        subject_type="canister",
        subject_id=CANISTER,
        score=0.9,
        evidence_refs=[r.model_dump(mode="json") for r in TWO_REFS_SAME_SOURCE],
        dedup_key="u" * 64,
    )
    session.add(row)
    session.flush()
    row.status = DetectionStatus.VERIFIED
    with pytest.raises(InsufficientEvidence):
        session.flush()
