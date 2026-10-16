"""Guardrail 8 extension: signal sources never count towards the two signals.

``signals_feed`` (community forums) is low-authority prose anyone can post. It may support
a detection as evidence, but ``verified`` still needs two different *authoritative* source
types, at every layer that can set the status: the state machine, the ``Detection`` model
(including ``model_copy``) and the ``detections`` table.
"""

from collections.abc import Iterator

import pytest
from pydantic import ValidationError
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from icp_threat_intel.core.enums import DetectionStatus, SourceType
from icp_threat_intel.core.evidence import (
    SIGNAL_SOURCE_TYPES,
    InsufficientEvidence,
    authoritative_source_types,
)
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


ONE_AUTHORITATIVE_PLUS_SIGNAL = (
    _ref(1, SourceType.IC_READ_STATE),
    _ref(2, SourceType.SIGNALS_FEED),
)
SIGNALS_ONLY = (_ref(1, SourceType.SIGNALS_FEED), _ref(2, SourceType.SIGNALS_FEED))
INSUFFICIENT = [ONE_AUTHORITATIVE_PLUS_SIGNAL, SIGNALS_ONLY]
IDS = ["one-authoritative-plus-signal", "signals-only"]
TWO_AUTHORITATIVE_PLUS_SIGNAL = (
    _ref(1, SourceType.IC_READ_STATE),
    _ref(2, SourceType.RAW_GATEWAY),
    _ref(3, SourceType.SIGNALS_FEED),
)


@pytest.fixture
def session() -> Iterator[Session]:
    engine: Engine = make_engine("sqlite://")
    Base.metadata.create_all(engine)
    with make_session_factory(engine)() as s:
        yield s
    engine.dispose()


def test_signals_feed_is_a_signal_source() -> None:
    assert SourceType.SIGNALS_FEED in SIGNAL_SOURCE_TYPES
    assert SourceType.VENDOR_RSS not in SIGNAL_SOURCE_TYPES


def test_authoritative_types_exclude_signal_sources() -> None:
    types = authoritative_source_types(ONE_AUTHORITATIVE_PLUS_SIGNAL)
    assert types == frozenset({str(SourceType.IC_READ_STATE)})


@pytest.mark.parametrize("refs", INSUFFICIENT, ids=IDS)
def test_state_machine_refuses_to_verify(refs: tuple[EvidenceRef, ...]) -> None:
    detection = _candidate(*refs)
    with pytest.raises(InsufficientEvidence, match="signal"):
        VerificationStateMachine().transition(
            detection, DetectionStatus.VERIFIED, actor="analyst", reason="forum says so"
        )
    assert detection.status is DetectionStatus.CANDIDATE


@pytest.mark.parametrize("refs", INSUFFICIENT, ids=IDS)
def test_model_cannot_be_built_as_verified(refs: tuple[EvidenceRef, ...]) -> None:
    with pytest.raises(ValidationError):
        Detection.model_validate(_candidate(*refs).model_dump() | {"status": "verified"})


@pytest.mark.parametrize("refs", INSUFFICIENT, ids=IDS)
def test_model_copy_cannot_skip_to_verified(refs: tuple[EvidenceRef, ...]) -> None:
    with pytest.raises(InsufficientEvidence):
        _candidate(*refs).model_copy(update={"status": DetectionStatus.VERIFIED})


@pytest.mark.parametrize("refs", INSUFFICIENT, ids=IDS)
def test_database_refuses_verified_row(session: Session, refs: tuple[EvidenceRef, ...]) -> None:
    row = DetectionRow(
        rule_id="H1",
        subject_type="canister",
        subject_id=CANISTER,
        score=0.9,
        evidence_refs=[r.model_dump(mode="json") for r in refs],
        status=DetectionStatus.VERIFIED,
        dedup_key="s" * 64,
    )
    session.add(row)
    with pytest.raises(InsufficientEvidence):
        session.flush()


def test_signal_evidence_may_sit_beside_two_authoritative_sources() -> None:
    verified = VerificationStateMachine().transition(
        _candidate(*TWO_AUTHORITATIVE_PLUS_SIGNAL),
        DetectionStatus.VERIFIED,
        actor="analyst",
        reason="confirmed on-chain and at the gateway",
    )
    assert verified.status is DetectionStatus.VERIFIED
