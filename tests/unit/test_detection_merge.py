"""One detection per rule and subject: new evidence is merged, not duplicated."""

from collections.abc import Iterator

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from icp_threat_intel.core.enums import DetectionStatus, SourceType
from icp_threat_intel.core.models import Detection, EvidenceRef
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import DetectionRow
from icp_threat_intel.db.session import make_engine, make_session_factory
from icp_threat_intel.verification.store import record_detection, save_candidate, transition_row

TDTQY, CJN37 = "tdtqy-oyaaa-aaaae-af2dq-cai", "cjn37-uyaaa-aaaac-qgnva-cai"


def _ref(i: int, st: SourceType = SourceType.IC_READ_STATE) -> EvidenceRef:
    return EvidenceRef(ref_type="event", id=i, source_type=st)


BASE = (_ref(1), _ref(2, SourceType.RAW_GATEWAY))


def _det(
    refs: tuple[EvidenceRef, ...] = BASE, subject: str = TDTQY, score: float = 0.8
) -> Detection:
    return Detection(
        rule_id="H1", subject_type="canister", subject_id=subject, canister_id=subject,
        score=score, weighted_confidence=0.9, signals=frozenset({"a", "b"}),
        evidence_refs=refs, explanation="x",
    )  # fmt: skip


@pytest.fixture
def session() -> Iterator[Session]:
    engine = make_engine("sqlite://")
    Base.metadata.create_all(engine)
    with make_session_factory(engine)() as s:
        yield s
    engine.dispose()


def _rows(session: Session) -> int:
    return int(session.scalar(select(func.count()).select_from(DetectionRow)) or 0)


def test_new_evidence_is_merged_into_the_open_candidate(session: Session) -> None:
    first, outcome = record_detection(session, _det())
    assert outcome == "created"
    again, outcome = record_detection(session, _det((*BASE, _ref(3)), score=0.95))
    assert (again, outcome) == (first, "updated") and _rows(session) == 1
    row = session.get(DetectionRow, first)
    assert row is not None
    assert {r["id"] for r in row.evidence_refs} == {1, 2, 3}
    assert row.score == pytest.approx(0.95)  # best score seen
    assert row.status is DetectionStatus.CANDIDATE
    assert row.status_history[-1]["event"] == "evidence_added"
    assert row.status_history[-1]["added"] == [
        {"ref_type": "event", "id": 3, "source_type": "ic_read_state"}
    ]


def test_same_evidence_is_unchanged(session: Session) -> None:
    first, _ = record_detection(session, _det())
    assert record_detection(session, _det()) == (first, "unchanged")
    assert save_candidate(session, _det()) == (first, False)


def test_other_subjects_and_rules_stay_separate(session: Session) -> None:
    record_detection(session, _det())
    _, outcome = record_detection(session, _det(subject=CJN37))
    assert outcome == "created"
    other_rule = _det().model_copy(update={"rule_id": "H2"})
    assert record_detection(session, other_rule)[1] == "created"
    assert _rows(session) == 3


def test_verified_detection_gains_evidence_and_keeps_its_status(session: Session) -> None:
    det_id, _ = record_detection(session, _det())
    transition_row(session, det_id, DetectionStatus.VERIFIED, actor="a", reason="ok")
    assert record_detection(session, _det((*BASE, _ref(4)))) == (det_id, "updated")
    row = session.get(DetectionRow, det_id)
    assert row is not None and row.status is DetectionStatus.VERIFIED
    assert {r["id"] for r in row.evidence_refs} == {1, 2, 4}


def test_dismissed_detection_reopens_only_on_new_evidence(session: Session) -> None:
    det_id, _ = record_detection(session, _det())
    transition_row(session, det_id, DetectionStatus.DISMISSED, actor="a", reason="benign")
    assert record_detection(session, _det((_ref(1),))) == (det_id, "unchanged")
    new_id, outcome = record_detection(session, _det((*BASE, _ref(5))))
    assert outcome == "created" and new_id != det_id
    assert _rows(session) == 2


def test_an_open_candidate_wins_over_older_dismissed_ones(session: Session) -> None:
    old, _ = record_detection(session, _det())
    transition_row(session, old, DetectionStatus.DISMISSED, actor="a", reason="noise")
    current, _ = record_detection(session, _det((*BASE, _ref(6))))
    assert record_detection(session, _det((*BASE, _ref(6), _ref(7)))) == (current, "updated")
