"""Verification state machine: every transition, audited dismissal, storage and CLI."""

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy.orm import Session
from typer.testing import CliRunner

from icp_threat_intel.cli.app import app
from icp_threat_intel.core.enums import DetectionStatus, SourceType
from icp_threat_intel.core.evidence import InsufficientEvidence, distinct_source_types
from icp_threat_intel.core.interfaces import Verifier
from icp_threat_intel.core.models import Detection, EvidenceRef
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import DetectionRow
from icp_threat_intel.db.session import make_engine, make_session_factory
from icp_threat_intel.verification.state_machine import IllegalTransition, VerificationStateMachine
from icp_threat_intel.verification.store import (
    DetectionNotFound,
    save_candidate,
    to_model,
    transition_row,
)

C, V, D = DetectionStatus.CANDIDATE, DetectionStatus.VERIFIED, DetectionStatus.DISMISSED
T = datetime(2026, 10, 15, 9, 0, tzinfo=UTC)
CANISTER = "tdtqy-oyaaa-aaaae-af2dq-cai"
MACHINE = VerificationStateMachine(clock=lambda: T)
TWO = (
    EvidenceRef(ref_type="event", id=1, source_type=SourceType.IC_READ_STATE),
    EvidenceRef(ref_type="raw_snapshot", id=2, source_type=SourceType.RAW_GATEWAY),
)
ONE = TWO[:1]


def _det(refs: tuple[EvidenceRef, ...] = TWO) -> Detection:
    return Detection(
        rule_id="H1",
        subject_type="canister",
        subject_id=CANISTER,
        canister_id=CANISTER,
        score=0.9,
        weighted_confidence=0.95,
        signals=frozenset({"setter_getter_pair", "small_text_body"}),
        evidence_refs=refs,
        explanation="dead drop",
    )


def _verified() -> Detection:
    return MACHINE.transition(_det(), V, actor="a", reason="ok")


def test_protocol() -> None:
    assert isinstance(MACHINE, Verifier)


def test_candidate_to_verified_records_history() -> None:
    verified = _verified()
    assert verified.status is V
    assert verified.status_history == (
        {"from": "candidate", "to": "verified", "actor": "a", "reason": "ok",
         "at": T.isoformat(), "explicit": False},
    )  # fmt: skip


def test_candidate_to_dismissed_needs_reason_and_works_with_one_signal() -> None:
    with pytest.raises(IllegalTransition):
        MACHINE.transition(_det(ONE), D, actor="a", reason=" ")
    dismissed = MACHINE.transition(_det(ONE), D, actor="a", reason="benign")
    assert dismissed.status is D


def test_verified_is_terminal_except_explicit_audited_dismissal() -> None:
    verified = _verified()
    with pytest.raises(IllegalTransition, match="explicit"):
        MACHINE.transition(verified, D, actor="a", reason="mistake")
    with pytest.raises(IllegalTransition):
        MACHINE.transition(verified, D, actor="a", reason="", explicit=True)
    dismissed = MACHINE.transition(
        verified, D, actor="lead", reason="false positive", explicit=True
    )
    assert dismissed.status is D
    assert [h["to"] for h in dismissed.status_history] == ["verified", "dismissed"]
    assert dismissed.status_history[-1]["explicit"] is True
    assert dismissed.status_history[-1]["actor"] == "lead"


@pytest.mark.parametrize(
    ("start", "to"),
    [(C, C), (V, V), (V, C), (D, D), (D, C), (D, V)],
)
def test_illegal_transitions(start: DetectionStatus, to: DetectionStatus) -> None:
    detection = {C: _det(), V: _verified()}.get(start) or MACHINE.transition(
        _det(), D, actor="a", reason="r"
    )
    with pytest.raises(IllegalTransition):
        MACHINE.transition(detection, to, actor="a", reason="r", explicit=True)


def test_actor_required() -> None:
    with pytest.raises(IllegalTransition, match="actor"):
        MACHINE.transition(_det(), V, actor="", reason="r")


def test_distinct_source_types_reads_models_and_dicts() -> None:
    dicts = [r.model_dump(mode="json") for r in TWO] + [{"id": 3}]
    assert distinct_source_types(dicts) == {"ic_read_state", "raw_gateway"}


@pytest.fixture
def db_url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'det.db'}"


@pytest.fixture
def session(db_url: str) -> Iterator[Session]:
    engine = make_engine(db_url)
    Base.metadata.create_all(engine)
    with make_session_factory(engine)() as s:
        yield s
    engine.dispose()


def test_save_candidate_is_idempotent_and_round_trips(session: Session) -> None:
    det_id, created = save_candidate(session, _det())
    again, created_again = save_candidate(session, _det())
    assert created and not created_again and again == det_id
    row = session.get(DetectionRow, det_id)
    assert row is not None
    model = to_model(row)
    assert model.evidence_refs == TWO and model.explanation == "dead drop"
    with pytest.raises(ValueError):
        save_candidate(session, _verified())


def test_transition_row_updates_status_and_timestamps(session: Session) -> None:
    det_id, _ = save_candidate(session, _det())
    transition_row(session, det_id, V, actor="a", reason="ok", machine=MACHINE)
    row = session.get(DetectionRow, det_id)
    assert row is not None and row.status is V and row.verified_at is not None
    transition_row(session, det_id, D, actor="a", reason="fp", explicit=True, machine=MACHINE)
    assert row.status is D and row.dismissed_at is not None
    assert [h.get("to") for h in row.status_history] == ["candidate", "verified", "dismissed"]
    with pytest.raises(DetectionNotFound):
        transition_row(session, 999, V, actor="a", reason="r")


def test_transition_row_refuses_single_signal(session: Session) -> None:
    det_id, _ = save_candidate(session, _det(ONE))
    with pytest.raises(InsufficientEvidence):
        transition_row(session, det_id, V, actor="a", reason="r")


def test_cli_verify(db_url: str, session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    good, _ = save_candidate(session, _det())
    weak, _ = save_candidate(session, _det(ONE))
    session.commit()
    monkeypatch.setenv("ICP_THREAT_INTEL_DATABASE_URL", db_url)
    runner = CliRunner()
    ok = runner.invoke(
        app, ["verify", str(good), "--to", "verified", "--actor", "me", "--reason", "x"]
    )
    assert ok.exit_code == 0, ok.output
    assert "candidate -> verified" in ok.output
    refused = runner.invoke(app, ["verify", str(weak), "--to", "verified", "--actor", "me"])
    assert refused.exit_code == 1 and "refused" in refused.output
    missing = runner.invoke(app, ["verify", "999", "--to", "dismissed", "--actor", "me"])
    assert missing.exit_code == 1 and "not found" in missing.output
