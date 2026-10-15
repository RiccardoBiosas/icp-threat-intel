"""H2 known-bad lifecycle: IOC canister plus a lifecycle change; neither alone."""

from typing import Any

import pytest

from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.interfaces import Rule
from icp_threat_intel.rules.engine import run_rules
from icp_threat_intel.rules.h2_lifecycle import H2KnownBadLifecycle, derived_changes
from tests.rules._events import TDTQY, event

RULE = H2KnownBadLifecycle()
CTL_A, CTL_B = "aaaaa-aaaaa-aaaaa-aaaaa-cai", "bbbbb-bbbbb-bbbbb-bbbbb-cai"


def _ioc(**kw: Any) -> Any:
    return event("ioc.reported", SourceType.THREATFOX, {"source_ref": "1781006"}, is_ioc=True, **kw)


def _state(module_hash: str | None, controllers: list[str] | None, **kw: Any) -> Any:
    payload = {"status": "ok", "module_hash": module_hash, "controllers": controllers}
    return event("canister.state_observed", SourceType.IC_READ_STATE, payload, **kw)


def _status(frm: str, to: str, **kw: Any) -> Any:
    return event("canister.status_changed", SourceType.DASHBOARD_API, {"from": frm, "to": to}, **kw)


def test_rule_contract() -> None:
    assert isinstance(RULE, Rule)
    assert RULE.id == "H2" and RULE.required_signals == {"ioc_canister", "lifecycle_change"}
    doc = H2KnownBadLifecycle.__doc__ or ""
    assert "CanisterWorm" in doc and "1781006" in doc and "CanisterSprawl" in doc


def test_positive_reenable_after_takedown_reports_hours() -> None:
    takedown = event(
        "gateway.body_observed",
        SourceType.RAW_GATEWAY,
        {"outcome": "ok", "http_status": 451, "denylisted": True},
        minutes=0,
        is_ioc=True,
    )
    flip = _status("stopped", "running", minutes=26 * 60)
    detection = RULE.score([takedown, flip])
    assert detection is not None
    assert detection.signals == {"ioc_canister", "lifecycle_change", "governance_action"}
    assert detection.score == pytest.approx(0.9)
    assert "stopped -> running" in detection.explanation
    assert "26.0 h" in detection.explanation
    assert {r.id for r in detection.evidence_refs} == {takedown.id, flip.id}


@pytest.mark.parametrize(
    ("kind", "payload", "label"),
    [
        ("canister.controllers_changed", {}, "controllers"),
        ("canister.module_hash_changed", {}, "module hash"),
        (
            "census.canister_changed",
            {
                "changes": {
                    "module_hash": {"from": "aa", "to": "bb"},
                    "status": {"from": "stopped", "to": "running"},
                }
            },
            "stopped -> running, module hash",
        ),
    ],
)
def test_positive_explicit_change_events(kind: str, payload: dict[str, Any], label: str) -> None:
    change = event(kind, SourceType.DASHBOARD_API, payload, minutes=10)
    detection = RULE.score([_ioc(), change])
    assert detection is not None
    assert label in detection.explanation
    assert "no earlier governance" in detection.explanation


def test_positive_change_derived_from_consecutive_observations() -> None:
    before = _state("aa" * 32, [CTL_A], minutes=0)
    after = _state("bb" * 32, [CTL_B], minutes=60)
    detection = RULE.score([_ioc(), before, after])
    assert detection is not None
    assert detection.score == pytest.approx(1.0)
    assert "controllers, module hash" in detection.explanation


def test_hours_since_proposal() -> None:
    proposal = event("proposal.references_target", SourceType.NNS, {"proposal_id": 1}, minutes=0)
    detection = RULE.score([_ioc(), proposal, _status("stopped", "running", minutes=90)])
    assert detection is not None and "1.5 h after" in detection.explanation
    assert proposal.id in {r.id for r in detection.evidence_refs}


def test_governance_after_the_change_is_not_counted() -> None:
    late = event("proposal.references_target", SourceType.NNS, {"proposal_id": 2}, minutes=120)
    detection = RULE.score([_ioc(), _status("stopped", "running", minutes=60), late])
    assert detection is not None and "no earlier governance" in detection.explanation


def test_negative_ioc_alone() -> None:
    assert RULE.score([_ioc(), _state("aa" * 32, [CTL_A])]) is None


def test_negative_lifecycle_change_alone() -> None:
    assert RULE.score([_status("stopped", "running")]) is None
    assert RULE.score([_state("aa" * 32, [CTL_A]), _state("bb" * 32, [CTL_A], minutes=5)]) is None


@pytest.mark.parametrize(
    ("frm", "to"), [("running", "stopped"), ("running", "running"), ("stopping", "stopped")]
)
def test_other_status_transitions_do_not_count(frm: str, to: str) -> None:
    assert RULE.score([_ioc(), _status(frm, to)]) is None


def test_unchanged_unknown_or_cross_source_observations_do_not_count() -> None:
    same = [_state("aa" * 32, [CTL_A, CTL_B]), _state("aa" * 32, [CTL_B, CTL_A], minutes=5)]
    assert RULE.score([_ioc(), *same]) is None
    unknown = [_state("aa" * 32, [CTL_A]), _state(None, None, minutes=5)]
    assert RULE.score([_ioc(), *unknown]) is None
    dashboard = event(
        "canister.state_observed",
        SourceType.DASHBOARD_API,
        {"status": "ok", "module_hash": "bb" * 32, "controllers": [CTL_A]},
        minutes=5,
    )
    assert derived_changes([_state("aa" * 32, [CTL_A]), dashboard]) == []


def test_other_canisters_are_not_mixed_in() -> None:
    other = _status("stopped", "running", canister_id="cjn37-uyaaa-aaaac-qgnva-cai")
    assert run_rules([RULE], [_ioc(), other]) == []
    assert [d.subject_id for d in run_rules([RULE], [_ioc(), _status("stopped", "running")])] == [
        TDTQY
    ]
