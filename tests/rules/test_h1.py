"""H1 dead-drop C2: both signals required; each signal alone is not a detection."""

from typing import Any

import pytest

from icp_threat_intel.core.enums import DetectionStatus, SourceType
from icp_threat_intel.core.interfaces import Rule
from icp_threat_intel.core.trust import default_reliability, weighted_confidence
from icp_threat_intel.rules.engine import group_by_subject, run_rules
from icp_threat_intel.rules.h1_dead_drop import (
    SMALL_BODY_BYTES,
    H1DeadDropC2,
    setter_getter_pairs,
)
from tests.rules._events import TDTQY, candid, event, gateway_body, method

CANISTERWORM_METHODS = (
    method("get_latest_link", "query", rets=("text",)),
    method("http_request", "query", ("HttpRequest",), ("HttpResponse",)),
    method("update_link", "update", ("text",)),
)
RULE = H1DeadDropC2()


def test_rule_contract() -> None:
    assert isinstance(RULE, Rule)
    assert RULE.id == "H1"
    assert RULE.required_signals == {"setter_getter_pair", "small_text_body"}
    assert "CanisterWorm" in (H1DeadDropC2.__doc__ or "")
    assert "tdtqy-oyaaa-aaaae-af2dq-cai" in (H1DeadDropC2.__doc__ or "")


def test_positive_canisterworm_pattern() -> None:
    pair, body = candid(*CANISTERWORM_METHODS), gateway_body("url")
    detection = RULE.score([pair, body])
    assert detection is not None
    assert detection.rule_id == "H1"
    assert detection.status is DetectionStatus.CANDIDATE
    assert detection.subject_id == detection.canister_id == TDTQY
    assert detection.signals == {"setter_getter_pair", "small_text_body"}
    assert {r.id for r in detection.evidence_refs} == {pair.id, body.id}
    assert {r.source_type for r in detection.evidence_refs} == {
        SourceType.IC_READ_STATE,
        SourceType.RAW_GATEWAY,
    }
    assert detection.score == pytest.approx(1.0)
    expected = weighted_confidence(
        [
            (SourceType.IC_READ_STATE, default_reliability(SourceType.IC_READ_STATE)),
            (SourceType.RAW_GATEWAY, default_reliability(SourceType.RAW_GATEWAY)),
        ]
    )
    assert detection.weighted_confidence == pytest.approx(expected)
    assert "update_link/get_latest_link" in detection.explanation


@pytest.mark.parametrize(
    ("methods", "body_class", "score"),
    [
        ((method("set", "update", ("text",)), method("get", "query")), "base64_blob", 0.7),
        ((method("put", "update"), method("fetch", "query")), "shell_fragment", 0.7),
        ((method("set_url", "update"), method("get_url", "query")), "url", 1.0),
    ],
)
def test_positive_other_pairs(
    methods: tuple[dict[str, Any], ...], body_class: str, score: float
) -> None:
    detection = RULE.score([candid(*methods), gateway_body(body_class)])
    assert detection is not None
    assert detection.score == pytest.approx(score)


def test_negative_setter_getter_pair_alone() -> None:
    assert RULE.score([candid(*CANISTERWORM_METHODS)]) is None


def test_negative_small_body_alone() -> None:
    assert RULE.score([gateway_body("url")]) is None
    assert RULE.score([gateway_body("shell_fragment"), gateway_body("base64_blob")]) is None


@pytest.mark.parametrize(
    "body",
    [
        gateway_body("url", SMALL_BODY_BYTES + 1),
        gateway_body("url", 0),
        gateway_body("url", truncated=True),
        gateway_body("url", status=404),
        gateway_body("binary"),
        gateway_body("other"),
        gateway_body("empty", 0),
    ],
)
def test_bodies_that_are_not_small_c2_text(body: Any) -> None:
    assert RULE.score([candid(*CANISTERWORM_METHODS), body]) is None


def test_failed_fetch_outcomes_do_not_count() -> None:
    body = gateway_body("url")
    timed_out = body.model_copy(update={"payload": {**body.payload, "outcome": "timeout"}})
    assert RULE.score([candid(*CANISTERWORM_METHODS), timed_out]) is None


def test_precheck_reply_body_counts_as_the_body_signal() -> None:
    payload = {"outcome": "ok", "response_status_code": 200, "body_class": "url", "size": 40}
    queried = event("gateway.http_request_queried", SourceType.RAW_GATEWAY, payload)
    assert RULE.score([candid(*CANISTERWORM_METHODS), queried]) is not None
    no_200 = event(
        "gateway.http_request_queried",
        SourceType.RAW_GATEWAY,
        {**payload, "response_status_code": 404},
    )
    assert RULE.score([candid(*CANISTERWORM_METHODS), no_200]) is None


@pytest.mark.parametrize(
    "methods",
    [
        (method("update_link", "update"),),  # setter only
        (method("get_link", "query"),),  # getter only
        (method("update_link", "query"), method("get_link", "query")),  # "setter" is a query
        (method("update_link", "update"), method("get_owner", "query")),  # stems differ
        (method("set_config", "update"), method("get", "query")),  # stem vs bare
        (method("upset", "update"), method("get", "query")),  # not a setter name
    ],
)
def test_interfaces_without_a_matching_pair(methods: tuple[dict[str, Any], ...]) -> None:
    assert RULE.score([candid(*methods), gateway_body("url")]) is None


def test_unparsed_or_absent_candid_does_not_count() -> None:
    absent = event("canister.candid_observed", SourceType.IC_READ_STATE, {"status": "absent"})
    assert RULE.score([absent, gateway_body("url")]) is None


def test_setter_getter_pairs_helper() -> None:
    assert setter_getter_pairs(list(CANISTERWORM_METHODS)) == [("update_link", "get_latest_link")]
    pairs = setter_getter_pairs(
        [method("set", "update"), method("put", "update"), method("get", "composite_query")]
    )
    assert pairs == [("put", "get"), ("set", "get")]


def test_evidence_falls_back_to_raw_snapshot_and_skips_unstored_events() -> None:
    pair = candid(*CANISTERWORM_METHODS, event_id=None)
    pair = pair.model_copy(update={"raw_snapshot_id": 41})
    body = gateway_body("url", event_id=None)
    detection = RULE.score([pair, body])
    assert detection is not None
    assert [(r.ref_type, r.id) for r in detection.evidence_refs] == [("raw_snapshot", 41)]


def test_engine_scores_each_canister_separately() -> None:
    other = "cjn37-uyaaa-aaaac-qgnva-cai"
    events = [
        candid(*CANISTERWORM_METHODS),
        gateway_body("url", canister_id=other),  # body on a different canister
        gateway_body("url", minutes=5),
    ]
    detections = run_rules([RULE], events)
    assert [d.subject_id for d in detections] == [TDTQY]
    groups = group_by_subject(events)
    assert list(groups) == sorted(groups)
    assert (
        run_rules([RULE], [candid(*CANISTERWORM_METHODS), gateway_body("url", canister_id=other)])
        == []
    )


def test_scoring_is_deterministic() -> None:
    events = [candid(*CANISTERWORM_METHODS), gateway_body("url")]
    assert RULE.score(events) == RULE.score(list(reversed(events)))
