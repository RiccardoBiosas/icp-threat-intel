"""Stub rules H4-H6 and the registry."""

import pytest
import structlog

from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.interfaces import Rule
from icp_threat_intel.rules import REGISTRY, all_rules
from icp_threat_intel.rules.stub import StubRule
from tests.rules._events import event

STUBS = ("H4", "H5", "H6")
EXPECTED_SIGNALS = {
    "H4": {"cmc_topup", "ioc_canister"},
    "H5": {"proposal_reference"},
    "H6": {"creation_burst", "opaque_module"},
}


def test_registry_covers_h1_to_h7() -> None:
    assert set(REGISTRY) == {"H1", "H2", "H3", "H4", "H5", "H6", "H7"}
    for rule_id, cls in REGISTRY.items():
        assert cls.id == rule_id
        assert isinstance(cls(), Rule)
        assert cls.__doc__ and cls.required_signals
    assert [r.id for r in all_rules()] == sorted(REGISTRY)


@pytest.mark.parametrize("rule_id", STUBS)
def test_stub_documents_signals_returns_none_and_logs(rule_id: str) -> None:
    rule = REGISTRY[rule_id]()
    assert isinstance(rule, StubRule)
    assert rule.required_signals == EXPECTED_SIGNALS[rule_id]
    for signal in rule.required_signals:
        assert signal in (type(rule).__doc__ or "")
    events = [event("ioc.reported", SourceType.THREATFOX, {}, is_ioc=True)]
    with structlog.testing.capture_logs() as logs:
        assert rule.score(events) is None
    assert {"event": "rule_stub", "rule_id": rule_id, "events": 1, "log_level": "info"} in logs


def test_h6_is_labelled_unverified() -> None:
    doc = REGISTRY["H6"].__doc__ or ""
    assert "UNVERIFIED" in doc and "1 September 2026" in doc


def test_real_rules_are_not_stubs() -> None:
    assert not any(isinstance(REGISTRY[r](), StubRule) for r in ("H1", "H2", "H3", "H7"))
