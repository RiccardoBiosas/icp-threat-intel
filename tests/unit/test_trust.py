"""Source weights, weighted confidence and the ingest-time enrichers."""

from datetime import UTC, datetime

import pytest

from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.models import Event
from icp_threat_intel.core.trust import (
    DEFAULT_RELIABILITY,
    default_reliability,
    weighted_confidence,
)
from icp_threat_intel.enrichment.extension_points import NOT_IMPLEMENTED
from icp_threat_intel.enrichment.ioc_join import IocJoinEnricher, canister_ids_in
from icp_threat_intel.enrichment.trust import TrustEnricher

TDTQY = "tdtqy-oyaaa-aaaae-af2dq-cai"


def _event(source_type: SourceType, canister_id: str | None = TDTQY) -> Event:
    return Event(
        kind="canister.state_observed",
        subject_type="canister",
        subject_id=canister_id or "x",
        canister_id=canister_id,
        observed_at=datetime(2026, 10, 15, tzinfo=UTC),
        source_type=source_type,
        parser="test@1",
    )


def test_every_source_type_has_a_bounded_default() -> None:
    assert set(DEFAULT_RELIABILITY) == set(SourceType)
    assert all(0 <= w <= 100 for w in DEFAULT_RELIABILITY.values())
    assert default_reliability(SourceType.RAW_GATEWAY) < default_reliability(SourceType.NNS)


def test_weighted_confidence_formula() -> None:
    assert weighted_confidence([]) == 0.0
    assert weighted_confidence([(SourceType.NPM, 80)]) == 0.8
    two = weighted_confidence([(SourceType.NPM, 80), (SourceType.RAW_GATEWAY, 50)])
    assert two == pytest.approx(1 - 0.2 * 0.5)


def test_repeated_source_type_counts_once_at_its_best_weight() -> None:
    same = [(SourceType.THREATFOX, 60), (SourceType.THREATFOX, 65), (SourceType.THREATFOX, 65)]
    assert weighted_confidence(same) == pytest.approx(0.65)


@pytest.mark.parametrize("weight", [-1, 101])
def test_weights_outside_range_rejected(weight: int) -> None:
    with pytest.raises(ValueError):
        weighted_confidence([(SourceType.NPM, weight)])


def test_trust_enricher_uses_overrides_then_defaults() -> None:
    enricher = TrustEnricher({SourceType.RAW_GATEWAY: 12})
    out = enricher.enrich([_event(SourceType.RAW_GATEWAY), _event(SourceType.NNS)])
    assert [e.weight for e in out] == [12, default_reliability(SourceType.NNS)]


def test_ioc_join() -> None:
    values = [f"https://{TDTQY}.raw.icp0.io/", "cjn37-uyaaa-aaaac-qgnva-cai", "/tmp/pglog"]
    ids = canister_ids_in(values)
    assert ids == {TDTQY, "cjn37-uyaaa-aaaac-qgnva-cai"}
    out = IocJoinEnricher(ids).enrich(
        [
            _event(SourceType.NPM),
            _event(SourceType.NPM, "aaaaa-aaaaa-aaaaa-aaaaa-cai"),
            _event(SourceType.NPM, None),
        ]
    )
    assert [e.is_ioc for e in out] == [True, False, False]


def test_extension_points_are_declared_not_implemented() -> None:
    assert NOT_IMPLEMENTED == ("llm_classifier", "wasm_analyzer")
