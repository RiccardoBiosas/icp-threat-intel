"""Principal text codec against known IC values."""

import pytest

from icp_threat_intel.core.ic_encoding import (
    ANONYMOUS_PRINCIPAL,
    principal_from_text,
    principal_to_text,
)

SEED_CANISTERS = ("tdtqy-oyaaa-aaaae-af2dq-cai", "cjn37-uyaaa-aaaac-qgnva-cai")


def test_anonymous_principal_text() -> None:
    assert principal_to_text(ANONYMOUS_PRINCIPAL) == "2vxsx-fae"
    assert principal_from_text("2vxsx-fae") == ANONYMOUS_PRINCIPAL


def test_management_canister_is_empty_principal() -> None:
    assert principal_to_text(b"") == "aaaaa-aa"
    assert principal_from_text("aaaaa-aa") == b""


@pytest.mark.parametrize("text", SEED_CANISTERS)
def test_seed_canisters_round_trip(text: str) -> None:
    raw = principal_from_text(text)
    assert len(raw) == 10
    assert raw.endswith(b"\x01\x01")
    assert principal_to_text(raw) == text


@pytest.mark.parametrize(
    "bad", ["tdtqy-oyaaa-aaaae-af2dq-caa", "tdtqyoyaaaaaaaeaf2dqcai", "not a principal", "2vxsx-fa"]
)
def test_invalid_principals_are_rejected(bad: str) -> None:
    with pytest.raises(ValueError):
        principal_from_text(bad)
