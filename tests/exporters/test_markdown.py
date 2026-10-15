"""Markdown case report and disclosure checklist; case builder rules."""

import pytest

from icp_threat_intel.core.enums import DetectionStatus
from icp_threat_intel.core.models import Case
from icp_threat_intel.publishing.case import build_case
from icp_threat_intel.publishing.gate import DisclosureRequired
from icp_threat_intel.publishing.markdown import (
    DFINITY_ABUSE_URL,
    DFINITY_BUG_BOUNTY_URL,
    MarkdownExporter,
)
from tests.exporters.conftest import CREATED, TDTQY, seed_iocs, verified_h1


def test_refuses_undisclosed_case(undisclosed: Case) -> None:
    with pytest.raises(DisclosureRequired):
        MarkdownExporter().export(undisclosed)


def test_report_and_checklist(case: Case) -> None:
    text = MarkdownExporter().export(case).decode()
    assert text.startswith("# CanisterWorm dead-drop canister")
    assert "| H1 |" in text and TDTQY in text
    assert "## Disclosure checklist" in text
    assert DFINITY_ABUSE_URL in text and DFINITY_BUG_BOUNTY_URL in text
    assert "UNVERIFIED" in text  # the abuse channel is not confirmed; the report says so
    assert "Disclosed to DFINITY at 2026-10-14T09:00:00+00:00" in text


def test_custom_contact_overrides_default(case: Case) -> None:
    custom = case.model_copy(update={"disclosure_contact": "confirmed channel X"})
    assert "confirmed channel X" in MarkdownExporter().export(custom).decode()


def test_build_case_refuses_unverified_and_adds_canister_iocs() -> None:
    candidate = verified_h1().model_copy(update={"status": DetectionStatus.CANDIDATE})
    with pytest.raises(ValueError, match="verified"):
        build_case("t", [candidate], [], created_at=CREATED)
    cjn37 = "cjn37-uyaaa-aaaac-qgnva-cai"
    case = build_case("t", [verified_h1(cjn37)], [], created_at=CREATED)
    added = [i for i in case.iocs if i.source_ref.startswith("detection:")]
    assert [i.value for i in added] == [cjn37]
    assert added[0].confidence == 96
    with_seed = build_case("t", [verified_h1(cjn37)], seed_iocs(), created_at=CREATED)
    assert not [i for i in with_seed.iocs if i.source_ref.startswith("detection:")]  # no dupes
    again = build_case("t", [verified_h1(cjn37)], [], created_at=CREATED)
    assert again.case_id == case.case_id  # deterministic
