"""A disclosed case built from a verified H1 detection and the real seed IOCs."""

from datetime import UTC, datetime

import pytest

from icp_threat_intel.core.enums import DetectionStatus, SourceType
from icp_threat_intel.core.models import Case, Detection, EvidenceRef, Ioc
from icp_threat_intel.db.seed import load_seed_file
from icp_threat_intel.publishing.case import build_case

TDTQY = "tdtqy-oyaaa-aaaae-af2dq-cai"
CREATED = datetime(2026, 10, 15, 8, 0, tzinfo=UTC)
DISCLOSED = datetime(2026, 10, 14, 9, 0, tzinfo=UTC)


def seed_iocs() -> list[Ioc]:
    seed = load_seed_file()
    types = {s.name: s.source_type for s in seed.sources}
    return [
        Ioc(
            ioc_type=i.ioc_type, value=i.value, source_type=types[i.source],
            source_ref=i.source_ref,
            source_url=i.source_url, threat_type=i.threat_type, malware=i.malware,
            confidence=i.confidence, first_seen=i.first_seen, last_seen=i.last_seen,
            expires_at=i.expires_at, tags=tuple(i.tags), reporter=i.reporter,
            campaign=i.campaign, notes=i.notes,
        )
        for i in seed.iocs
    ]  # fmt: skip


def verified_h1(canister_id: str = TDTQY) -> Detection:
    return Detection(
        id=7,
        rule_id="H1",
        subject_type="canister",
        subject_id=canister_id,
        canister_id=canister_id,
        score=1.0,
        weighted_confidence=0.955,
        signals=frozenset({"setter_getter_pair", "small_text_body"}),
        evidence_refs=(
            EvidenceRef(ref_type="event", id=11, source_type=SourceType.IC_READ_STATE),
            EvidenceRef(ref_type="event", id=12, source_type=SourceType.RAW_GATEWAY),
        ),
        explanation="update_link/get_latest_link pair and a small URL body",
        status=DetectionStatus.VERIFIED,
    )


def make_case(disclosed: datetime | None = DISCLOSED) -> Case:
    return build_case(
        "CanisterWorm dead-drop canister",
        [verified_h1()],
        seed_iocs(),
        created_at=CREATED,
        disclosed_at=disclosed,
        summary="Dead-drop C2 on the IC.",
    )


@pytest.fixture
def case() -> Case:
    return make_case()


@pytest.fixture
def undisclosed() -> Case:
    return make_case(None)
