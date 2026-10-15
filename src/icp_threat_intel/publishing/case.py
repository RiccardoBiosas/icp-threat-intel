"""Build a publishable ``Case`` and the shared exporter base (disclosure gate first)."""

import uuid
from collections.abc import Sequence
from datetime import datetime

from icp_threat_intel.core.enums import DetectionStatus, IocType
from icp_threat_intel.core.models import Case, Detection, Ioc
from icp_threat_intel.publishing.gate import require_disclosure

GATEWAY_SUFFIXES = ("raw.icp0.io", "icp0.io", "raw.ic0.app", "ic0.app")
NAMESPACE = uuid.UUID("6f1c2b0e-8d0f-4c55-9a43-1c5a2d1e7f10")  # icp-threat-intel


def stable_uuid(*parts: object) -> str:
    """Deterministic UUID5 so re-exporting a case yields identical ids."""
    return str(uuid.uuid5(NAMESPACE, "|".join(str(p) for p in parts)))


def gateway_hosts(canister_id: str) -> list[str]:
    return [f"{canister_id}.{suffix}" for suffix in GATEWAY_SUFFIXES]


def build_case(
    title: str,
    detections: Sequence[Detection],
    iocs: Sequence[Ioc],
    *,
    created_at: datetime,
    disclosed_at: datetime | None = None,
    disclosure_contact: str | None = None,
    summary: str = "",
) -> Case:
    """Only verified detections may be published; candidates never leave the system."""
    unverified = [d.rule_id for d in detections if d.status is not DetectionStatus.VERIFIED]
    if unverified:
        raise ValueError(f"only verified detections can be published; got {unverified}")
    all_iocs = list(iocs)
    known = {(i.ioc_type, i.value) for i in all_iocs}
    for det in detections:
        if det.canister_id and (IocType.CANISTER_ID, det.canister_id) not in known:
            all_iocs.append(
                Ioc(
                    ioc_type=IocType.CANISTER_ID,
                    value=det.canister_id,
                    source_type=det.evidence_refs[0].source_type,
                    source_ref=f"detection:{det.rule_id}:{det.id}",
                    source_url="",
                    confidence=round(det.weighted_confidence * 100),
                    notes=det.explanation,
                )
            )
            known.add((IocType.CANISTER_ID, det.canister_id))
    case_id = stable_uuid("case", title, created_at.isoformat())
    return Case(
        case_id=case_id,
        title=title,
        created_at=created_at,
        detections=tuple(detections),
        iocs=tuple(all_iocs),
        disclosed_at=disclosed_at,
        disclosure_contact=disclosure_contact,
        summary=summary,
    )


class GatedExporter:
    """Base for every exporter: ``export`` refuses a case without ``disclosed_at``."""

    format = "base"

    def export(self, case: Case) -> bytes:
        require_disclosure(case)
        return self.render(case)

    def render(self, case: Case) -> bytes:
        raise NotImplementedError
