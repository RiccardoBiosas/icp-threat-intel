"""Disclosure gate (SPEC guardrail 7): nothing is published before disclosure."""

from datetime import UTC, datetime

from icp_threat_intel.core.interfaces import Exporter
from icp_threat_intel.core.models import Case


class DisclosureRequired(Exception):
    """The case has no (valid, past) ``disclosed_at`` and must not be published."""


def require_disclosure(case: Case, *, now: datetime | None = None) -> None:
    """Raise unless ``case.disclosed_at`` is a timezone-aware time not in the future."""
    disclosed = case.disclosed_at
    if disclosed is None:
        raise DisclosureRequired(f"case {case.case_id} has no disclosed_at")
    if disclosed.tzinfo is None or disclosed.utcoffset() is None:
        raise DisclosureRequired(f"case {case.case_id}: disclosed_at must be timezone-aware")
    if disclosed > (now or datetime.now(UTC)):
        raise DisclosureRequired(f"case {case.case_id}: disclosed_at is in the future")


def gated_export(exporter: Exporter, case: Case, *, now: datetime | None = None) -> bytes:
    """Export ``case`` only after the disclosure gate passes."""
    require_disclosure(case, now=now)
    return exporter.export(case)
