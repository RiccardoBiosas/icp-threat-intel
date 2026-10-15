"""Apply source reliability to events at ingest (SPEC: source trust)."""

from collections.abc import Mapping, Sequence

from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.models import Event
from icp_threat_intel.core.trust import default_reliability


class TrustEnricher:
    """Sets ``Event.weight`` from the weight of the event's source type.

    ``weights`` normally comes from the ``sources`` rows (operator-tunable); a source type
    missing from it falls back to ``core.trust.DEFAULT_RELIABILITY``.
    """

    name = "trust"

    def __init__(self, weights: Mapping[SourceType, int] | None = None) -> None:
        self._weights = dict(weights or {})

    def weight_for(self, source_type: SourceType) -> int:
        return self._weights.get(source_type, default_reliability(source_type))

    def enrich(self, events: Sequence[Event]) -> list[Event]:
        return [e.model_copy(update={"weight": self.weight_for(e.source_type)}) for e in events]
