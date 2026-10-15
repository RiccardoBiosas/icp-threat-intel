"""Mark events whose canister is a known IOC."""

import re
from collections.abc import Iterable, Sequence

from icp_threat_intel.core.models import Event

CANISTER_ID_RE = re.compile(r"\b(?:[a-z2-7]{5}-){4}cai\b")  # SPEC section 4


def canister_ids_in(values: Iterable[str]) -> frozenset[str]:
    """Canister IDs named anywhere in IOC values (bare IDs, gateway URLs, host names)."""
    return frozenset(m.group(0) for v in values for m in CANISTER_ID_RE.finditer(v.lower()))


class IocJoinEnricher:
    """Sets ``Event.is_ioc`` when the event's canister is in the IOC set."""

    name = "ioc_join"

    def __init__(self, ioc_canisters: Iterable[str]) -> None:
        self._iocs = frozenset(ioc_canisters)

    def enrich(self, events: Sequence[Event]) -> list[Event]:
        return [
            e.model_copy(update={"is_ioc": e.is_ioc or e.canister_id in self._iocs}) for e in events
        ]
