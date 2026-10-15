"""Pure diff between two census runs (PLAN "Census algorithm", step 6)."""

from collections.abc import Mapping
from dataclasses import dataclass, field

from icp_threat_intel.core.enums import CanisterStatus

DIFF_FIELDS = ("subnet", "controllers", "module_hash", "status", "candid_sha256")


@dataclass(frozen=True)
class CanisterState:
    canister_id: str
    subnet: str | None
    controllers: tuple[str, ...] | None = None
    module_hash: str | None = None
    status: CanisterStatus = CanisterStatus.UNKNOWN
    candid_sha256: str | None = None

    def value(self, name: str) -> object:
        if name == "controllers":
            return None if self.controllers is None else frozenset(self.controllers)
        return getattr(self, name)


@dataclass(frozen=True)
class CensusDiff:
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    changed: dict[str, dict[str, dict[str, object]]] = field(default_factory=dict)


def _jsonable(value: object) -> object:
    if isinstance(value, frozenset):
        return sorted(value)
    if isinstance(value, CanisterStatus):
        return value.value
    return value


def diff_runs(
    previous: Mapping[str, CanisterState],
    current: Mapping[str, CanisterState],
    complete_in_both: frozenset[str],
) -> CensusDiff:
    """Added, removed and changed canisters.

    ``removed`` only lists canisters whose previous subnet was walked completely in both
    runs, so a partial walk never reports removals. ``changed`` maps canister id to
    ``{field: {"from": old, "to": new}}`` (controllers compared as sets). A field that is
    unknown on either side (``None`` or status ``unknown``) is never reported as changed.
    """
    added = sorted(set(current) - set(previous))
    removed = sorted(
        cid
        for cid in set(previous) - set(current)
        if previous[cid].subnet is not None and previous[cid].subnet in complete_in_both
    )
    changed: dict[str, dict[str, dict[str, object]]] = {}
    for cid in sorted(set(previous) & set(current)):
        fields = {}
        for name in DIFF_FIELDS:
            old, new = previous[cid].value(name), current[cid].value(name)
            unknown = {None, CanisterStatus.UNKNOWN}
            if old in unknown or new in unknown:
                continue  # a field becoming known (or unknown) is not a change
            if old != new:
                fields[name] = {"from": _jsonable(old), "to": _jsonable(new)}
        if fields:
            changed[cid] = fields
    return CensusDiff(tuple(added), tuple(removed), changed)
