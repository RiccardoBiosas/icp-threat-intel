"""H2: lifecycle changes on known-bad canisters."""

from collections.abc import Sequence
from typing import Any, ClassVar

from icp_threat_intel.core.models import Event
from icp_threat_intel.rules.base import BaseRule

LIFECYCLE_FIELDS = ("status", "controllers", "module_hash")
_FIELD_KINDS = {
    "canister.controllers_changed": "controllers",
    "canister.module_hash_changed": "module_hash",
}
_WEIGHTS = {"status": 0.3, "module_hash": 0.2, "controllers": 0.2}


def _flip(change: Any) -> bool:
    return isinstance(change, dict) and (change.get("from"), change.get("to")) == (
        "stopped",
        "running",
    )


def explicit_changes(event: Event) -> list[str]:
    """Lifecycle fields an explicit change event reports.

    ``canister.status_changed`` counts only for stopped -> running (a re-enable).
    ``census.canister_changed`` carries ``payload["changes"] = {field: {"from", "to"}}``.
    """
    payload = event.payload
    if event.kind == "canister.status_changed":
        return ["status"] if _flip(payload) else []
    if event.kind in _FIELD_KINDS:
        return [_FIELD_KINDS[event.kind]]
    if event.kind == "census.canister_changed":
        changes = payload.get("changes") or {}
        found = [f for f in ("controllers", "module_hash") if f in changes]
        return (["status"] if _flip(changes.get("status")) else []) + found
    return []


def _observed(event: Event, field: str) -> Any:
    value = event.payload.get(field)
    if field == "controllers" and isinstance(value, list):
        return tuple(sorted(value))
    return value


def derived_changes(events: Sequence[Event]) -> list[tuple[str, Event, Event]]:
    """(field, before, after) for consecutive state observations from one source type."""
    last: dict[Any, Event] = {}
    out = []
    observed = [
        e for e in events if e.kind == "canister.state_observed" and e.payload.get("status") == "ok"
    ]
    for event in sorted(observed, key=lambda e: (e.observed_at, e.id or 0)):
        previous = last.get(event.source_type)
        if previous is not None:
            for field in ("controllers", "module_hash"):
                before, after = _observed(previous, field), _observed(event, field)
                if before is not None and after is not None and before != after:
                    out.append((field, previous, event))
        last[event.source_type] = event
    return out


def _governance_action(event: Event) -> bool:
    return event.kind == "proposal.references_target" or (
        event.kind == "gateway.body_observed" and event.payload.get("denylisted") is True
    )


class H2KnownBadLifecycle(BaseRule):
    """Known-bad canister lifecycle: an IOC canister that comes back or changes hands.

    Precedents (SPEC section 3):

    * CanisterWorm (March 2026): governance needed about 26 hours after disclosure to
      disable ``tdtqy-oyaaa-aaaae-af2dq-cai``, and a disabled canister can be re-enabled.
    * ThreatFox IOC 1781006: the same canister's raw-gateway URL was reported delivering a
      payload on 2026-04-04, after the March takedown, which is the re-enable this rule
      watches for.
    * CanisterSprawl (April 2026): the exfiltration canister ``cjn37-uyaaa-aaaac-qgnva-cai``
      is an IOC whose controllers and module hash are worth tracking the same way.

    Signals (both required):

    * ``ioc_canister``: any event for the subject with ``is_ioc`` set by enrichment.
    * ``lifecycle_change``: a stopped -> running status flip, a controller change or a
      module-hash change, either as an explicit change event (``canister.status_changed``,
      ``canister.controllers_changed``, ``canister.module_hash_changed``,
      ``census.canister_changed``) or derived from two consecutive
      ``canister.state_observed`` events from the same source type that differ.

    Optional signal ``governance_action`` (``proposal.references_target`` or a gateway 451
    ``denylisted``): the explanation reports the hours from the latest such action to the
    change, and the action is kept as evidence.
    """

    id: ClassVar[str] = "H2"
    hypothesis: ClassVar[str] = "Known-bad canister lifecycle"
    required_signals: ClassVar[frozenset[str]] = frozenset({"ioc_canister", "lifecycle_change"})

    def signals(self, events: Sequence[Event]) -> dict[str, list[Event]]:
        changes = [e for e in events if explicit_changes(e)]
        for _field, before, after in derived_changes(events):
            changes.extend([before, after])
        return {
            "ioc_canister": [e for e in events if e.is_ioc],
            "lifecycle_change": list({id(e): e for e in changes}.values()),
            # optional context, not required: feeds "hours since the last action"
            "governance_action": [e for e in events if _governance_action(e)],
        }

    def assess(self, support: dict[str, list[Event]]) -> tuple[float, str]:
        changed = support["lifecycle_change"]
        fields = {f for e in changed for f in explicit_changes(e)}
        fields |= {f for f, _b, _a in derived_changes(changed)}
        score = 0.6 + sum(_WEIGHTS[f] for f in fields)
        first_change = min(e.observed_at for e in changed)
        actions = [e for e in support.get("governance_action", []) if e.observed_at <= first_change]
        if actions:
            last = max(actions, key=lambda e: e.observed_at)
            hours = (first_change - last.observed_at).total_seconds() / 3600
            since = f"{hours:.1f} h after the last governance/takedown action ({last.kind})"
        else:
            since = "no earlier governance or takedown action seen"
        labels = {
            "status": "stopped -> running",
            "controllers": "controllers",
            "module_hash": "module hash",
        }
        changed_text = ", ".join(labels[f] for f in LIFECYCLE_FIELDS if f in fields)
        return score, f"IOC canister lifecycle change ({changed_text}); {since}."
