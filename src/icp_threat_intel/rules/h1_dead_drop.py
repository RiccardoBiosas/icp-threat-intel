"""H1: dead-drop C2 canisters."""

import re
from collections.abc import Sequence
from typing import Any, ClassVar

from icp_threat_intel.core.models import Event
from icp_threat_intel.rules.base import BaseRule

SMALL_BODY_BYTES = 4096
C2_BODY_CLASSES = frozenset({"url", "base64_blob", "shell_fragment"})
_SETTER = re.compile(r"^(?:update|set|put)(?:_(?P<stem>[a-z0-9_]+))?$")
_GETTER = re.compile(r"^(?:get|fetch)(?:_latest)?(?:_(?P<stem>[a-z0-9_]+))?$")
_GETTER_MODES = frozenset({"query", "composite_query", "update"})


def setter_getter_pairs(methods: Sequence[dict[str, Any]]) -> list[tuple[str, str]]:
    """(setter, getter) pairs such as update_link/get_link, set/get, put/fetch.

    The stems must match (``update_link`` with ``get_link`` or ``get_latest_link``; bare
    ``set``/``put`` with bare ``get``/``fetch``). Setters must be update methods: a query
    cannot change state, so a "setter" query is no dead drop.
    """
    setters: dict[str | None, list[str]] = {}
    getters: dict[str | None, list[str]] = {}
    for method in methods:
        name, mode = str(method.get("name", "")), method.get("mode")
        if (m := _SETTER.match(name)) and mode == "update":
            setters.setdefault(m.group("stem"), []).append(name)
        elif (m := _GETTER.match(name)) and mode in _GETTER_MODES:
            getters.setdefault(m.group("stem"), []).append(name)
    return sorted(
        (s, g)
        for stem in setters.keys() & getters.keys()
        for s in setters[stem]
        for g in getters[stem]
    )


def _small_text(payload: dict[str, Any]) -> bool:
    return (
        payload.get("body_class") in C2_BODY_CLASSES
        and isinstance(payload.get("size"), int)
        and 0 < payload["size"] <= SMALL_BODY_BYTES
        and payload.get("truncated") is not True
    )


def _has_pair(event: Event) -> bool:
    payload = event.payload
    return (
        event.kind == "canister.candid_observed"
        and payload.get("status") == "ok"
        and bool(setter_getter_pairs(payload.get("candid_methods") or []))
    )


def _has_small_body(event: Event) -> bool:
    payload = event.payload
    if event.kind == "gateway.body_observed":
        served = payload.get("outcome") == "ok" and payload.get("http_status") == 200
    elif event.kind == "gateway.http_request_queried":
        served = payload.get("response_status_code") == 200
    else:
        return False
    return served and _small_text(payload)


class H1DeadDropC2(BaseRule):
    """Dead-drop C2: a canister that stores a value anyone can rotate and serves it as text.

    Precedent (SPEC section 3): CanisterWorm, 19-22 March 2026. TeamPCP's Python backdoor
    polled canister ``tdtqy-oyaaa-aaaae-af2dq-cai`` about every 50 minutes; its
    ``update_link`` method let the operator rotate the payload URL without redeploying,
    and the raw gateway served that URL as a small text body.

    Signals (both required):

    * ``setter_getter_pair``: a ``canister.candid_observed`` event whose Candid interface
      has a setter/getter pair (``update_link``/``get_link``, ``set``/``get``,
      ``put``/``fetch``). Candid cannot show whether the setter checks its caller; the pair
      is the observable part, and the second signal is what makes it suspicious.
    * ``small_text_body``: a ``gateway.body_observed`` (HTTP 200) or
      ``gateway.http_request_queried`` event whose body is at most 4 KiB, not truncated,
      and classified as a URL, base64 blob or shell fragment.

    Works within the platform limit: only the public Candid and the gateway body are used.
    """

    id: ClassVar[str] = "H1"
    hypothesis: ClassVar[str] = "Dead-drop C2 canisters"
    required_signals: ClassVar[frozenset[str]] = frozenset(
        {"setter_getter_pair", "small_text_body"}
    )

    def signals(self, events: Sequence[Event]) -> dict[str, list[Event]]:
        pairs = [e for e in events if _has_pair(e)]
        bodies = [e for e in events if _has_small_body(e)]
        return {"setter_getter_pair": pairs, "small_text_body": bodies}

    def assess(self, support: dict[str, list[Event]]) -> tuple[float, str]:
        pairs = sorted(
            {
                f"{s}/{g}"
                for e in support["setter_getter_pair"]
                for s, g in setter_getter_pairs(e.payload.get("candid_methods") or [])
            }
        )
        classes = sorted({str(e.payload["body_class"]) for e in support["small_text_body"]})
        score = 0.7
        if "url" in classes:
            score += 0.15  # the CanisterWorm shape: a rotatable payload URL
        if any("link" in p or "url" in p for p in pairs):
            score += 0.15
        explanation = (
            f"Candid setter/getter pair(s) {', '.join(pairs)} and a small gateway body "
            f"classified as {', '.join(classes)}: matches the CanisterWorm dead-drop pattern."
        )
        return score, explanation
