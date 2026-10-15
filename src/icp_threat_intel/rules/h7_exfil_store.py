"""H7: exfiltration-store canisters (extension beyond SPEC section 4; see OPEN_QUESTIONS)."""

import re
from collections.abc import Sequence
from typing import Any, ClassVar

from icp_threat_intel.core.models import Event
from icp_threat_intel.rules.base import BaseRule

SMALL_REPLY_BYTES = 4096
WRITERS = ("store", "put", "save", "upload", "submit", "drop", "push", "append", "ingest", "write")
READERS = ("list", "get", "count", "fetch", "read", "dump", "export", "entries", "keys", "size")
WIPERS = ("purge", "clear", "wipe", "delete", "reset")
_PAYLOAD = re.compile(r"\b(?:blob|text|vec\s+nat8)\b")
_STATUS_WORDS = re.compile(r'"(?:entries|count|items|stored|records)"\s*:', re.I)


def _named(name: str, words: Sequence[str]) -> bool:
    return any(name == w or name.startswith(w + "_") for w in words)


def store_methods(methods: Sequence[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """(writers, readers): update methods taking a blob/text payload, and query read-backs."""
    writers, readers = [], []
    for m in methods:
        name, mode = str(m.get("name", "")), m.get("mode")
        args = " ".join(str(a) for a in m.get("args") or [])
        if _named(name, WRITERS) and mode == "update" and _PAYLOAD.search(args):
            writers.append(name)
        elif _named(name, READERS) and mode in ("query", "composite_query"):
            readers.append(name)
    return sorted(writers), sorted(readers)


def _methods(event: Event) -> list[dict[str, Any]]:
    return list(event.payload.get("candid_methods") or [])


def _is_store(event: Event) -> bool:
    if event.kind != "canister.candid_observed" or event.payload.get("status") != "ok":
        return False
    writers, readers = store_methods(_methods(event))
    return bool(writers and readers)


def _small(payload: dict[str, Any]) -> bool:
    size = payload.get("size")
    return (
        isinstance(size, int)
        and 0 < size <= SMALL_REPLY_BYTES
        and payload.get("truncated") is not True
        and payload.get("body_class") != "binary"
    )


def _is_reply(event: Event) -> bool:
    p = event.payload
    if event.kind == "gateway.http_request_queried":
        return p.get("outcome") == "ok" and p.get("response_status_code") == 200 and _small(p)
    if event.kind == "gateway.body_observed":
        return p.get("outcome") == "ok" and p.get("http_status") == 200 and _small(p)
    return False


class H7ExfilStore(BaseRule):
    """Exfiltration store: a canister that accepts arbitrary payloads and lets them be read back.

    Precedent (SPEC section 3): CanisterSprawl, 21-23 April 2026. Canister
    ``cjn37-uyaaa-aaaac-qgnva-cai`` was used for exfiltration rather than C2: the worm
    posted collected data to it, so it has to accept arbitrary payloads and keep them.

    This hypothesis is an extension beyond the six in SPEC section 4, added at the
    maintainer's request; SPEC should list it before it is relied on.

    Signals (both required):

    * ``store_interface``: a ``canister.candid_observed`` event with an *update* method that
      writes a blob or text payload (``store``, ``put``, ``save``, ``upload``, ``drop``, ...)
      and a *query* read-back (``list``, ``get``, ``count``, ``fetch``, ...).
    * ``served_reply``: the canister answers HTTP with a small, non-binary body (raw gateway
      200 or the ``http_request`` query pre-check), i.e. it is reachable as a web endpoint.

    Legitimate key-value canisters can look the same, so this rule only raises candidates.
    Score rises with a blob payload, a wipe method (``purge``, ``clear``, ...) and a reply
    that reports stored entries.
    """

    id: ClassVar[str] = "H7"
    hypothesis: ClassVar[str] = "Exfiltration-store canisters (extension)"
    required_signals: ClassVar[frozenset[str]] = frozenset({"store_interface", "served_reply"})

    def signals(self, events: Sequence[Event]) -> dict[str, list[Event]]:
        return {
            "store_interface": [e for e in events if _is_store(e)],
            "served_reply": [e for e in events if _is_reply(e)],
        }

    def assess(self, support: dict[str, list[Event]]) -> tuple[float, str]:
        methods = {m["name"]: m for e in support["store_interface"] for m in _methods(e)}
        writers, readers = store_methods(list(methods.values()))
        wipers = sorted(
            n for n, m in methods.items() if _named(n, WIPERS) and m.get("mode") == "update"
        )
        blob = any("blob" in " ".join(methods[w].get("args") or []) for w in writers)
        counts = any(
            _STATUS_WORDS.search(str(e.payload.get("excerpt", ""))) for e in support["served_reply"]
        )
        score = 0.6 + (0.15 if blob else 0) + (0.15 if wipers else 0) + (0.1 if counts else 0)
        sigs = ", ".join(f"{w}({', '.join(methods[w].get('args') or [])})" for w in writers)
        wipe = f"; wipes via {', '.join(wipers)}" if wipers else ""
        explanation = (
            f"Write/read-back interface: writes {sigs}; reads {', '.join(readers)}{wipe}; "
            "and it answers HTTP. Matches the CanisterSprawl exfiltration store."
        )
        return score, explanation
