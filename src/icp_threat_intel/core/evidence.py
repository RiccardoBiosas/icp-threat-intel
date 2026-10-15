"""The two-signal rule (SPEC guardrail 8), shared by every layer that can set ``verified``.

A detection may be ``verified`` only with at least two evidence references whose source
types differ. It is checked in three places, so no path skips it: the ``Detection`` model,
the verification state machine and the ``detections`` table (ORM flush hook).
"""

from collections.abc import Iterable, Mapping
from typing import Any

MIN_SOURCE_TYPES = 2


class InsufficientEvidence(ValueError):
    """Fewer than two distinct source types back the detection."""


def _source_type(ref: Any) -> str | None:
    value = (
        ref.get("source_type") if isinstance(ref, Mapping) else getattr(ref, "source_type", None)
    )
    return None if value is None else str(value)


def distinct_source_types(refs: Iterable[Any]) -> frozenset[str]:
    """Source types named by evidence refs (models or their JSON dicts)."""
    return frozenset(t for t in (_source_type(r) for r in refs) if t)


def require_two_signals(refs: Iterable[Any]) -> None:
    refs = list(refs)
    types = distinct_source_types(refs)
    if len(refs) < MIN_SOURCE_TYPES or len(types) < MIN_SOURCE_TYPES:
        raise InsufficientEvidence(
            f"verified needs >= {MIN_SOURCE_TYPES} evidence refs from different source types; "
            f"got {len(refs)} ref(s) from {sorted(types) or 'no'} source type(s)"
        )
