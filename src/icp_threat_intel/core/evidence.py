"""The two-signal rule (SPEC guardrail 8), shared by every layer that can set ``verified``.

A detection may be ``verified`` only with at least two evidence references whose source
types differ. It is checked in three places, so no path skips it: the ``Detection`` model,
the verification state machine and the ``detections`` table (ORM flush hook).

Signal sources (``SIGNAL_SOURCE_TYPES``: community forums anyone can post to) may sit in a
detection's evidence but never count towards the two: ``verified`` needs two different
authoritative source types besides them.
"""

from collections.abc import Iterable, Mapping
from typing import Any

from icp_threat_intel.core.enums import SourceType

MIN_SOURCE_TYPES = 2
SIGNAL_SOURCE_TYPES: frozenset[str] = frozenset({SourceType.SIGNALS_FEED.value})


class InsufficientEvidence(ValueError):
    """Fewer than two distinct authoritative source types back the detection."""


def _source_type(ref: Any) -> str | None:
    value = (
        ref.get("source_type") if isinstance(ref, Mapping) else getattr(ref, "source_type", None)
    )
    return None if value is None else str(value)


def distinct_source_types(refs: Iterable[Any]) -> frozenset[str]:
    """Source types named by evidence refs (models or their JSON dicts)."""
    return frozenset(t for t in (_source_type(r) for r in refs) if t)


def authoritative_source_types(refs: Iterable[Any]) -> frozenset[str]:
    """``distinct_source_types`` without the signal sources."""
    return distinct_source_types(refs) - SIGNAL_SOURCE_TYPES


def require_two_signals(refs: Iterable[Any]) -> None:
    refs = list(refs)
    types = authoritative_source_types(refs)
    counted = [r for r in refs if _source_type(r) not in SIGNAL_SOURCE_TYPES]
    if len(counted) < MIN_SOURCE_TYPES or len(types) < MIN_SOURCE_TYPES:
        raise InsufficientEvidence(
            f"verified needs >= {MIN_SOURCE_TYPES} evidence refs from different source types "
            f"(signal sources {sorted(SIGNAL_SOURCE_TYPES)} do not count); got {len(refs)} "
            f"ref(s) from {sorted(types) or 'no'} authoritative source type(s)"
        )
