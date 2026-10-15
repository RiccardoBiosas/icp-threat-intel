"""Shared parser helpers: event construction, canonical JSON and the event dedup key.

Parsers are pure functions of one ``RawSnapshot``: no I/O, no clock, no randomness. Every
timestamp comes from ``snapshot.fetched_at`` and every payload is JSON-serialisable, so
re-parsing the same snapshot yields identical events with identical dedup keys.
"""

import hashlib
import json
from typing import Any

from icp_threat_intel.core.models import Event, RawSnapshot


def canonical_json(value: Any) -> str:
    """Stable JSON: sorted keys, no whitespace, non-ASCII kept as is."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def dedup_key(event: Event) -> str:
    """sha256 over parser, raw snapshot, kind, subject and canonical payload (PLAN events)."""
    material = canonical_json(
        [
            event.parser,
            event.raw_snapshot_id,
            event.kind,
            event.subject_type,
            event.subject_id,
            event.payload,
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def canister_event(
    snapshot: RawSnapshot, parser: str, kind: str, canister_id: str, payload: dict[str, Any]
) -> Event:
    """An event about one canister, stamped with the snapshot's provenance."""
    return Event(
        kind=kind,
        subject_type="canister",
        subject_id=canister_id,
        canister_id=canister_id,
        observed_at=snapshot.fetched_at,
        source_type=snapshot.source_type,
        parser=parser,
        raw_snapshot_id=snapshot.id,
        payload={**payload, "synthetic": snapshot.synthetic},
    )
