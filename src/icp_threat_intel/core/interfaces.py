"""Stage protocols (SPEC D1). Names, signatures and pipeline order are the stable contract.

Pipeline: collectors -> raw_store -> parsers -> enrichment -> rules -> verification
-> alerting -> publishing.
"""

from collections.abc import Iterator, Sequence
from datetime import datetime
from typing import Protocol, runtime_checkable

from icp_threat_intel.core.enums import DetectionStatus, SourceType
from icp_threat_intel.core.models import (
    Case,
    Detection,
    Event,
    Notification,
    ParseResult,
    RawFetch,
    RawSnapshot,
    RawSnapshotRef,
)

__all__ = [
    "Collector",
    "Enricher",
    "Exporter",
    "Notifier",
    "Parser",
    "RawStore",
    "Rule",
    "Verifier",
]


@runtime_checkable
class Collector(Protocol):
    """Fetches raw data, only through the shared HTTP client or the query-only IC client."""

    name: str
    source_type: SourceType

    def collect(self, targets: Sequence[str]) -> Iterator[RawFetch]: ...


@runtime_checkable
class RawStore(Protocol):
    """Stores every fetched body verbatim (after redaction) before any parsing."""

    def save(self, fetch: RawFetch) -> RawSnapshotRef:
        """Store ``fetch``; idempotent on (source, url, sha256)."""
        ...

    def get(self, snapshot_id: int) -> RawSnapshot: ...

    def iter_snapshots(
        self, source_type: SourceType, since: datetime | None = None
    ) -> Iterator[RawSnapshot]: ...


@runtime_checkable
class Parser(Protocol):
    """Turns one raw snapshot into events and canister snapshots, without I/O."""

    source_type: SourceType
    version: str

    def parse(self, snapshot: RawSnapshot) -> ParseResult: ...


@runtime_checkable
class Enricher(Protocol):
    """Adds trust weight, IOC membership and subject links to events."""

    name: str

    def enrich(self, events: Sequence[Event]) -> list[Event]: ...


@runtime_checkable
class Rule(Protocol):
    """A pure detection rule over all events for one subject; never touches network or DB."""

    id: str
    hypothesis: str
    required_signals: frozenset[str]

    def score(self, events: Sequence[Event]) -> Detection | None: ...


@runtime_checkable
class Verifier(Protocol):
    """Guarded detection state machine; enforces the two-signal rule."""

    def transition(
        self, detection: Detection, to: DetectionStatus, *, actor: str, reason: str
    ) -> Detection: ...


@runtime_checkable
class Notifier(Protocol):
    """Delivers an alert or digest (stdout, webhook)."""

    name: str

    def notify(self, message: Notification) -> None: ...


@runtime_checkable
class Exporter(Protocol):
    """Serializes a case; raises DisclosureRequired when ``case.disclosed_at`` is unset."""

    format: str

    def export(self, case: Case) -> bytes: ...
