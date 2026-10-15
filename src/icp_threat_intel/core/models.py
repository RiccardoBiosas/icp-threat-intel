"""Pydantic domain types passed between stages.

These are not ORM rows: stages exchange these models so they can be mounted elsewhere.
Fields mirror the PLAN.md data model; persistence-only columns are left out.
"""

from collections.abc import Mapping
from datetime import datetime
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from icp_threat_intel.core.enums import CanisterStatus, DetectionStatus, IocType, SourceType
from icp_threat_intel.core.evidence import require_two_signals


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True)


class RawFetch(_Frozen):
    """One response exactly as a collector received it, before storage."""

    source_type: SourceType
    source_name: str
    url: str
    fetched_at: datetime
    body: bytes
    truncated: bool = False
    http_status: int | None = None
    content_type: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    synthetic: bool = False
    request_meta: dict[str, Any] = Field(default_factory=dict)


class RawSnapshotRef(_Frozen):
    """Handle returned by ``RawStore.save``; ``created`` is false on an idempotent repeat."""

    id: int
    sha256: str
    created: bool


class RawSnapshot(_Frozen):
    """A stored raw body: verbatim apart from redaction, content-hashed and source-tagged."""

    id: int
    source_type: SourceType
    source_name: str
    url: str
    fetched_at: datetime
    sha256: str
    stored_sha256: str
    body: bytes
    size_bytes: int
    truncated: bool = False
    http_status: int | None = None
    content_type: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    redacted: bool = False
    redaction_kinds: tuple[str, ...] = ()
    synthetic: bool = False
    request_meta: dict[str, Any] = Field(default_factory=dict)


class Event(_Frozen):
    """A normalized observation produced by a parser and enriched before scoring."""

    kind: str
    subject_type: str
    subject_id: str
    observed_at: datetime
    source_type: SourceType
    parser: str
    canister_id: str | None = None
    raw_snapshot_id: int | None = None
    id: int | None = None
    weight: int = Field(default=0, ge=0, le=100)
    is_ioc: bool = False
    payload: dict[str, Any] = Field(default_factory=dict)


class CanisterSnapshot(_Frozen):
    """Immutable point-in-time public state of one canister."""

    canister_id: str
    observed_at: datetime
    source_type: SourceType
    status: CanisterStatus = CanisterStatus.UNKNOWN
    subnet: str | None = None
    controllers: tuple[str, ...] | None = None  # None: not observed by this source
    module_hash: str | None = None
    candid_methods: tuple[dict[str, Any], ...] | None = None
    candid_sha256: str | None = None
    raw_snapshot_id: int | None = None
    census_run_id: str | None = None


class ParseResult(_Frozen):
    """Everything a parser derives from one raw snapshot."""

    events: tuple[Event, ...] = ()
    canister_snapshots: tuple[CanisterSnapshot, ...] = ()


class EvidenceRef(_Frozen):
    """Pointer from a detection to the evidence behind one of its signals."""

    ref_type: Literal["event", "raw_snapshot", "ioc"]
    id: int
    source_type: SourceType


class Detection(_Frozen):
    """Output of a rule. Rules always emit ``candidate``; only verification changes status."""

    rule_id: str
    subject_type: str
    subject_id: str
    canister_id: str | None = None
    score: float = Field(ge=0.0, le=1.0)
    weighted_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    signals: frozenset[str]
    evidence_refs: tuple[EvidenceRef, ...]
    explanation: str
    status: DetectionStatus = DetectionStatus.CANDIDATE
    rule_version: str = "1"
    id: int | None = None
    status_history: tuple[dict[str, Any], ...] = ()

    @model_validator(mode="after")
    def _two_signals_when_verified(self) -> "Detection":
        if self.status is DetectionStatus.VERIFIED:
            require_two_signals(self.evidence_refs)
        return self

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        """``model_copy`` skips validators; re-check the two-signal rule on the copy."""
        copied = super().model_copy(update=update, deep=deep)
        if copied.status is DetectionStatus.VERIFIED:
            require_two_signals(copied.evidence_refs)
        return copied


class Notification(_Frozen):
    """A message for a notifier: an immediate alert or a digest."""

    kind: Literal["alert", "digest"]
    title: str
    markdown: str
    data: dict[str, Any] = Field(default_factory=dict)


class Ioc(_Frozen):
    """An indicator of compromise with its original publisher's provenance."""

    ioc_type: IocType
    value: str
    source_type: SourceType
    source_ref: str
    source_url: str
    threat_type: str | None = None
    malware: str | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    expires_at: datetime | None = None
    tags: tuple[str, ...] = ()
    reporter: str | None = None
    campaign: str | None = None
    notes: str | None = None


class Case(_Frozen):
    """A publishable bundle of verified detections and IOCs.

    Exporters refuse a case whose ``disclosed_at`` is unset (SPEC guardrail 7).
    """

    case_id: str
    title: str
    created_at: datetime
    detections: tuple[Detection, ...] = ()
    iocs: tuple[Ioc, ...] = ()
    disclosed_at: datetime | None = None
    disclosure_contact: str | None = None
    summary: str = ""
