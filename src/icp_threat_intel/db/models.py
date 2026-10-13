"""SQLAlchemy tables (PLAN.md "Data model").

This module holds the evidence and detection tables; registry, ledger, governance, IOC and
publication tables live in ``models_domain`` and are re-exported here.
"""

import re
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, validates

from icp_threat_intel.core.enums import CanisterStatus, DetectionStatus, SourceType
from icp_threat_intel.db.base import (
    Base,
    BigIntPk,
    JsonType,
    Timestamp,
    enum_check,
    str_enum,
    utcnow,
)
from icp_threat_intel.db.immutability import Immutable
from icp_threat_intel.db.models_domain import (
    Ioc,
    LedgerTransfer,
    Package,
    PackageVersion,
    Proposal,
    Publication,
)

__all__ = [
    "Canister",
    "CanisterSnapshot",
    "DetectionRow",
    "EventRow",
    "Ioc",
    "LedgerTransfer",
    "Package",
    "PackageVersion",
    "Proposal",
    "Publication",
    "RawSnapshotRow",
    "Source",
]

CANISTER_ID_RE = re.compile(r"(?:[a-z2-7]{5}-){4}cai")


def _check_canister_id(value: str | None) -> str | None:
    if value is not None and not CANISTER_ID_RE.fullmatch(value):
        raise ValueError(f"not a canister id: {value!r}")
    return value


class Source(Base):
    __tablename__ = "sources"
    __table_args__ = (
        CheckConstraint("reliability BETWEEN 0 AND 100", name="reliability"),
        enum_check("source_type", SourceType),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    source_type: Mapped[SourceType] = mapped_column(str_enum(SourceType, "source_type"))
    base_url: Mapped[str] = mapped_column(Text)
    reliability: Mapped[int] = mapped_column(SmallInteger)
    status: Mapped[str] = mapped_column(String(16), default="EXPERIMENTAL")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(Timestamp, default=utcnow)


class Canister(Base):
    __tablename__ = "canisters"
    __table_args__ = (
        CheckConstraint("length(id) = 27", name="id_length"),
        enum_check("status", CanisterStatus),
    )

    id: Mapped[str] = mapped_column(String(27), primary_key=True)
    subnet: Mapped[str | None] = mapped_column(String(63))
    controllers: Mapped[list[str]] = mapped_column(JsonType, default=list)
    module_hash: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[CanisterStatus] = mapped_column(
        str_enum(CanisterStatus, "canister_status"), default=CanisterStatus.UNKNOWN
    )
    first_seen: Mapped[datetime] = mapped_column(Timestamp, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(Timestamp, default=utcnow)
    candid_methods: Mapped[list[dict[str, Any]] | None] = mapped_column(JsonType)
    candid_sha256: Mapped[str | None] = mapped_column(String(64))
    is_ioc: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(Timestamp, default=utcnow, onupdate=utcnow)

    @validates("id")
    def _validate_id(self, _key: str, value: str) -> str:
        return _check_canister_id(value) or value


class RawSnapshotRow(Immutable, Base):
    """Immutable evidence trail: every fetched body, verbatim after redaction."""

    __tablename__ = "raw_snapshots"
    __table_args__ = (UniqueConstraint("source_id", "url", "sha256"),)

    id: Mapped[int] = mapped_column(BigIntPk, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"))
    url: Mapped[str] = mapped_column(Text)
    fetched_at: Mapped[datetime] = mapped_column(Timestamp, default=utcnow)
    sha256: Mapped[str] = mapped_column(String(64))
    body: Mapped[bytes] = mapped_column(LargeBinary)
    stored_sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    http_status: Mapped[int | None] = mapped_column(SmallInteger)
    content_type: Mapped[str | None] = mapped_column(String(255))
    headers: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    redacted: Mapped[bool] = mapped_column(Boolean, default=False)
    redaction_kinds: Mapped[list[str]] = mapped_column(JsonType, default=list)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    request_meta: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)


class CanisterSnapshot(Immutable, Base):
    """Immutable point-in-time public state of a canister."""

    __tablename__ = "canister_snapshots"
    __table_args__ = (
        UniqueConstraint("canister_id", "source_id", "raw_snapshot_id"),
        enum_check("status", CanisterStatus),
    )

    id: Mapped[int] = mapped_column(BigIntPk, primary_key=True)
    canister_id: Mapped[str] = mapped_column(ForeignKey("canisters.id"), index=True)
    observed_at: Mapped[datetime] = mapped_column(Timestamp)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"))
    raw_snapshot_id: Mapped[int | None] = mapped_column(ForeignKey("raw_snapshots.id"))
    census_run_id: Mapped[str | None] = mapped_column(String(36), index=True)
    subnet: Mapped[str | None] = mapped_column(String(63))
    controllers: Mapped[list[str]] = mapped_column(JsonType, default=list)
    module_hash: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[CanisterStatus] = mapped_column(
        str_enum(CanisterStatus, "canister_status"), default=CanisterStatus.UNKNOWN
    )
    candid_methods: Mapped[list[dict[str, Any]] | None] = mapped_column(JsonType)
    candid_sha256: Mapped[str | None] = mapped_column(String(64))


class EventRow(Base):
    __tablename__ = "events"
    __table_args__ = (enum_check("source_type", SourceType),)

    id: Mapped[int] = mapped_column(BigIntPk, primary_key=True)
    kind: Mapped[str] = mapped_column(String(64), index=True)
    subject_type: Mapped[str] = mapped_column(String(16))
    subject_id: Mapped[str] = mapped_column(Text)
    canister_id: Mapped[str | None] = mapped_column(String(27), index=True)
    observed_at: Mapped[datetime] = mapped_column(Timestamp)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"))
    source_type: Mapped[SourceType] = mapped_column(str_enum(SourceType, "source_type"))
    raw_snapshot_id: Mapped[int | None] = mapped_column(ForeignKey("raw_snapshots.id"))
    parser: Mapped[str] = mapped_column(String(64))
    weight: Mapped[int] = mapped_column(SmallInteger, default=0)
    is_ioc: Mapped[bool] = mapped_column(Boolean, default=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    dedup_key: Mapped[str] = mapped_column(String(64), unique=True)

    @validates("canister_id")
    def _validate_canister_id(self, _key: str, value: str | None) -> str | None:
        return _check_canister_id(value)


class DetectionRow(Base):
    __tablename__ = "detections"
    __table_args__ = (
        CheckConstraint("score >= 0 AND score <= 1", name="score_range"),
        CheckConstraint(
            "weighted_confidence >= 0 AND weighted_confidence <= 1", name="confidence_range"
        ),
        enum_check("status", DetectionStatus),
    )

    id: Mapped[int] = mapped_column(BigIntPk, primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(8), index=True)
    rule_version: Mapped[str] = mapped_column(String(16), default="1")
    subject_type: Mapped[str] = mapped_column(String(16))
    subject_id: Mapped[str] = mapped_column(Text)
    canister_id: Mapped[str | None] = mapped_column(String(27), index=True)
    score: Mapped[float] = mapped_column(Float)
    weighted_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    signals: Mapped[list[str]] = mapped_column(JsonType, default=list)
    evidence_refs: Mapped[list[dict[str, Any]]] = mapped_column(JsonType, default=list)
    status: Mapped[DetectionStatus] = mapped_column(
        str_enum(DetectionStatus, "detection_status"), default=DetectionStatus.CANDIDATE
    )
    status_history: Mapped[list[dict[str, Any]]] = mapped_column(JsonType, default=list)
    created_at: Mapped[datetime] = mapped_column(Timestamp, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(Timestamp, default=utcnow, onupdate=utcnow)
    verified_at: Mapped[datetime | None] = mapped_column(Timestamp)
    dismissed_at: Mapped[datetime | None] = mapped_column(Timestamp)
    dedup_key: Mapped[str] = mapped_column(String(64), unique=True)
