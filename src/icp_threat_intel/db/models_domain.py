"""Registry, ledger, governance, IOC and publication tables (PLAN.md "Data model")."""

from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    false,
)
from sqlalchemy.orm import Mapped, mapped_column

from icp_threat_intel.core.enums import Ecosystem, IocType
from icp_threat_intel.db.base import (
    Base,
    BigIntPk,
    JsonType,
    Timestamp,
    enum_check,
    str_enum,
    utcnow,
)


class Package(Base):
    __tablename__ = "packages"
    __table_args__ = (UniqueConstraint("ecosystem", "name"), enum_check("ecosystem", Ecosystem))

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ecosystem: Mapped[Ecosystem] = mapped_column(str_enum(Ecosystem, "ecosystem"))
    name: Mapped[str] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(Timestamp, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(Timestamp, default=utcnow)
    is_ioc: Mapped[bool] = mapped_column(Boolean, default=False)


class PackageVersion(Base):
    __tablename__ = "package_versions"
    __table_args__ = (UniqueConstraint("package_id", "version"),)

    id: Mapped[int] = mapped_column(BigIntPk, primary_key=True)
    package_id: Mapped[int] = mapped_column(ForeignKey("packages.id"))
    version: Mapped[str] = mapped_column(String(128))
    published_at: Mapped[datetime | None] = mapped_column(Timestamp)
    tarball_sha256: Mapped[str | None] = mapped_column(String(64))
    tarball_path: Mapped[str | None] = mapped_column(Text)
    install_hooks: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    canister_refs: Mapped[list[str]] = mapped_column(JsonType, default=list)
    host_indicators: Mapped[list[str]] = mapped_column(JsonType, default=list)
    raw_snapshot_id: Mapped[int | None] = mapped_column(ForeignKey("raw_snapshots.id"))
    is_ioc: Mapped[bool] = mapped_column(Boolean, default=False)


class LedgerTransfer(Base):
    __tablename__ = "ledger_transfers"

    id: Mapped[int] = mapped_column(BigIntPk, primary_key=True)
    block_index: Mapped[int] = mapped_column(BigInteger, unique=True)
    from_account: Mapped[str] = mapped_column(String(64), index=True)
    to_account: Mapped[str] = mapped_column(String(64), index=True)
    amount_e8s: Mapped[Decimal] = mapped_column(Numeric(30, 0))
    fee_e8s: Mapped[Decimal] = mapped_column(Numeric(30, 0))
    memo: Mapped[Decimal | None] = mapped_column(Numeric(30, 0))
    created_at: Mapped[datetime] = mapped_column(Timestamp)
    is_cmc_topup: Mapped[bool] = mapped_column(Boolean, default=False)
    target_canister_id: Mapped[str | None] = mapped_column(String(27), index=True)
    raw_snapshot_id: Mapped[int] = mapped_column(ForeignKey("raw_snapshots.id"))


class Proposal(Base):
    __tablename__ = "proposals"

    id: Mapped[int] = mapped_column(BigIntPk, primary_key=True, autoincrement=False)
    title: Mapped[str] = mapped_column(Text)
    topic: Mapped[str] = mapped_column(String(64))
    action_type: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))
    proposer: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(Timestamp)
    decided_at: Mapped[datetime | None] = mapped_column(Timestamp)
    executed_at: Mapped[datetime | None] = mapped_column(Timestamp)
    referenced_canisters: Mapped[list[str]] = mapped_column(JsonType, default=list)
    referenced_subnets: Mapped[list[str]] = mapped_column(JsonType, default=list)
    summary: Mapped[str] = mapped_column(Text, default="")
    raw_snapshot_id: Mapped[int] = mapped_column(ForeignKey("raw_snapshots.id"))


class Ioc(Base):
    __tablename__ = "iocs"
    __table_args__ = (
        UniqueConstraint("ioc_type", "value", "source_ref"),
        CheckConstraint("confidence IS NULL OR confidence BETWEEN 0 AND 100", name="confidence"),
        enum_check("ioc_type", IocType),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ioc_type: Mapped[IocType] = mapped_column(str_enum(IocType, "ioc_type"))
    value: Mapped[str] = mapped_column(Text)
    threat_type: Mapped[str | None] = mapped_column(String(64))
    malware: Mapped[str | None] = mapped_column(String(128))
    confidence: Mapped[int | None] = mapped_column(SmallInteger)
    first_seen: Mapped[datetime | None] = mapped_column(Timestamp)
    last_seen: Mapped[datetime | None] = mapped_column(Timestamp)
    expires_at: Mapped[datetime | None] = mapped_column(Timestamp)
    tags: Mapped[list[str]] = mapped_column(JsonType, default=list)
    reporter: Mapped[str | None] = mapped_column(String(128))
    campaign: Mapped[str | None] = mapped_column(String(64))
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"))
    source_ref: Mapped[str] = mapped_column(String(128))
    source_url: Mapped[str] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)
    detection_id: Mapped[int | None] = mapped_column(ForeignKey("detections.id"))


class Publication(Base):
    __tablename__ = "publications"

    id: Mapped[int] = mapped_column(BigIntPk, primary_key=True)
    case_id: Mapped[str] = mapped_column(String(36), index=True)
    format: Mapped[str] = mapped_column(String(16))
    detection_ids: Mapped[list[int]] = mapped_column(JsonType, default=list)
    ioc_ids: Mapped[list[int]] = mapped_column(JsonType, default=list)
    disclosed_at: Mapped[datetime] = mapped_column(Timestamp, nullable=False)
    disclosure_contact: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(Timestamp, default=utcnow)
    payload_sha256: Mapped[str] = mapped_column(String(64))
    path: Mapped[str] = mapped_column(Text)
    submitted: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    submitted_at: Mapped[datetime | None] = mapped_column(Timestamp)
