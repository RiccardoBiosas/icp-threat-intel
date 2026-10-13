"""Declarative base and portable column types.

``JSON`` becomes ``JSONB`` on Postgres, big-integer primary keys fall back to ``INTEGER`` on
SQLite so autoincrement works, and enums are stored as checked strings (no native enum
types to migrate).
"""

from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import JSON, BigInteger, CheckConstraint, DateTime, Enum, Integer, MetaData
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

JsonType = JSON().with_variant(JSONB(), "postgresql")
BigIntPk = BigInteger().with_variant(Integer(), "sqlite")
Timestamp = DateTime(timezone=True)


def str_enum(enum_cls: type[StrEnum], name: str) -> Enum:
    """A string column holding the enum's values; pair it with ``enum_check``."""
    return Enum(
        enum_cls,
        name=name,
        native_enum=False,
        create_constraint=False,
        validate_strings=True,
        length=32,
        values_callable=lambda members: [m.value for m in members],
    )


def enum_check(column: str, enum_cls: type[StrEnum]) -> CheckConstraint:
    """Database CHECK that ``column`` holds one of the enum's values."""
    values = ", ".join(f"'{m.value}'" for m in enum_cls)
    return CheckConstraint(f"{column} IN ({values})", name=f"{column}_enum")


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
