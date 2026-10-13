"""Immutability of ``raw_snapshots`` and ``canister_snapshots``.

Three layers, so a row cannot change once written:

1. ORM ``before_update`` / ``before_delete`` listeners on mapped instances.
2. A session ``do_orm_execute`` hook that refuses bulk ``update()`` / ``delete()`` statements.
3. Database triggers that reject UPDATE and DELETE, created with the tables on SQLite and
   Postgres (the migration creates the same triggers).
"""

from typing import Any, ClassVar

from sqlalchemy import Connection, MetaData, Table, event
from sqlalchemy.orm import Mapper, ORMExecuteState, Session

from icp_threat_intel.db.base import Base

IMMUTABLE_TABLES = ("raw_snapshots", "canister_snapshots")


class ImmutableRowError(Exception):
    """An immutable row was about to be updated or deleted."""


class Immutable:
    """Mixin marking a mapped class as append-only."""

    __immutable__: ClassVar[bool] = True


def sqlite_trigger_ddl(table: str) -> list[str]:
    return [
        f"CREATE TRIGGER {table}_no_{op.lower()} BEFORE {op} ON {table} "
        f"BEGIN SELECT RAISE(ABORT, '{table} is immutable'); END"
        for op in ("UPDATE", "DELETE")
    ]


def postgres_trigger_ddl(table: str) -> list[str]:
    return [
        "CREATE OR REPLACE FUNCTION reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN RAISE EXCEPTION USING MESSAGE = TG_TABLE_NAME || ' is immutable'; END $$",
        f"CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE ON {table} "
        "FOR EACH ROW EXECUTE FUNCTION reject_mutation()",
    ]


def _refuse(_mapper: Mapper[Any], _connection: Connection, target: Any) -> None:
    if getattr(type(target), "__immutable__", False):
        raise ImmutableRowError(f"{type(target).__tablename__} rows are immutable")


event.listen(Base, "before_update", _refuse, propagate=True)
event.listen(Base, "before_delete", _refuse, propagate=True)


@event.listens_for(Session, "do_orm_execute")
def _refuse_bulk(state: ORMExecuteState) -> None:
    if not (state.is_update or state.is_delete):
        return
    mapper = state.bind_mapper
    table = getattr(mapper, "local_table", None) if mapper is not None else None
    if isinstance(table, Table) and table.name in IMMUTABLE_TABLES:
        raise ImmutableRowError(f"bulk changes to {table.name} are not allowed")


@event.listens_for(Base.metadata, "after_create")
def _create_triggers(_target: MetaData, connection: Connection, **_kw: Any) -> None:
    dialect = connection.dialect.name
    for table in IMMUTABLE_TABLES:
        if dialect == "sqlite":
            statements = sqlite_trigger_ddl(table)
        elif dialect == "postgresql":
            statements = postgres_trigger_ddl(table)
        else:
            continue
        for statement in statements:
            connection.exec_driver_sql(statement)
