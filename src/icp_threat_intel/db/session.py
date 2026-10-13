"""Engine and session factories. The URL comes from ``ICP_THREAT_INTEL_DATABASE_URL``."""

from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

import icp_threat_intel.db.models  # noqa: F401  # registers tables and immutability guards
from icp_threat_intel.core.config import Settings


def make_engine(url: str | None = None, **kwargs: Any) -> Engine:
    """Create an engine; SQLite connections get foreign-key enforcement."""
    engine = create_engine(url or Settings.from_env().database_url, **kwargs)
    if engine.dialect.name == "sqlite":

        @event.listens_for(engine, "connect")
        def _fk_on(dbapi_connection: Any, _record: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)
