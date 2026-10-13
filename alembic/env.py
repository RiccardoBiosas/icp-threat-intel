"""Alembic environment. Reads ICP_THREAT_INTEL_DATABASE_URL; ``--sql`` needs no server."""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

import icp_threat_intel.db.models  # noqa: F401  # registers every table on Base.metadata
from icp_threat_intel.core.config import Settings
from icp_threat_intel.db.base import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

url = config.get_main_option("sqlalchemy.url") or Settings.from_env().database_url
target_metadata = Base.metadata


def run_offline() -> None:
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=url.startswith("sqlite"),
    )
    with context.begin_transaction():
        context.run_migrations()


def run_online() -> None:
    connectable = engine_from_config(
        {"sqlalchemy.url": url}, prefix="sqlalchemy.", poolclass=pool.NullPool
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=connection.dialect.name == "sqlite",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_offline()
else:
    run_online()
