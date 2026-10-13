"""``icp-threat-intel db`` commands."""

from pathlib import Path
from typing import Annotated

import typer

from icp_threat_intel.db.seed import DEFAULT_SEED_PATH, apply_seed, describe, load_seed_file

db_app = typer.Typer(help="Database maintenance.", no_args_is_help=True)


@db_app.command("migrate")
def db_migrate() -> None:
    """Apply Alembic migrations up to head (use `make migrate` for now)."""
    typer.echo("db migrate: not implemented; run `make migrate`", err=True)
    raise typer.Exit(code=2)


@db_app.command("seed")
def db_seed(
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Print what would load without a database.")
    ] = False,
    seed_file: Annotated[
        Path, typer.Option("--file", help="Seed YAML file.", exists=True, dir_okay=False)
    ] = DEFAULT_SEED_PATH,
) -> None:
    """Load data/seed_iocs.yaml into the database."""
    seed = load_seed_file(seed_file)
    if dry_run:
        for line in describe(seed):
            typer.echo(line)
        typer.echo("dry run: no database was used")
        return
    from icp_threat_intel.db.session import make_engine, make_session_factory

    engine = make_engine()
    with make_session_factory(engine)() as session, session.begin():
        result = apply_seed(session, seed)
    typer.echo(
        f"seeded: {result.sources_created} sources, {result.iocs_created} new iocs "
        f"({result.iocs_existing} already present), {result.canisters_marked} canisters marked"
    )
