"""Typer application behind the ``icp-threat-intel`` console script.

Every command from SPEC section 6 is registered here. Commands not built yet exit 2 with
"not implemented"; later tasks replace the stubs.
"""

from typing import Annotated, NoReturn

import typer

app = typer.Typer(
    name="icp-threat-intel",
    help="Threat intelligence for ICP canisters used as attack infrastructure.",
    no_args_is_help=True,
)
db_app = typer.Typer(help="Database maintenance.", no_args_is_help=True)
canister_app = typer.Typer(help="Inspect individual canisters.", no_args_is_help=True)
app.add_typer(db_app, name="db")
app.add_typer(canister_app, name="canister")


def _not_implemented(command: str) -> NoReturn:
    typer.echo(f"{command}: not implemented", err=True)
    raise typer.Exit(code=2)


@app.command()
def collect() -> None:
    """Run collectors and store every response in the raw store."""
    _not_implemented("collect")


@app.command()
def census() -> None:
    """Walk subnets via the Dashboard API and diff against the previous run."""
    _not_implemented("census")


@app.command()
def parse() -> None:
    """Parse raw snapshots into normalized events."""
    _not_implemented("parse")


@app.command()
def enrich() -> None:
    """Apply source trust weights and IOC membership to events."""
    _not_implemented("enrich")


@app.command()
def score() -> None:
    """Run detection rules H1-H6 and record candidate detections."""
    _not_implemented("score")


@app.command()
def verify() -> None:
    """Move detections through the two-signal verification state machine."""
    _not_implemented("verify")


@app.command()
def digest() -> None:
    """Build the daily digest (Markdown and JSON)."""
    _not_implemented("digest")


@app.command()
def publish() -> None:
    """Export a disclosed case as ThreatFox, STIX 2.1, MISP or Markdown."""
    _not_implemented("publish")


@db_app.command("migrate")
def db_migrate() -> None:
    """Apply Alembic migrations up to head."""
    _not_implemented("db migrate")


@db_app.command("seed")
def db_seed(
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Print what would load without writing.")
    ] = False,
) -> None:
    """Load data/seed_iocs.yaml into the database."""
    _not_implemented("db seed")


@canister_app.command("inspect")
def canister_inspect(
    canister_id: Annotated[str, typer.Argument(help="Canister ID, e.g. aaaaa-aa...-cai.")],
    offline: Annotated[
        bool, typer.Option("--offline", help="Read the raw store or cassettes, never the network.")
    ] = False,
) -> None:
    """Show a canister's public state: status, controllers, module hash, Candid, raw body."""
    _not_implemented("canister inspect")


def main() -> None:
    """Console-script entry point."""
    app()
