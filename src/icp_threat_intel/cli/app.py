"""Typer application behind the ``icp-threat-intel`` console script.

Every command from SPEC section 6 is registered here. Commands not built yet exit 2 with
"not implemented"; later tasks replace the stubs.
"""

from typing import NoReturn

import typer

from icp_threat_intel.cli.canister import canister_app
from icp_threat_intel.cli.db import db_app
from icp_threat_intel.cli.pipeline import census, verify

app = typer.Typer(
    name="icp-threat-intel",
    help="Threat intelligence for ICP canisters used as attack infrastructure.",
    no_args_is_help=True,
)
app.add_typer(db_app, name="db")
app.add_typer(canister_app, name="canister")
app.command("verify")(verify)
app.command("census")(census)


def _not_implemented(command: str) -> NoReturn:
    typer.echo(f"{command}: not implemented", err=True)
    raise typer.Exit(code=2)


@app.command()
def collect() -> None:
    """Run collectors and store every response in the raw store."""
    _not_implemented("collect")


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
def digest() -> None:
    """Build the daily digest (Markdown and JSON)."""
    _not_implemented("digest")


@app.command()
def publish() -> None:
    """Export a disclosed case as ThreatFox, STIX 2.1, MISP or Markdown."""
    _not_implemented("publish")


def main() -> None:
    """Console-script entry point."""
    app()
