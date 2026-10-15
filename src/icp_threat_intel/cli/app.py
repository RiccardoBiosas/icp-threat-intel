"""Typer application behind the ``icp-threat-intel`` console script.

Every command from SPEC section 6 is registered here. Commands not built yet exit 2 with
"not implemented"; later tasks replace the stubs.
"""

from typing import NoReturn

import typer

from icp_threat_intel.cli.canister import canister_app
from icp_threat_intel.cli.db import db_app
from icp_threat_intel.cli.pipeline import census, enrich, parse, score, verify
from icp_threat_intel.cli.publishing import digest, publish

app = typer.Typer(
    name="icp-threat-intel",
    help="Threat intelligence for ICP canisters used as attack infrastructure.",
    no_args_is_help=True,
)
app.add_typer(db_app, name="db")
app.add_typer(canister_app, name="canister")
app.command("parse")(parse)
app.command("enrich")(enrich)
app.command("score")(score)
app.command("verify")(verify)
app.command("census")(census)
app.command("digest")(digest)
app.command("publish")(publish)


def _not_implemented(command: str) -> NoReturn:
    typer.echo(f"{command}: not implemented", err=True)
    raise typer.Exit(code=2)


@app.command()
def collect() -> None:
    """Run collectors and store every response in the raw store."""
    _not_implemented("collect")


def main() -> None:
    """Console-script entry point."""
    app()
