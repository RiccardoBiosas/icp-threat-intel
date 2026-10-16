"""Typer application behind the ``icp-threat-intel`` console script.

Every command from SPEC section 6 is registered here. Commands not built yet exit 2 with
"not implemented" (bare ``collect``, ``db migrate``); later work replaces the stubs.
"""

import typer

from icp_threat_intel.cli import collect_feeds  # noqa: F401  (registers collect subcommands)
from icp_threat_intel.cli.canister import canister_app
from icp_threat_intel.cli.collect import collect_app
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
app.add_typer(collect_app, name="collect")
app.command("parse")(parse)
app.command("enrich")(enrich)
app.command("score")(score)
app.command("verify")(verify)
app.command("census")(census)
app.command("digest")(digest)
app.command("publish")(publish)


def main() -> None:
    """Console-script entry point."""
    app()
