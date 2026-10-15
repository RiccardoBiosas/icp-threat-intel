"""``collect`` command group. Only ``collect signals`` is built; bare ``collect`` stays a stub.

``collect signals`` polls the signals feed (community forums, ``collectors/signals_feed.py``)
into the raw store and, unless ``--no-parse``, ingests what it stored. It is run by hand
only: no scheduler job calls it (``OPEN_QUESTIONS.md``).
"""

from typing import TYPE_CHECKING, Annotated

import typer

if TYPE_CHECKING:
    from sqlalchemy.orm import Session, sessionmaker

    from icp_threat_intel.raw_store.store import SqlRawStore

collect_app = typer.Typer(
    help="Run collectors and store every response in the raw store.",
    invoke_without_command=True,
)


@collect_app.callback()
def collect(ctx: typer.Context) -> None:
    """Run collectors and store every response in the raw store."""
    if ctx.invoked_subcommand is None:
        typer.echo(
            "collect: not implemented for the IC collectors; use `collect signals` or "
            "`canister inspect`",
            err=True,
        )
        raise typer.Exit(code=2)


@collect_app.command("signals")
def signals(
    feed: Annotated[
        list[str] | None,
        typer.Option("--feed", help="Feed name (repeatable); default: every feed."),
    ] = None,
    pages: Annotated[
        int, typer.Option("--pages", min=1, max=10, help="Pages of 50 posts per feed.")
    ] = 1,
    parse: Annotated[
        bool, typer.Option("--parse/--no-parse", help="Ingest the new snapshots.")
    ] = True,
) -> None:
    """Poll community forums (low-authority signals) into the raw store."""
    from sqlalchemy.exc import SQLAlchemyError

    from icp_threat_intel.collectors.runner import collect_into
    from icp_threat_intel.collectors.signals_feed import (
        DEFAULT_FEEDS,
        SignalsFeedCollector,
        signals_http,
    )
    from icp_threat_intel.core.config import Settings
    from icp_threat_intel.db.session import make_engine, make_session_factory
    from icp_threat_intel.raw_store.store import SqlRawStore

    settings = Settings.from_env()
    if not settings.contact:
        typer.echo(
            "collect signals needs ICP_THREAT_INTEL_CONTACT (sent in the User-Agent)", err=True
        )
        raise typer.Exit(code=2)
    known = {f.name for f in DEFAULT_FEEDS}
    unknown = sorted(set(feed or ()) - known)
    if unknown:
        typer.echo(f"unknown signals feed(s): {unknown}; known: {sorted(known)}", err=True)
        raise typer.Exit(code=2)
    engine = make_engine(settings.database_url)
    sessions = make_session_factory(engine)
    store = SqlRawStore(sessions)
    try:
        with signals_http(settings.contact) as http:
            collector = SignalsFeedCollector(http, pages=pages)
            names = feed or [f.name for f in DEFAULT_FEEDS]
            refs_by_feed = {name: collect_into(collector, store, [name]) for name in names}
        for name, refs in refs_by_feed.items():
            new = [r for r in refs if r.created]
            line = f"{name}: {len(refs)} page(s), {len(new)} new snapshot(s)"
            if not parse:
                typer.echo(f"{line} (not parsed; run `parse`)")
                continue
            typer.echo(f"{line}; {_ingest(sessions, store, [r.id for r in new])}")
    except SQLAlchemyError as exc:
        typer.echo(
            f"raw store unavailable ({exc.__class__.__name__}); run `make migrate`", err=True
        )
        raise typer.Exit(code=1) from None
    except Exception as exc:  # network failures surface as the HTTP library's errors
        typer.echo(f"collect signals failed: {exc.__class__.__name__}: {exc}", err=True)
        raise typer.Exit(code=1) from None
    finally:
        engine.dispose()


def _ingest(sessions: "sessionmaker[Session]", store: "SqlRawStore", ids: list[int]) -> str:
    """Ingest the given raw snapshots; summarise what the signals parser found in them."""
    from sqlalchemy import func, select

    from icp_threat_intel.db.models import EventRow
    from icp_threat_intel.parsers.ingest import Ingestor

    result = Ingestor(sessions).ingest([store.get(i) for i in ids])
    counts: dict[str, int] = {}
    with sessions() as session:
        for label, where in (
            ("matched", (EventRow.kind == "signal.post_observed",)),
            (
                "iocs",
                (EventRow.kind == "signal.canister_reference", EventRow.is_ioc.is_(True)),
            ),
        ):
            query = select(func.count()).select_from(EventRow)
            query = query.where(EventRow.raw_snapshot_id.in_(ids), *where)
            counts[label] = int(session.scalar(query) or 0)
    return (
        f"{counts['matched']} post(s) matched, {counts['iocs']} IOC canister reference(s), "
        f"{result.events_created} new event(s)"
    )
