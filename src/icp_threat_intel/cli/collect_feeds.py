"""``collect hackernews`` and ``collect blocklists`` (registered on ``cli.collect.collect_app``).

* ``collect hackernews`` searches Hacker News with curated ICP queries
  (``collectors/signals_hn.py``);
* ``collect blocklists`` downloads community phishing blocklists (PhishDestroy,
  ``collectors/signals_blocklist.py``) and lists the ICP canisters in them.

Both are low-authority signals and run by hand only.
"""

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated

import typer

from icp_threat_intel.cli import collect as base
from icp_threat_intel.cli.collect import collect_app

if TYPE_CHECKING:
    from sqlalchemy.orm import Session, sessionmaker


@collect_app.command("hackernews")
def hackernews(
    pages: Annotated[
        int, typer.Option("--pages", min=1, help="Result pages of 100 per query (1-10).")
    ] = 1,
    since: Annotated[
        datetime | None,
        typer.Option("--since", formats=["%Y-%m-%d"], help="Only items after this date (UTC)."),
    ] = None,
    parse: Annotated[
        bool, typer.Option("--parse/--no-parse", help="Ingest the new snapshots.")
    ] = True,
) -> None:
    """Search Hacker News (Algolia) with curated ICP queries (low-authority signals)."""
    from sqlalchemy.exc import SQLAlchemyError

    from icp_threat_intel.collectors import signals_hn
    from icp_threat_intel.collectors.runner import collect_into
    from icp_threat_intel.core.config import Settings
    from icp_threat_intel.db.session import make_engine, make_session_factory
    from icp_threat_intel.raw_store.store import SqlRawStore

    settings = Settings.from_env()
    if not settings.contact:
        typer.echo(
            "collect hackernews needs ICP_THREAT_INTEL_CONTACT (sent in the User-Agent)",
            err=True,
        )
        raise typer.Exit(code=2)
    engine = make_engine(settings.database_url)
    sessions = make_session_factory(engine)
    store = SqlRawStore(sessions)
    cutoff = since.replace(tzinfo=UTC) if since is not None else None
    try:
        ioc_values = base._ioc_values(sessions)
        with signals_hn.hn_http(settings.contact) as http:
            try:
                collector = signals_hn.HackerNewsCollector(
                    http, ioc_values=ioc_values, pages=pages, since=cutoff, sleep=base._pause
                )
            except ValueError as exc:
                typer.echo(f"collect hackernews: {exc}", err=True)
                raise typer.Exit(code=2) from None
            typer.echo(f"hackernews: searching {len(collector.queries)} curated queries ...")
            refs = collect_into(collector, store, [signals_hn.FEED_NAME])
        new = [r.id for r in refs if r.created]
        line = f"hackernews: {len(refs)} page(s), {len(new)} new snapshot(s)"
        if parse:
            typer.echo(f"{line}; {base._ingest(sessions, store, new)}")
        else:
            typer.echo(f"{line} (not parsed; run `parse`)")
    except typer.Exit:
        raise
    except SQLAlchemyError as exc:
        typer.echo(
            f"raw store unavailable ({exc.__class__.__name__}); run `make migrate`", err=True
        )
        raise typer.Exit(code=1) from None
    except Exception as exc:  # network failures surface as the HTTP library's errors
        typer.echo(f"collect hackernews failed: {exc.__class__.__name__}: {exc}", err=True)
        raise typer.Exit(code=1) from None
    finally:
        engine.dispose()


@collect_app.command("blocklists")
def blocklists(
    parse: Annotated[
        bool, typer.Option("--parse/--no-parse", help="Ingest the new snapshots.")
    ] = True,
) -> None:
    """Download community phishing blocklists (PhishDestroy) and list the ICP canisters in them."""
    from sqlalchemy.exc import SQLAlchemyError

    from icp_threat_intel.collectors.runner import collect_into
    from icp_threat_intel.collectors.signals_blocklist import (
        DEFAULT_BLOCKLISTS,
        SignalsBlocklistCollector,
        blocklist_http,
    )
    from icp_threat_intel.core.config import Settings
    from icp_threat_intel.db.session import make_engine, make_session_factory
    from icp_threat_intel.parsers.ingest import Ingestor
    from icp_threat_intel.raw_store.store import SqlRawStore

    settings = Settings.from_env()
    if not settings.contact:
        typer.echo(
            "collect blocklists needs ICP_THREAT_INTEL_CONTACT (sent in the User-Agent)",
            err=True,
        )
        raise typer.Exit(code=2)
    engine = make_engine(settings.database_url)
    sessions = make_session_factory(engine)
    store = SqlRawStore(sessions)
    try:
        with blocklist_http(settings.contact) as http:
            collector = SignalsBlocklistCollector(http)
            runs = [(f.name, collect_into(collector, store, [f.name])) for f in DEFAULT_BLOCKLISTS]
        for name, refs in runs:
            new = [r.id for r in refs if r.created]
            line = f"{name}: {len(refs)} download(s), {len(new)} new snapshot(s)"
            if not parse:
                typer.echo(f"{line} (not parsed; run `parse`)")
                continue
            result = Ingestor(sessions).ingest([store.get(i) for i in new])
            listed, iocs = _listed(sessions, new)
            typer.echo(
                f"{line}; {listed} ICP canister(s) listed ({iocs} already an IOC), "
                f"{result.events_created} new event(s)"
            )
    except SQLAlchemyError as exc:
        typer.echo(
            f"raw store unavailable ({exc.__class__.__name__}); run `make migrate`", err=True
        )
        raise typer.Exit(code=1) from None
    except Exception as exc:  # network failures surface as the HTTP library's errors
        typer.echo(f"collect blocklists failed: {exc.__class__.__name__}: {exc}", err=True)
        raise typer.Exit(code=1) from None
    finally:
        engine.dispose()


def _listed(sessions: "sessionmaker[Session]", ids: list[int]) -> tuple[int, int]:
    """(canisters listed, of which already IOCs) in the given raw snapshots."""
    from sqlalchemy import func, select

    from icp_threat_intel.db.models import EventRow

    base = (
        select(func.count())
        .select_from(EventRow)
        .where(EventRow.raw_snapshot_id.in_(ids), EventRow.kind == "signal.canister_listed")
    )
    with sessions() as session:
        listed = int(session.scalar(base) or 0)
        iocs = int(session.scalar(base.where(EventRow.is_ioc.is_(True))) or 0)
    return listed, iocs
