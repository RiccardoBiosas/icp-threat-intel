"""``collect`` command group. Only ``collect signals`` is built; bare ``collect`` stays a stub.

``collect blocklists`` downloads community phishing blocklists (PhishDestroy,
``collectors/signals_blocklist.py``) and lists the ICP canisters in them.
``collect signals`` polls the signals feed (community forums, ``collectors/signals_feed.py``)
into the raw store and, unless ``--no-parse``, ingests what it stored. ``--backfill`` walks
further back (up to 200 pages, optionally stopping at ``--since``); ``--search`` also runs
the curated generic-term forum search (``collectors/signals_search.py``). It is run by hand
only: no scheduler job calls it (``OPEN_QUESTIONS.md``).
"""

import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated

import typer

if TYPE_CHECKING:
    from sqlalchemy.orm import Session, sessionmaker

    from icp_threat_intel.core.models import RawSnapshotRef
    from icp_threat_intel.raw_store.store import SqlRawStore

collect_app = typer.Typer(
    help="Run collectors and store every response in the raw store.",
    invoke_without_command=True,
)


def _pause(seconds: float) -> None:
    """Pause between forum searches (patched out in tests)."""
    time.sleep(seconds)


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
        int,
        typer.Option("--pages", min=1, help="Pages of 50 latest posts per feed (1-10)."),
    ] = 1,
    backfill: Annotated[
        bool, typer.Option("--backfill", help="Allow up to 200 pages for a one-off history walk.")
    ] = False,
    since: Annotated[
        datetime | None,
        typer.Option(
            "--since", formats=["%Y-%m-%d"], help="Stop paging once posts are older (UTC)."
        ),
    ] = None,
    search: Annotated[
        bool, typer.Option("--search", help="Also search the curated generic threat terms.")
    ] = False,
    search_pages: Annotated[
        int, typer.Option("--search-pages", min=1, max=5, help="Result pages per term.")
    ] = 1,
    max_topics: Annotated[
        int, typer.Option("--max-topics", min=1, max=500, help="Topics fetched per feed.")
    ] = 50,
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
    from icp_threat_intel.collectors.signals_search import SignalsSearchCollector
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
    names = feed or [f.name for f in DEFAULT_FEEDS]
    cutoff = since.replace(tzinfo=UTC) if since is not None else None
    try:
        ioc_values = _ioc_values(sessions) if search else []
        with signals_http(settings.contact) as http:
            try:
                latest = SignalsFeedCollector(http, pages=pages, backfill=backfill, since=cutoff)
                searcher = SignalsSearchCollector(
                    http,
                    ioc_values=ioc_values,
                    search_pages=search_pages,
                    max_topics=max_topics,
                    sleep=_pause,
                )
            except ValueError as exc:
                typer.echo(f"collect signals: {exc}", err=True)
                raise typer.Exit(code=2) from None
            runs: list[tuple[str, list[RawSnapshotRef]]] = []
            for name in names:
                runs.append((f"{name}", collect_into(latest, store, [name])))
                if search:
                    typer.echo(f"{name}: searching {len(searcher.terms)} generic terms ...")
                    runs.append((f"{name} search", collect_into(searcher, store, [name])))
        for label, refs in runs:
            new = [r for r in refs if r.created]
            line = f"{label}: {len(refs)} page(s), {len(new)} new snapshot(s)"
            if not parse:
                typer.echo(f"{line} (not parsed; run `parse`)")
                continue
            typer.echo(f"{line}; {_ingest(sessions, store, [r.id for r in new])}")
    except typer.Exit:
        raise
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


def _ioc_values(sessions: "sessionmaker[Session]") -> list[str]:
    """Every IOC value, so no search term can contain one."""
    from sqlalchemy import select

    from icp_threat_intel.db.models import Ioc

    with sessions() as session:
        return list(session.scalars(select(Ioc.value)))


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
            ("ioc_posts", (EventRow.kind == "signal.post_observed", EventRow.is_ioc.is_(True))),
            (
                "iocs",
                (EventRow.kind == "signal.canister_reference", EventRow.is_ioc.is_(True)),
            ),
        ):
            query = select(func.count()).select_from(EventRow)
            query = query.where(EventRow.raw_snapshot_id.in_(ids), *where)
            counts[label] = int(session.scalar(query) or 0)
    return (
        f"{counts['matched']} post(s) matched ({counts['ioc_posts']} naming an IOC value), "
        f"{counts['iocs']} IOC canister reference(s), "
        f"{result.events_created} new event(s)"
    )
