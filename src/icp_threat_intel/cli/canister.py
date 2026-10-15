"""``icp-threat-intel canister inspect <id> [--offline]``.

Shows a canister's public state: status, subnet, controllers, module hash, Candid methods
and a summary of each raw-gateway body. Live mode first runs the read_state, raw-gateway and
Dashboard collectors for the canister (query-only, allowlisted hosts, contact address
required) and stores every response in the raw store. Offline mode reads the raw store, or,
when the store has nothing for the canister, recorded cassettes. Bodies are only
summarised (class, size, hash, short excerpt); nothing in them is executed or followed.
"""

from pathlib import Path
from typing import Annotated, Any

import typer
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from icp_threat_intel.core.config import Settings
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.ic_encoding import principal_from_text
from icp_threat_intel.core.models import Event, RawSnapshot
from icp_threat_intel.parsers.ingest import PARSERS
from icp_threat_intel.raw_store.cassettes import snapshots_for

canister_app = typer.Typer(help="Inspect individual canisters.", no_args_is_help=True)
DEFAULT_CASSETTES = Path("tests/cassettes")
_INSPECTED = (SourceType.IC_READ_STATE, SourceType.RAW_GATEWAY, SourceType.DASHBOARD_API)


def _store_snapshots(canister_id: str) -> list[RawSnapshot]:
    """Snapshots about the canister in the configured raw store; [] if there is none."""
    url = Settings.from_env().database_url
    if url.startswith("sqlite:///") and not Path(url.removeprefix("sqlite:///")).exists():
        return []  # never create a database just to look into it
    from icp_threat_intel.db.session import make_engine, make_session_factory
    from icp_threat_intel.raw_store.store import SqlRawStore

    engine = make_engine(url)
    try:
        store = SqlRawStore(make_session_factory(engine))
        return [
            s
            for source_type in _INSPECTED
            for s in store.iter_snapshots(source_type)
            if s.request_meta.get("canister_id") == canister_id
        ]
    except SQLAlchemyError:
        return []
    finally:
        engine.dispose()


def _collect_live(canister_id: str) -> None:
    """Run the three collectors for one canister into the raw store (needs a contact)."""
    from icp_threat_intel.collectors.dashboard import DashboardCollector
    from icp_threat_intel.collectors.raw_gateway import RawGatewayCollector
    from icp_threat_intel.collectors.read_state import ReadStateCollector
    from icp_threat_intel.collectors.runner import collect_into
    from icp_threat_intel.core.http import SafeHttpClient
    from icp_threat_intel.core.ic_client import IcClient
    from icp_threat_intel.db.models import RawSnapshotRow
    from icp_threat_intel.db.session import make_engine, make_session_factory
    from icp_threat_intel.raw_store.store import SqlRawStore

    settings = Settings.from_env()
    if not settings.contact:
        typer.echo("live inspect needs ICP_THREAT_INTEL_CONTACT (sent in the User-Agent)", err=True)
        raise typer.Exit(code=2)
    engine = make_engine(settings.database_url)
    sessions = make_session_factory(engine)
    store = SqlRawStore(sessions)
    try:
        with sessions() as session:  # fail before any request if the store is unusable
            session.execute(select(RawSnapshotRow.id).limit(1))
        with SafeHttpClient(settings.contact) as http:
            ic = IcClient(http)
            collectors = (
                ReadStateCollector(ic),
                RawGatewayCollector(http, ic),
                DashboardCollector(http),
            )
            for collector in collectors:
                try:
                    collect_into(collector, store, [canister_id])
                except SQLAlchemyError:
                    raise
                except Exception as exc:
                    typer.echo(f"{collector.name}: collection failed: {exc}", err=True)
    except SQLAlchemyError as exc:
        typer.echo(
            f"raw store unavailable ({exc.__class__.__name__}); run `make migrate`", err=True
        )
        raise typer.Exit(code=1) from None
    finally:
        engine.dispose()


def _latest_events(snapshots: list[RawSnapshot]) -> dict[tuple[str, str, str], Event]:
    """Newest event per (kind, source type, domain)."""
    latest: dict[tuple[str, str, str], Event] = {}
    for snap in snapshots:
        for event in PARSERS[snap.source_type].parse(snap).events:
            key = (event.kind, event.source_type.value, str(event.payload.get("domain", "")))
            if key not in latest or event.observed_at >= latest[key].observed_at:
                latest[key] = event
    return latest


def _pick(events: dict[tuple[str, str, str], Event], kind: str, field: str) -> tuple[Any, str]:
    """First non-empty ``field`` of ``kind``, preferring read_state over the Dashboard."""
    for source in (SourceType.IC_READ_STATE, SourceType.DASHBOARD_API):
        event = events.get((kind, source.value, ""))
        if event is not None and event.payload.get(field) not in (None, ""):
            return event.payload[field], source.value
    return None, "-"


def render(canister_id: str, snapshots: list[RawSnapshot], origin: str) -> list[str]:
    events = _latest_events(snapshots)
    synthetic = any(s.synthetic for s in snapshots)
    status, status_src = _pick(events, "canister.state_observed", "canister_status")
    subnet, subnet_src = _pick(events, "canister.state_observed", "subnet_id")
    controllers, ctl_src = _pick(events, "canister.state_observed", "controllers")
    module_hash, mh_src = _pick(events, "canister.state_observed", "module_hash")
    lines = [
        f"canister:     {canister_id}",
        f"data:         {origin}{' (SYNTHETIC fixtures, not observations)' if synthetic else ''}",
        f"status:       {status or 'unknown'} [{status_src}]",
        f"subnet:       {subnet or 'unknown'} [{subnet_src}]",
        f"controllers:  {', '.join(controllers) if controllers else 'unknown'} [{ctl_src}]",
        f"module hash:  {module_hash or 'unknown'} [{mh_src}]",
    ]
    state = events.get(("canister.state_observed", SourceType.IC_READ_STATE.value, ""))
    if state is not None:
        lines.append(f"certificate:  {state.payload.get('verification', 'n/a')}")
    candid = events.get(("canister.candid_observed", SourceType.IC_READ_STATE.value, ""))
    if candid is None:
        lines.append("candid:       not read")
    elif candid.payload.get("status") != "ok":
        lines.append(f"candid:       {candid.payload.get('status')}")
    else:
        methods = candid.payload.get("candid_methods") or []
        lines.append(f"candid:       {len(methods)} method(s)")
        for m in methods:
            sig = f"({', '.join(m['args'])}) -> ({', '.join(m['rets'])})"
            lines.append(f"  {m['name']} : {sig} {m['mode']}")
    lines.append("raw gateway:")
    for (kind, _src, domain), event in sorted(events.items()):
        if kind not in ("gateway.body_observed", "gateway.http_request_queried"):
            continue
        p = event.payload
        where = domain or "http_request query"
        parts = [f"outcome={p.get('outcome')}", f"http={p.get('http_status')}"]
        if "body_class" in p:
            parts += [f"class={p['body_class']}", f"size={p.get('size')}",
                      f"sha256={str(p.get('body_sha256'))[:16]}..."]  # fmt: skip
        if p.get("denylisted"):
            parts.append("DENYLISTED")
        lines.append(f"  {where}: {' '.join(parts)}")
        if p.get("excerpt"):
            lines.append(f"    excerpt: {p['excerpt'][:120]!r}")
    if lines[-1] == "raw gateway:":
        lines.append("  no gateway data")
    return lines


@canister_app.command("inspect")
def canister_inspect(
    canister_id: Annotated[str, typer.Argument(help="Canister ID, e.g. aaaaa-aa...-cai.")],
    offline: Annotated[
        bool, typer.Option("--offline", help="Read the raw store or cassettes, never the network.")
    ] = False,
    cassettes: Annotated[
        Path, typer.Option("--cassettes", help="Cassette directory for offline mode.")
    ] = DEFAULT_CASSETTES,
) -> None:
    """Show a canister's public state: status, controllers, module hash, Candid, raw body."""
    try:
        principal_from_text(canister_id)
    except ValueError:
        typer.echo(f"not a canister id: {canister_id!r}", err=True)
        raise typer.Exit(code=2) from None
    if not offline:
        _collect_live(canister_id)
    snapshots, origin = _store_snapshots(canister_id), "raw store"
    if not snapshots and offline:
        snapshots, origin = snapshots_for(cassettes, canister_id), f"cassettes ({cassettes})"
    if not snapshots:
        typer.echo(f"no {'offline ' if offline else ''}data for {canister_id}", err=True)
        raise typer.Exit(code=1)
    for line in render(canister_id, snapshots, origin):
        typer.echo(line)
