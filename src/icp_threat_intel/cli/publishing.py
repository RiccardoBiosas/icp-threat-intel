"""``publish`` and ``digest`` commands."""

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from icp_threat_intel.core.models import Case
from icp_threat_intel.publishing.case import GatedExporter
from icp_threat_intel.publishing.gate import DisclosureRequired
from icp_threat_intel.publishing.markdown import MarkdownExporter
from icp_threat_intel.publishing.misp import MispExporter
from icp_threat_intel.publishing.stix import StixExporter
from icp_threat_intel.publishing.threatfox import ThreatFoxExporter


class Format(StrEnum):
    THREATFOX = "threatfox"
    STIX = "stix"
    MISP = "misp"
    MARKDOWN = "markdown"


EXPORTERS: dict[Format, type[GatedExporter]] = {
    Format.THREATFOX: ThreatFoxExporter,
    Format.STIX: StixExporter,
    Format.MISP: MispExporter,
    Format.MARKDOWN: MarkdownExporter,
}


def publish(
    case_file: Annotated[
        Path, typer.Option("--case", help="Case JSON file.", exists=True, dir_okay=False)
    ],
    fmt: Annotated[Format, typer.Option("--format", help="Export format.")],
    out: Annotated[Path, typer.Option("--out", help="Output file (written locally only).")],
) -> None:
    """Export a disclosed case as ThreatFox, STIX 2.1, MISP or Markdown (local file only)."""
    try:
        case = Case.model_validate_json(case_file.read_text(encoding="utf-8"))
    except ValidationError as exc:
        typer.echo(f"invalid case file: {exc}", err=True)
        raise typer.Exit(code=1) from None
    try:
        data = EXPORTERS[fmt]().export(case)
    except DisclosureRequired as exc:
        typer.echo(f"refused: {exc}", err=True)
        raise typer.Exit(code=1) from None
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    typer.echo(f"wrote {fmt.value} export of case {case.case_id} to {out}")


def _now() -> datetime:
    return datetime.now(UTC)


def digest(
    out_dir: Annotated[Path, typer.Option("--out", help="Directory for .md and .json.")] = Path(
        "digests"
    ),
    hours: Annotated[int, typer.Option("--hours", help="Look-back window.", min=1)] = 24,
    overwrite: Annotated[
        bool, typer.Option("--overwrite", help="Replace a digest file that already exists.")
    ] = False,
) -> None:
    """Build the digest (Markdown and JSON) from detections in the database.

    Files are named after the period end in UTC, to the second, and existing files are
    never replaced unless ``--overwrite`` is given.
    """
    from sqlalchemy import select

    from icp_threat_intel.alerting.digest import DigestExists, build_digest, write_digest
    from icp_threat_intel.alerting.signals import recent_signals
    from icp_threat_intel.alerting.watch import latest_census, watched_canisters
    from icp_threat_intel.db.models import DetectionRow
    from icp_threat_intel.db.session import make_engine, make_session_factory
    from icp_threat_intel.verification.store import to_model

    end = _now()
    start = end - timedelta(hours=hours)
    with make_session_factory(make_engine())() as session:
        rows = session.scalars(select(DetectionRow).where(DetectionRow.updated_at >= start))
        detections = [to_model(r) for r in rows]
        watched, census = watched_canisters(session), latest_census(session)
        signals = recent_signals(session, start)
    report = build_digest(
        detections,
        period_start=start,
        period_end=end,
        watched=watched,
        census=census,
        signals=signals,
    )
    try:
        md, js = write_digest(report, out_dir, overwrite=overwrite)
    except DigestExists as exc:
        typer.echo(f"{exc}; nothing written (use --overwrite to replace it)", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(f"digest: {len(detections)} detection(s), {len(signals)} signal(s) -> {md}, {js}")
