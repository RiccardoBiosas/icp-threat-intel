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


def digest(
    out_dir: Annotated[Path, typer.Option("--out", help="Directory for .md and .json.")] = Path(
        "digests"
    ),
    hours: Annotated[int, typer.Option("--hours", help="Look-back window.", min=1)] = 24,
) -> None:
    """Build the daily digest (Markdown and JSON) from detections in the database."""
    from sqlalchemy import select

    from icp_threat_intel.alerting.digest import build_digest, write_digest
    from icp_threat_intel.alerting.watch import latest_census, watched_canisters
    from icp_threat_intel.db.models import DetectionRow
    from icp_threat_intel.db.session import make_engine, make_session_factory
    from icp_threat_intel.verification.store import to_model

    end = datetime.now(UTC)
    start = end - timedelta(hours=hours)
    with make_session_factory(make_engine())() as session:
        rows = session.scalars(select(DetectionRow).where(DetectionRow.updated_at >= start))
        detections = [to_model(r) for r in rows]
        watched, census = watched_canisters(session), latest_census(session)
    report = build_digest(
        detections, period_start=start, period_end=end, watched=watched, census=census
    )
    md, js = write_digest(report, out_dir)
    typer.echo(f"digest: {len(detections)} detection(s) -> {md}, {js}")
