"""Daily digest (Markdown and JSON) and immediate alerts for verified detections."""

import json
from collections import Counter
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from icp_threat_intel.alerting.signals import SignalFilter, SignalPost, signals_section
from icp_threat_intel.alerting.watch import CensusSummary, WatchedCanister
from icp_threat_intel.core.enums import DetectionStatus
from icp_threat_intel.core.interfaces import Notifier
from icp_threat_intel.core.models import Detection, Notification

_ORDER = {DetectionStatus.VERIFIED: 0, DetectionStatus.CANDIDATE: 1, DetectionStatus.DISMISSED: 2}


def _row(d: Detection) -> str:
    subject = d.subject_id.replace("|", "\\|")
    return (
        f"| {d.status.value} | {d.rule_id} | `{subject}` | {d.score:.2f} | "
        f"{d.weighted_confidence:.2f} | {', '.join(sorted(d.signals))} |"
    )


def _ts(value: datetime | None) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%MZ") if value else "-"


def _watched_section(watched: Sequence[WatchedCanister]) -> list[str]:
    lines = ["", "## Watched canisters", "",
             "IOC canisters, latest observation, and change since the previous observation.", "",
             "| Canister | Last observed | Module hash | Controllers | Gateway | Since previous |",
             "|---|---|---|---|---|---|"]  # fmt: skip
    for w in watched:
        if w.last_observed is None:
            lines.append(f"| `{w.canister_id}` | never observed | - | - | - | - |")
            continue
        module = f"`{w.module_hash[:8]}…`" if w.module_hash else "unknown"
        controllers = str(len(w.controllers)) if w.controllers is not None else "unknown"
        gateway = f"{w.gateway} (since {_ts(w.gateway_since)})" if w.gateway_since else w.gateway
        if w.changes:
            since = f"**CHANGED: {', '.join(w.changes)}**"
        else:
            since = "unchanged" if w.observations > 1 else "first observation"
        lines.append(
            f"| `{w.canister_id}` | {_ts(w.last_observed)} | {module} | {controllers} | "
            f"{gateway} | {since} |"
        )
    return lines


def _census_section(c: CensusSummary) -> list[str]:
    total = c.complete_subnets + c.incomplete_subnets
    lines = [
        "", "## Census", "",
        f"Latest run `{c.run_id}` at {_ts(c.observed_at)}: {c.canisters} canisters, "
        f"+{c.added} added, -{c.removed} removed, ~{c.changed} changed; "
        f"{c.complete_subnets} of {total} subnets walked completely"
        + ("; **ceiling hit**." if c.ceiling_hit else "."),
    ]  # fmt: skip
    if c.incomplete_subnets:
        lines.append(
            "Removals are only reported for subnets walked completely in two runs, so this "
            "run is a sample."
        )
    return lines


def build_digest(
    detections: Sequence[Detection],
    *,
    period_start: datetime,
    period_end: datetime,
    watched: Sequence[WatchedCanister] = (),
    census: CensusSummary | None = None,
    signals: Sequence[SignalPost] = (),
    signals_total: int | None = None,
    signals_filter: SignalFilter | None = None,
) -> Notification:
    ordered = sorted(
        detections,
        key=lambda d: (_ORDER[d.status], -d.weighted_confidence, d.rule_id, d.subject_id),
    )
    by_status = Counter(d.status.value for d in ordered)
    by_rule = Counter(d.rule_id for d in ordered)
    title = f"icp-threat-intel digest {period_end.date().isoformat()}"
    lines = [
        f"# {title}",
        "",
        f"Period: {period_start.isoformat()} to {period_end.isoformat()}",
        "",
        "Detections: " + (", ".join(f"{k} {v}" for k, v in sorted(by_status.items())) or "none"),
    ]
    if ordered:
        lines += ["", "| Status | Rule | Subject | Score | Confidence | Signals |",
                  "|---|---|---|---|---|---|", *(_row(d) for d in ordered)]  # fmt: skip
    if watched:
        lines += _watched_section(watched)
    if census is not None:
        lines += _census_section(census)
    if signals:
        lines += signals_section(signals, signals_total, signals_filter)
    data: dict[str, Any] = {
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "counts": {
            "by_status": dict(sorted(by_status.items())),
            "by_rule": dict(sorted(by_rule.items())),
        },
        "detections": [d.model_dump(mode="json") for d in ordered],
        "watched": [w.to_dict() for w in watched],
        "census": census.to_dict() if census is not None else None,
        "signals_total": signals_total if signals_total is not None else len(signals),
        "signals": [p.to_dict() for p in signals],
    }
    if signals_filter is not None and signals_filter.active:
        data["signals_filter"] = signals_filter.to_dict()
    return Notification(kind="digest", title=title, markdown="\n".join(lines) + "\n", data=data)


class DigestExists(FileExistsError):
    """A digest file with this name is already on disk and ``overwrite`` was not set."""

    def __init__(self, path: Path) -> None:
        super().__init__(f"digest exists: {path}")
        self.path = path


def digest_stem(digest: Notification) -> str:
    """``<title without its date>_<period end, UTC, to the second>``.

    ``icp-threat-intel_digest_2026-10-15T160652Z`` for the full digest,
    ``icp-threat-intel_signals_digest_...`` for ``digest --signals-only``.
    """
    end = datetime.fromisoformat(str(digest.data["period_end"])).astimezone(UTC)
    prefix = "_".join(digest.title.split()[:-1])
    return f"{prefix}_{end:%Y-%m-%dT%H%M%SZ}"


def write_digest(
    digest: Notification, out_dir: Path, *, overwrite: bool = False
) -> tuple[Path, Path]:
    """Write ``<stem>.md`` and ``<stem>.json``; returns both paths.

    Existing files are never replaced unless ``overwrite`` is true: if either file exists,
    ``DigestExists`` is raised before anything is written. Files are created exclusively,
    so a file appearing between the check and the write is not clobbered either.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = digest_stem(digest)
    md, js = out_dir / f"{stem}.md", out_dir / f"{stem}.json"
    if not overwrite:
        for path in (md, js):
            if path.exists():
                raise DigestExists(path)
    mode = "w" if overwrite else "x"
    contents = (
        (md, digest.markdown),
        (js, json.dumps(digest.data, indent=2, sort_keys=True) + "\n"),
    )
    for path, text in contents:
        try:
            with path.open(mode, encoding="utf-8") as handle:
                handle.write(text)
        except FileExistsError:
            raise DigestExists(path) from None
    return md, js


def verified_alert(detection: Detection) -> Notification:
    if detection.status is not DetectionStatus.VERIFIED:
        raise ValueError("immediate alerts are only for verified detections")
    title = f"VERIFIED {detection.rule_id}: {detection.subject_id}"
    markdown = (
        f"# {title}\n\n{detection.explanation}\n\n"
        f"Score {detection.score:.2f}, weighted confidence {detection.weighted_confidence:.2f}, "
        f"signals: {', '.join(sorted(detection.signals))}.\n"
    )
    return Notification(
        kind="alert", title=title, markdown=markdown, data=detection.model_dump(mode="json")
    )


def alert_verified(detections: Iterable[Detection], notifiers: Sequence[Notifier]) -> int:
    """Send one alert per verified detection to every notifier; returns alerts sent."""
    sent = 0
    for detection in detections:
        if detection.status is DetectionStatus.VERIFIED:
            for notifier in notifiers:
                notifier.notify(verified_alert(detection))
            sent += 1
    return sent
