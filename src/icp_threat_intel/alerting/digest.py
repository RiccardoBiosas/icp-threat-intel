"""Daily digest (Markdown and JSON) and immediate alerts for verified detections."""

import json
from collections import Counter
from collections.abc import Iterable, Sequence
from datetime import datetime
from pathlib import Path

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


def build_digest(
    detections: Sequence[Detection], *, period_start: datetime, period_end: datetime
) -> Notification:
    ordered = sorted(
        detections,
        key=lambda d: (_ORDER[d.status], -d.weighted_confidence, d.rule_id, d.subject_id),
    )
    by_status = Counter(d.status.value for d in ordered)
    by_rule = Counter(d.rule_id for d in ordered)
    title = f"icp-threat-intel digest {period_start.date().isoformat()}"
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
    data = {
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "counts": {
            "by_status": dict(sorted(by_status.items())),
            "by_rule": dict(sorted(by_rule.items())),
        },
        "detections": [d.model_dump(mode="json") for d in ordered],
    }
    return Notification(kind="digest", title=title, markdown="\n".join(lines) + "\n", data=data)


def write_digest(digest: Notification, out_dir: Path) -> tuple[Path, Path]:
    """Write ``<title>.md`` and ``<title>.json``; returns both paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = digest.title.replace(" ", "_")
    md, js = out_dir / f"{stem}.md", out_dir / f"{stem}.json"
    md.write_text(digest.markdown, encoding="utf-8")
    js.write_text(json.dumps(digest.data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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
