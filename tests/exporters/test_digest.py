"""Daily digest (Markdown + JSON), immediate alerts, stdout notifier, publish/digest CLI."""

import io
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from icp_threat_intel.alerting.digest import (
    alert_verified,
    build_digest,
    verified_alert,
    write_digest,
)
from icp_threat_intel.alerting.stdout import StdoutNotifier
from icp_threat_intel.cli.app import app
from icp_threat_intel.core.enums import DetectionStatus
from icp_threat_intel.core.models import Case, Notification
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.session import make_engine, make_session_factory
from icp_threat_intel.verification.store import save_candidate
from tests.exporters.conftest import verified_h1

END = datetime(2026, 10, 15, tzinfo=UTC)
START = END - timedelta(days=1)


def _detections() -> list:  # type: ignore[type-arg]
    candidate = verified_h1("cjn37-uyaaa-aaaac-qgnva-cai").model_copy(
        update={"status": DetectionStatus.CANDIDATE, "weighted_confidence": 0.7}
    )
    return [candidate, verified_h1()]


def test_digest_markdown_and_json(tmp_path: Path) -> None:
    digest = build_digest(_detections(), period_start=START, period_end=END)
    assert digest.kind == "digest" and digest.title.endswith("2026-10-14")
    assert "candidate 1, verified 1" in digest.markdown
    rows = [line for line in digest.markdown.splitlines() if line.startswith("| verified")]
    assert digest.markdown.index("| verified") < digest.markdown.index("| candidate") and rows
    md, js = write_digest(digest, tmp_path / "out")
    assert md.read_text() == digest.markdown
    data = json.loads(js.read_text())
    assert data["counts"]["by_status"] == {"candidate": 1, "verified": 1}
    assert data["counts"]["by_rule"] == {"H1": 2} and len(data["detections"]) == 2


def test_empty_digest() -> None:
    digest = build_digest([], period_start=START, period_end=END)
    assert "Detections: none" in digest.markdown and digest.data["detections"] == []


def test_alerts_only_for_verified() -> None:
    stream = io.StringIO()
    sent = alert_verified(_detections(), [StdoutNotifier(stream)])
    assert sent == 1
    assert "VERIFIED H1: tdtqy-oyaaa-aaaae-af2dq-cai" in stream.getvalue()
    with pytest.raises(ValueError):
        verified_alert(_detections()[0])


def test_stdout_notifier_adds_newline() -> None:
    stream = io.StringIO()
    StdoutNotifier(stream).notify(Notification(kind="alert", title="t", markdown="no newline"))
    assert stream.getvalue() == "no newline\n"


runner = CliRunner()


def test_cli_publish(tmp_path: Path, case: Case, undisclosed: Case) -> None:
    case_file, undisclosed_file = tmp_path / "case.json", tmp_path / "undisclosed.json"
    case_file.write_text(case.model_dump_json())
    undisclosed_file.write_text(undisclosed.model_dump_json())
    for fmt in ("threatfox", "stix", "misp", "markdown"):
        out = tmp_path / f"out.{fmt}"
        result = runner.invoke(
            app, ["publish", "--case", str(case_file), "--format", fmt, "--out", str(out)]
        )
        assert result.exit_code == 0, result.output
        assert out.stat().st_size > 0
    refused = runner.invoke(
        app,
        [
            "publish",
            "--case",
            str(undisclosed_file),
            "--format",
            "stix",
            "--out",
            str(tmp_path / "x"),
        ],
    )
    assert refused.exit_code == 1 and "refused" in refused.output and not (tmp_path / "x").exists()
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    invalid = runner.invoke(
        app, ["publish", "--case", str(bad), "--format", "stix", "--out", str(tmp_path / "y")]
    )
    assert invalid.exit_code == 1 and "invalid case file" in invalid.output


def test_cli_digest(tmp_path: Path) -> None:
    db = tmp_path / "d.db"
    engine = make_engine(f"sqlite:///{db}")
    Base.metadata.create_all(engine)
    with make_session_factory(engine)() as s, s.begin():
        save_candidate(s, _detections()[0])
    engine.dispose()
    out = tmp_path / "digests"
    result = runner.invoke(
        app, ["digest", "--out", str(out)], env={"ICP_THREAT_INTEL_DATABASE_URL": f"sqlite:///{db}"}
    )
    assert result.exit_code == 0, result.output
    assert "1 detection(s)" in result.output
    assert len(list(out.glob("*.md"))) == 1 and len(list(out.glob("*.json"))) == 1
