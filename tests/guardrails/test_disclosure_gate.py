"""Guardrail 7: nothing is published for a case that has no ``disclosed_at``."""

from datetime import UTC, datetime, timedelta

import pytest
from typer.testing import CliRunner

from icp_threat_intel.cli.app import app
from icp_threat_intel.core.models import Case
from icp_threat_intel.publishing.gate import DisclosureRequired, gated_export, require_disclosure

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)


class _RecordingExporter:
    format = "test"

    def __init__(self) -> None:
        self.calls = 0

    def export(self, case: Case) -> bytes:
        self.calls += 1
        return case.case_id.encode()


def _case(disclosed_at: datetime | None) -> Case:
    return Case(
        case_id="00000000-0000-4000-8000-000000000001",
        title="test case",
        created_at=NOW - timedelta(days=3),
        disclosed_at=disclosed_at,
    )


def test_case_without_disclosure_is_refused() -> None:
    with pytest.raises(DisclosureRequired):
        require_disclosure(_case(None), now=NOW)


def test_gated_export_never_reaches_the_exporter() -> None:
    exporter = _RecordingExporter()
    with pytest.raises(DisclosureRequired):
        gated_export(exporter, _case(None), now=NOW)
    assert exporter.calls == 0


def test_future_disclosure_is_refused() -> None:
    with pytest.raises(DisclosureRequired):
        require_disclosure(_case(NOW + timedelta(hours=1)), now=NOW)


def test_naive_disclosure_timestamp_is_refused() -> None:
    with pytest.raises(DisclosureRequired):
        require_disclosure(_case(datetime(2026, 10, 1, 9, 0)), now=NOW)


def test_disclosed_case_is_exported() -> None:
    exporter = _RecordingExporter()
    out = gated_export(exporter, _case(NOW - timedelta(days=1)), now=NOW)
    assert out == b"00000000-0000-4000-8000-000000000001"
    assert exporter.calls == 1


def test_publish_command_does_not_succeed_without_a_case() -> None:
    result = CliRunner().invoke(app, ["publish"])
    assert result.exit_code != 0
