"""Digest files: timestamped names (to the second), never overwritten without ``--overwrite``."""

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from icp_threat_intel.alerting.digest import DigestExists, build_digest, digest_stem, write_digest
from icp_threat_intel.cli import publishing
from icp_threat_intel.cli.app import app
from icp_threat_intel.core.models import Notification
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.session import make_engine

END = datetime(2026, 10, 15, 16, 6, 52, 168743, tzinfo=UTC)
START = END - timedelta(days=1)
runner = CliRunner()


def _digest(end: datetime = END) -> Notification:
    return build_digest([], period_start=end - timedelta(days=1), period_end=end)


def test_stem_has_utc_date_and_time_to_the_second() -> None:
    assert digest_stem(_digest()) == "icp-threat-intel_digest_2026-10-15T160652Z"


def test_stem_converts_to_utc() -> None:
    plus7 = END.astimezone(timezone(timedelta(hours=7)))
    assert digest_stem(_digest(plus7)) == "icp-threat-intel_digest_2026-10-15T160652Z"


def test_title_keeps_the_date_only() -> None:
    assert _digest().title == "icp-threat-intel digest 2026-10-15"


def test_write_creates_both_files(tmp_path: Path) -> None:
    md, js = write_digest(_digest(), tmp_path / "out")
    assert md.name == "icp-threat-intel_digest_2026-10-15T160652Z.md"
    assert js.name == "icp-threat-intel_digest_2026-10-15T160652Z.json"
    assert md.is_file() and js.is_file()


def test_runs_a_second_apart_keep_both(tmp_path: Path) -> None:
    write_digest(_digest(), tmp_path)
    write_digest(_digest(END + timedelta(seconds=1)), tmp_path)
    assert len(list(tmp_path.glob("*.md"))) == 2 and len(list(tmp_path.glob("*.json"))) == 2


@pytest.mark.parametrize("existing", [".md", ".json"])
def test_refuses_to_overwrite_and_writes_nothing(tmp_path: Path, existing: str) -> None:
    stem = digest_stem(_digest())
    taken = tmp_path / f"{stem}{existing}"
    taken.write_text("keep me", encoding="utf-8")
    with pytest.raises(DigestExists) as exc:
        write_digest(_digest(), tmp_path)
    assert exc.value.path == taken
    assert isinstance(exc.value, FileExistsError)
    assert taken.read_text(encoding="utf-8") == "keep me"
    assert [p.name for p in tmp_path.iterdir()] == [taken.name]  # the other file not written


def test_overwrite_replaces_both(tmp_path: Path) -> None:
    md, js = write_digest(_digest(), tmp_path)
    md.write_text("old", encoding="utf-8")
    js.write_text("old", encoding="utf-8")
    write_digest(_digest(), tmp_path, overwrite=True)
    assert md.read_text(encoding="utf-8").startswith("# icp-threat-intel digest")
    assert js.read_text(encoding="utf-8").startswith("{")


def _cli(tmp_path: Path, *extra: str) -> Result:
    db = tmp_path / "d.db"
    if not db.exists():
        engine = make_engine(f"sqlite:///{db}")
        Base.metadata.create_all(engine)
        engine.dispose()
    return runner.invoke(
        app,
        ["digest", "--out", str(tmp_path / "digests"), *extra],
        env={"ICP_THREAT_INTEL_DATABASE_URL": f"sqlite:///{db}"},
    )


def test_cli_refuses_existing_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(publishing, "_now", lambda: END)
    first = _cli(tmp_path)
    assert first.exit_code == 0, first.output
    md = tmp_path / "digests" / "icp-threat-intel_digest_2026-10-15T160652Z.md"
    md.write_text("keep me", encoding="utf-8")
    second = _cli(tmp_path)
    assert second.exit_code == 1
    assert "digest exists" in second.output and "--overwrite" in second.output
    assert md.read_text(encoding="utf-8") == "keep me"


def test_cli_overwrite_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(publishing, "_now", lambda: END)
    _cli(tmp_path)
    md = tmp_path / "digests" / "icp-threat-intel_digest_2026-10-15T160652Z.md"
    md.write_text("old", encoding="utf-8")
    result = _cli(tmp_path, "--overwrite")
    assert result.exit_code == 0, result.output
    assert md.read_text(encoding="utf-8").startswith("# icp-threat-intel digest")
