"""Digest signals filter: ``--keyword LABEL`` (repeatable, any of) and ``--ioc-only``."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from icp_threat_intel.alerting.digest import build_digest
from icp_threat_intel.alerting.signals import SignalFilter, SignalPost, build_signals_digest
from icp_threat_intel.cli import publishing
from icp_threat_intel.cli.app import app
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import EventRow, Source
from icp_threat_intel.db.session import make_engine, make_session_factory
from icp_threat_intel.parsers.signals_keywords import KEYWORDS

NOW = datetime(2026, 10, 16, 1, 0, 0, tzinfo=UTC)
START = NOW - timedelta(hours=24)
runner = CliRunner()


def _post(post_id: int, keywords: tuple[str, ...], **kw: Any) -> SignalPost:
    fields: dict[str, Any] = {
        "feed": "dfinity-forum",
        "post_id": post_id,
        "url": None,
        "topic_title": "t",
        "created_at": None,
        "author_staff": False,
        "keywords": keywords,
        "canister_ids": (),
        "ioc_canisters": (),
    }
    return SignalPost(**(fields | kw))


PHISH = _post(1, ("phishing",))
SCAM = _post(2, ("scam", "stolen"))
IOC = _post(3, (), ioc_terms=("/tmp/pglog",))
IOC_PHISH = _post(4, ("phishing",), ioc_canisters=("tdtqy-oyaaa-aaaae-af2dq-cai",))
POSTS = [PHISH, SCAM, IOC, IOC_PHISH]


def test_no_filter_keeps_everything() -> None:
    f = SignalFilter.create()
    assert not f.active and [p for p in POSTS if f.matches(p)] == POSTS


def test_keyword_filter_is_any_of() -> None:
    f = SignalFilter.create(keywords=["phishing", "stolen"])
    assert [p.post_id for p in POSTS if f.matches(p)] == [1, 2, 4]


def test_ioc_only() -> None:
    f = SignalFilter.create(ioc_only=True)
    assert [p.post_id for p in POSTS if f.matches(p)] == [3, 4]


def test_keyword_and_ioc_only_combine() -> None:
    f = SignalFilter.create(keywords=["phishing"], ioc_only=True)
    assert [p.post_id for p in POSTS if f.matches(p)] == [4]


def test_unknown_label_is_refused_with_the_known_ones() -> None:
    with pytest.raises(ValueError, match="unknown keyword label") as exc:
        SignalFilter.create(keywords=["phising"])
    assert "phishing" in str(exc.value)


def test_labels_are_normalised_and_deduplicated() -> None:
    f = SignalFilter.create(keywords=["Phishing", "phishing", " scam "])
    assert f.keywords == ("phishing", "scam")


def test_every_keyword_label_is_accepted() -> None:
    assert SignalFilter.create(keywords=list(KEYWORDS)).keywords == tuple(sorted(KEYWORDS))


def test_describe_and_to_dict() -> None:
    f = SignalFilter.create(keywords=["scam", "phishing"], ioc_only=True)
    assert f.describe() == "keywords phishing, scam; IOC matches only"
    assert f.to_dict() == {"keywords": ["phishing", "scam"], "ioc_only": True}


def test_signals_digest_records_the_filter() -> None:
    f = SignalFilter.create(keywords=["phishing"])
    digest = build_signals_digest(
        [PHISH], period_start=START, period_end=NOW, total=1, signal_filter=f
    )
    assert "Filter: keywords phishing" in digest.markdown
    assert digest.data["signals_filter"] == {"keywords": ["phishing"], "ioc_only": False}


def test_unfiltered_digest_has_no_filter_line_or_key() -> None:
    digest = build_signals_digest([PHISH], period_start=START, period_end=NOW)
    assert "Filter:" not in digest.markdown and "signals_filter" not in digest.data


def test_full_digest_section_records_the_filter() -> None:
    f = SignalFilter.create(ioc_only=True)
    digest = build_digest([], period_start=START, period_end=NOW, signals=[IOC], signals_filter=f)
    assert "Filter: IOC matches only" in digest.markdown
    assert digest.data["signals_filter"] == {"keywords": [], "ioc_only": True}


def _db(tmp_path: Path) -> str:
    url = f"sqlite:///{tmp_path / 'd.db'}"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    with make_session_factory(engine)() as s, s.begin():
        src = Source(
            name="dfinity-forum",
            source_type=SourceType.SIGNALS_FEED,
            base_url="https://forum.dfinity.org",
            reliability=40,
        )
        s.add(src)
        s.flush()
        for i, (keywords, terms) in enumerate(
            [(["phishing"], []), (["scam"], []), (["drainer"], []), ([], ["/tmp/pglog"])]
        ):
            s.add(
                EventRow(
                    kind="signal.post_observed",
                    subject_type="signal_post",
                    subject_id=f"dfinity-forum:{i}",
                    observed_at=NOW - timedelta(minutes=1),
                    source_id=src.id,
                    source_type=SourceType.SIGNALS_FEED,
                    parser="signals_feed@2",
                    weight=40,
                    is_ioc=bool(terms),
                    payload={
                        "feed": "dfinity-forum",
                        "post_id": i,
                        "keywords": keywords,
                        "ioc_terms": terms,
                    },
                    dedup_key=f"{i:064d}",
                )
            )
    engine.dispose()
    return url


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *extra: str) -> tuple[int, str, str]:
    monkeypatch.setattr(publishing, "_now", lambda: NOW)
    out = tmp_path / "digests"
    result = runner.invoke(
        app,
        ["digest", "--signals-only", "--out", str(out), *extra],
        env={"ICP_THREAT_INTEL_DATABASE_URL": _db(tmp_path)},
    )
    md = next(out.glob("*.md"), None)
    return result.exit_code, result.output, md.read_text(encoding="utf-8") if md else ""


def test_cli_keyword(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, output, md = _run(tmp_path, monkeypatch, "--keyword", "phishing", "--keyword", "drainer")
    assert code == 0, output
    assert "signals digest: 2 signal(s)" in output
    assert "Filter: keywords drainer, phishing" in md
    assert "scam" not in md.split("## Signals")[1]


def test_cli_ioc_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, output, md = _run(tmp_path, monkeypatch, "--ioc-only")
    assert code == 0, output
    assert "signals digest: 1 signal(s)" in output
    assert "/tmp/pglog" in md


def test_cli_filter_with_limit_counts_the_filtered_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, output, md = _run(
        tmp_path, monkeypatch, "--keyword", "phishing", "--keyword", "scam", "--limit", "1"
    )
    assert code == 0, output
    assert "1 of 2 signal(s)" in output
    assert "Showing 1 of 2 matched posts" in md


def test_cli_unknown_keyword_exits_two_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, output, md = _run(tmp_path, monkeypatch, "--keyword", "phising")
    assert code == 2
    assert "unknown keyword label" in output and "phishing" in output
    assert md == ""


def test_comma_separated_labels() -> None:
    f = SignalFilter.create(keywords=["phishing,drainer", " scam , stolen "])
    assert f.keywords == ("drainer", "phishing", "scam", "stolen")


def test_empty_pieces_are_ignored() -> None:
    assert SignalFilter.create(keywords=["phishing,,", ","]).keywords == ("phishing",)


def test_only_empty_labels_is_refused() -> None:
    with pytest.raises(ValueError, match="no keyword labels"):
        SignalFilter.create(keywords=[" , "])


def test_unknown_label_inside_a_list_is_refused() -> None:
    with pytest.raises(ValueError, match="phising"):
        SignalFilter.create(keywords=["scam,phising"])


def test_cli_comma_separated_keyword(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, output, md = _run(tmp_path, monkeypatch, "--keyword", "phishing,drainer")
    assert code == 0, output
    assert "signals digest: 2 signal(s)" in output
    assert "Filter: keywords drainer, phishing" in md


def test_cli_comma_list_and_repeated_flags_combine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, output, md = _run(
        tmp_path, monkeypatch, "--keyword", "phishing,drainer", "--keyword", "scam"
    )
    assert code == 0, output
    assert "signals digest: 3 signal(s)" in output
    assert "Filter: keywords drainer, phishing, scam" in md
