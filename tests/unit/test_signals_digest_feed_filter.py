"""Digest ``--feed NAME[,NAME...]``: only signals (and blocklisted canisters) from those feeds."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from icp_threat_intel.alerting.signals import SignalFilter, SignalPost, known_feeds
from icp_threat_intel.cli import publishing
from icp_threat_intel.cli.app import app
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import EventRow, Source
from icp_threat_intel.db.session import make_engine, make_session_factory

NOW = datetime(2026, 10, 16, 6, 0, tzinfo=UTC)
CANISTER = "tdtqy-oyaaa-aaaae-af2dq-cai"
runner = CliRunner()


def _post(post_id: int, feed: str, keywords: tuple[str, ...] = ("scam",)) -> SignalPost:
    return SignalPost(
        feed=feed,
        post_id=post_id,
        url=None,
        topic_title="t",
        created_at=None,
        author_staff=False,
        keywords=keywords,
        canister_ids=(),
        ioc_canisters=(),
    )


FORUM = _post(1, "dfinity-forum")
HN = _post(2, "hackernews")
HN_PHISH = _post(3, "hackernews", ("phishing",))


def test_known_feeds() -> None:
    assert known_feeds() == ("dfinity-forum", "hackernews", "phishdestroy")


def test_feed_filter_keeps_only_those_feeds() -> None:
    f = SignalFilter.create(feeds=["hackernews"])
    assert [p.post_id for p in (FORUM, HN, HN_PHISH) if f.matches(p)] == [2, 3]
    assert f.active and f.feeds == ("hackernews",)


def test_comma_separated_and_repeated_feeds() -> None:
    f = SignalFilter.create(feeds=["hackernews, dfinity-forum", "HackerNews"])
    assert f.feeds == ("dfinity-forum", "hackernews")


def test_unknown_feed_refused_with_the_known_ones() -> None:
    with pytest.raises(ValueError, match="unknown feed") as exc:
        SignalFilter.create(feeds=["reddit"])
    assert "hackernews" in str(exc.value)


def test_only_empty_feeds_refused() -> None:
    with pytest.raises(ValueError, match="no feed names"):
        SignalFilter.create(feeds=[","])


def test_feed_and_keyword_combine() -> None:
    f = SignalFilter.create(keywords=["phishing"], feeds=["hackernews"])
    assert [p.post_id for p in (FORUM, HN, HN_PHISH) if f.matches(p)] == [3]


def test_describe_and_to_dict_include_feeds() -> None:
    f = SignalFilter.create(keywords=["scam"], feeds=["hackernews"], ioc_only=True)
    assert f.describe() == "feeds hackernews; keywords scam; IOC matches only"
    assert f.to_dict() == {
        "keywords": ["scam"],
        "ioc_only": True,
        "feeds": ["hackernews"],
    }


def test_to_dict_without_feeds_is_unchanged() -> None:
    assert SignalFilter.create(ioc_only=True).to_dict() == {"keywords": [], "ioc_only": True}


def _db(tmp_path: Path) -> str:
    url = f"sqlite:///{tmp_path / 'd.db'}"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    with make_session_factory(engine)() as s, s.begin():
        sources = {}
        for name in ("dfinity-forum", "hackernews", "phishdestroy"):
            src = Source(
                name=name, source_type=SourceType.SIGNALS_FEED, base_url="", reliability=40
            )
            s.add(src)
            s.flush()
            sources[name] = src
        rows: list[dict[str, Any]] = [
            {"feed": "dfinity-forum", "n": 1, "kind": "signal.post_observed"},
            {"feed": "hackernews", "n": 2, "kind": "signal.post_observed"},
            {"feed": "hackernews", "n": 3, "kind": "signal.post_observed"},
            {"feed": "phishdestroy", "n": 4, "kind": "signal.canister_listed"},
        ]
        for r in rows:
            listed = r["kind"] == "signal.canister_listed"
            s.add(
                EventRow(
                    kind=r["kind"],
                    subject_type="canister" if listed else "signal_post",
                    subject_id=CANISTER if listed else f"{r['feed']}:{r['n']}",
                    canister_id=CANISTER if listed else None,
                    observed_at=NOW - timedelta(minutes=5),
                    source_id=sources[r["feed"]].id,
                    source_type=SourceType.SIGNALS_FEED,
                    parser="signals_feed@3",
                    weight=40,
                    payload={
                        "feed": r["feed"],
                        "post_id": r["n"],
                        "keywords": ["scam"],
                        "hosts": [f"{CANISTER}.icp0.io"],
                    },
                    dedup_key=f"{r['n']:064d}",
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


def test_cli_feed_hackernews(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, output, md = _run(tmp_path, monkeypatch, "--feed", "hackernews")
    assert code == 0, output
    assert "signals digest: 2 signal(s) ->" in output  # no blocklisted canisters
    assert "Filter: feeds hackernews" in md
    assert "dfinity-forum" not in md.split("## Signals")[1]
    assert "Blocklisted" not in md


def test_cli_feed_list_with_blocklist(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, output, md = _run(tmp_path, monkeypatch, "--feed", "dfinity-forum,phishdestroy")
    assert code == 0, output
    assert "1 signal(s), 1 blocklisted canister(s)" in output
    assert "## Blocklisted ICP canisters" in md


def test_cli_unknown_feed_exits_two(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, output, md = _run(tmp_path, monkeypatch, "--feed", "reddit")
    assert code == 2 and "unknown feed" in output and md == ""
