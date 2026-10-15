"""Signals parser v2: IOC values from the ``iocs`` table are matched in post text at ingest."""

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import Engine, select
from sqlalchemy.orm import sessionmaker

from icp_threat_intel.core.enums import IocType, SourceType
from icp_threat_intel.core.models import RawSnapshot
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import EventRow, Ioc, Source
from icp_threat_intel.db.session import make_engine, make_session_factory
from icp_threat_intel.parsers.ingest import Ingestor, ioc_text_terms
from icp_threat_intel.parsers.signals_feed import SignalsFeedParser
from icp_threat_intel.parsers.signals_keywords import IocTerm
from icp_threat_intel.raw_store.store import SqlRawStore
from tests.collectors import _signals_feed_fixtures as fx

T0 = datetime(2026, 10, 15, 6, 0, tzinfo=UTC)
TERMS = (IocTerm("file_path", "/tmp/pglog"), IocTerm("systemd_unit", "pgmon.service"))
BODY = fx.body(
    fx.post(201, "Found /tmp/pglog and pgmon.service on my build box, no idea why."),
    fx.post(202, "Nothing relevant here."),
)


def _snap(body: bytes = BODY) -> RawSnapshot:
    fields: dict[str, Any] = {
        "id": 3,
        "source_type": SourceType.SIGNALS_FEED,
        "source_name": "dfinity-forum",
        "url": "https://forum.dfinity.org/posts.json",
        "fetched_at": T0,
        "sha256": "0" * 64,
        "stored_sha256": "0" * 64,
        "body": body,
        "size_bytes": len(body),
        "http_status": 200,
        "synthetic": True,
        "request_meta": {"feed": "dfinity-forum"},
    }
    return RawSnapshot(**fields)


def test_parser_version_is_2() -> None:
    assert SignalsFeedParser().parser_id == "signals_feed@2"


def test_without_terms_a_term_only_post_is_ignored() -> None:
    events = SignalsFeedParser().parse(_snap()).events
    assert [e.kind for e in events] == ["signal.feed_polled"]


def test_ioc_terms_make_a_post_observed_and_ioc() -> None:
    parser = SignalsFeedParser().with_ioc_terms(TERMS)
    polled, post = parser.parse(_snap()).events
    assert polled.payload["matched_posts"] == 1
    assert post.kind == "signal.post_observed" and post.is_ioc is True
    assert post.payload["ioc_terms"] == ["/tmp/pglog", "pgmon.service"]
    assert post.payload["keywords"] == []


def test_keyword_post_without_terms_is_not_ioc() -> None:
    parser = SignalsFeedParser().with_ioc_terms(TERMS)
    (_, post) = parser.parse(_snap(fx.body(fx.post(1, "a phishing site")))).events
    assert post.is_ioc is False and post.payload["ioc_terms"] == []


def test_with_ioc_terms_is_deterministic() -> None:
    a = SignalsFeedParser().with_ioc_terms(reversed(TERMS)).parse(_snap())
    b = SignalsFeedParser().with_ioc_terms(TERMS).parse(_snap())
    assert a == b


@pytest.fixture
def engine() -> Iterator[Engine]:
    eng = make_engine("sqlite://")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


def _seed(sessions: sessionmaker[Any]) -> None:
    with sessions() as s, s.begin():
        src = Source(name="seed", source_type=SourceType.VENDOR_RSS, base_url="", reliability=60)
        s.add(src)
        s.flush()
        for ioc_type, value in (
            (IocType.FILE_PATH, "/tmp/pglog"),
            (IocType.SYSTEMD_UNIT, "pgmon.service"),
            (IocType.CANISTER_ID, fx.IOC_CANISTER),
            (IocType.PACKAGE_VERSION, "npm:@opengov/form-renderer@0.2.20"),
        ):
            s.add(
                Ioc(
                    ioc_type=ioc_type,
                    value=value,
                    source_id=src.id,
                    source_ref=value,
                    source_url="",
                )
            )


def test_ioc_text_terms_from_the_table(engine: Engine) -> None:
    sessions = make_session_factory(engine)
    _seed(sessions)
    with sessions() as s:
        terms = ioc_text_terms(s)
    assert {t.term for t in terms} == {"/tmp/pglog", "pgmon.service", "@opengov/form-renderer"}


def test_ingest_matches_table_iocs(engine: Engine) -> None:
    sessions = make_session_factory(engine)
    _seed(sessions)
    store = SqlRawStore(sessions)
    from icp_threat_intel.core.models import RawFetch

    store.save(
        RawFetch(
            source_type=SourceType.SIGNALS_FEED,
            source_name="dfinity-forum",
            url="https://forum.dfinity.org/posts.json",
            fetched_at=T0,
            body=BODY,
            http_status=200,
            synthetic=True,
            request_meta={"feed": "dfinity-forum"},
        )
    )
    snapshots = list(store.iter_snapshots(SourceType.SIGNALS_FEED))
    Ingestor(sessions).ingest(snapshots)
    with sessions() as s:
        row = s.scalar(select(EventRow).where(EventRow.kind == "signal.post_observed"))
    assert row is not None and row.is_ioc is True
    assert row.payload["ioc_terms"] == ["/tmp/pglog", "pgmon.service"]
