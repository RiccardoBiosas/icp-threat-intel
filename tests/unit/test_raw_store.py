"""Raw store: verbatim, content-hashed, source-tagged, idempotent, redacted before storage."""

import hashlib
import os
import string
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.interfaces import RawStore
from icp_threat_intel.core.models import RawFetch
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import RawSnapshotRow, Source
from icp_threat_intel.db.session import make_engine, make_session_factory
from icp_threat_intel.raw_store.store import SnapshotNotFound, SqlRawStore

T0 = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)
GATEWAY = "https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/"


@pytest.fixture
def engine() -> Iterator[Engine]:
    eng = make_engine("sqlite://")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def sessions(engine: Engine) -> sessionmaker[Session]:
    return make_session_factory(engine)


@pytest.fixture
def store(sessions: sessionmaker[Session]) -> SqlRawStore:
    return SqlRawStore(sessions)


def _fetch(body: bytes = b"https://payload.example/stage2\n", **kw: object) -> RawFetch:
    fields: dict[str, object] = {
        "source_type": SourceType.RAW_GATEWAY,
        "source_name": "raw-gateway",
        "url": GATEWAY,
        "fetched_at": T0,
        "body": body,
        "http_status": 200,
        "content_type": "text/plain",
        "headers": {"Content-Type": "text/plain"},
        "request_meta": {"collector": "raw_gateway", "version": "1"},
    }
    fields.update(kw)
    return RawFetch.model_validate(fields)


def _token() -> str:
    alphabet = string.ascii_letters + string.digits
    return "gh" + "p_" + "".join(alphabet[b % len(alphabet)] for b in os.urandom(36))


def test_implements_the_protocol(store: SqlRawStore) -> None:
    assert isinstance(store, RawStore)


def test_body_is_stored_verbatim_with_hash_time_source_and_url(store: SqlRawStore) -> None:
    body = b"\xff\xfe\x00 not utf-8 <script>x</script>"
    ref = store.save(_fetch(body))
    assert ref.created is True
    snap = store.get(ref.id)
    assert snap.body == body
    assert snap.sha256 == hashlib.sha256(body).hexdigest() == snap.stored_sha256 == ref.sha256
    assert snap.fetched_at == T0
    assert snap.url == GATEWAY
    assert snap.source_type is SourceType.RAW_GATEWAY
    assert snap.source_name == "raw-gateway"
    assert snap.size_bytes == len(body)
    assert snap.http_status == 200
    assert snap.redacted is False


def test_identical_content_is_stored_once(
    store: SqlRawStore, sessions: sessionmaker[Session]
) -> None:
    first = store.save(_fetch())
    again = store.save(_fetch(fetched_at=T0 + timedelta(hours=6)))
    assert again.id == first.id
    assert again.created is False
    assert store.get(first.id).fetched_at == T0  # first fetch time kept
    with sessions() as s:
        assert len(s.scalars(select(RawSnapshotRow)).all()) == 1


def test_changed_content_is_a_new_snapshot(store: SqlRawStore) -> None:
    first = store.save(_fetch(b"https://a.example/1"))
    second = store.save(_fetch(b"https://a.example/2", fetched_at=T0 + timedelta(hours=1)))
    assert second.id != first.id
    assert second.created is True


def test_same_content_from_another_url_is_separate(store: SqlRawStore) -> None:
    a = store.save(_fetch())
    b = store.save(_fetch(url="https://cjn37-uyaaa-aaaac-qgnva-cai.raw.icp0.io/"))
    assert a.id != b.id


def test_source_is_registered_once(store: SqlRawStore, sessions: sessionmaker[Session]) -> None:
    store.save(_fetch(b"1"))
    store.save(_fetch(b"2"))
    with sessions() as s:
        sources = s.scalars(select(Source)).all()
    assert [(x.name, x.source_type, x.base_url) for x in sources] == [
        ("raw-gateway", SourceType.RAW_GATEWAY, "https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io")
    ]


def test_source_type_mismatch_is_refused(store: SqlRawStore) -> None:
    store.save(_fetch())
    with pytest.raises(ValueError):
        store.save(_fetch(b"other", source_type=SourceType.DASHBOARD_API))


def test_secrets_are_redacted_before_persistence(
    store: SqlRawStore, sessions: sessionmaker[Session]
) -> None:
    secret = _token()
    body = f"https://payload.example/stage2\n{secret}\n".encode()
    ref = store.save(
        _fetch(
            body,
            headers={"Authorization": "Bearer " + secret, "X-Note": secret},
            request_meta={"query": {"token": secret}},
        )
    )
    with sessions() as s:
        row = s.get(RawSnapshotRow, ref.id)
        assert row is not None
        stored = (row.body, str(row.headers), str(row.request_meta))
        assert row.redacted is True
        assert row.sha256 == hashlib.sha256(body).hexdigest()
        assert row.stored_sha256 == hashlib.sha256(row.body).hexdigest() != row.sha256
        assert {"api_token", "header"} <= set(row.redaction_kinds)
    assert secret.encode() not in stored[0]
    assert b"https://payload.example/stage2" in stored[0]
    assert secret not in stored[1]
    assert secret not in stored[2]


def test_redacted_body_is_still_idempotent(store: SqlRawStore) -> None:
    body = f"x {_token()} y".encode()
    assert store.save(_fetch(body)).id == store.save(_fetch(body)).id


def test_truncation_and_synthetic_flags_persist(store: SqlRawStore) -> None:
    snap = store.get(store.save(_fetch(b"A" * 10, truncated=True, synthetic=True)).id)
    assert snap.truncated is True
    assert snap.synthetic is True


def test_iter_snapshots_filters_by_source_type_and_time(store: SqlRawStore) -> None:
    store.save(_fetch(b"1", fetched_at=T0))
    store.save(_fetch(b"2", fetched_at=T0 + timedelta(hours=2)))
    store.save(
        _fetch(
            b"{}",
            source_type=SourceType.DASHBOARD_API,
            source_name="dashboard-api",
            url="https://ic-api.internetcomputer.org/api/v3/subnets",
        )
    )
    bodies = [s.body for s in store.iter_snapshots(SourceType.RAW_GATEWAY)]
    assert bodies == [b"1", b"2"]
    later = [s.body for s in store.iter_snapshots(SourceType.RAW_GATEWAY, T0 + timedelta(hours=1))]
    assert later == [b"2"]
    assert [s.body for s in store.iter_snapshots(SourceType.DASHBOARD_API)] == [b"{}"]


def test_missing_snapshot(store: SqlRawStore) -> None:
    with pytest.raises(SnapshotNotFound):
        store.get(12345)
