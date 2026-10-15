"""SQL-backed raw store: the evidence trail (SPEC section 6).

Every response is stored before any parsing: redact, hash, then insert-or-get. Identical
content from the same source and URL is stored once (the first ``fetched_at`` is kept).
"""

import urllib.parse
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.models import RawFetch, RawSnapshot, RawSnapshotRef
from icp_threat_intel.core.redaction import redact, redact_headers
from icp_threat_intel.core.trust import default_reliability
from icp_threat_intel.db.models import RawSnapshotRow, Source

log = structlog.get_logger(__name__)


class SnapshotNotFound(KeyError):
    """No raw snapshot has the requested id."""


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _redact_value(value: Any, kinds: set[str]) -> Any:
    if isinstance(value, str):
        result = redact(value.encode("utf-8", "surrogateescape"))
        kinds.update(result.kinds)
        return result.body.decode("utf-8", "surrogateescape")
    if isinstance(value, dict):
        return {k: _redact_value(v, kinds) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_redact_value(v, kinds) for v in value]
    return value


def get_or_create_source(session: Session, name: str, source_type: SourceType, url: str) -> Source:
    """Return the ``sources`` row called ``name``, creating it with its type's default weight."""
    source = session.scalar(select(Source).where(Source.name == name))
    if source is not None:
        if source.source_type != source_type:
            raise ValueError(f"source {name!r} is {source.source_type}, not {source_type}")
        return source
    parts = urllib.parse.urlsplit(url)
    base_url = f"{parts.scheme}://{parts.netloc}" if parts.netloc else ""
    source = Source(
        name=name,
        source_type=source_type,
        base_url=base_url,
        reliability=default_reliability(source_type),
    )
    session.add(source)
    session.flush()
    log.info("source_registered", name=name, source_type=str(source_type))
    return source


class SqlRawStore:
    """``RawStore`` implementation over the ``raw_snapshots`` table."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sessions = session_factory

    def save(self, fetch: RawFetch) -> RawSnapshotRef:
        """Redact, hash and store ``fetch``; idempotent on (source, url, sha256)."""
        body = redact(fetch.body)
        headers, header_kinds = redact_headers(fetch.headers)
        meta_kinds: set[str] = set()
        request_meta = _redact_value(dict(fetch.request_meta), meta_kinds)
        url = _redact_value(fetch.url, meta_kinds)
        kinds = sorted(set(body.kinds) | set(header_kinds) | meta_kinds)
        with self._sessions() as session, session.begin():
            source = get_or_create_source(session, fetch.source_name, fetch.source_type, url)
            existing = self._find(session, source.id, url, body.sha256)
            if existing is not None:
                return RawSnapshotRef(id=existing, sha256=body.sha256, created=False)
            row = RawSnapshotRow(
                source_id=source.id,
                url=url,
                fetched_at=_aware(fetch.fetched_at),
                sha256=body.sha256,
                body=body.body,
                stored_sha256=body.stored_sha256,
                size_bytes=len(fetch.body),
                truncated=fetch.truncated,
                http_status=fetch.http_status,
                content_type=fetch.content_type,
                headers=headers,
                redacted=bool(kinds),
                redaction_kinds=kinds,
                synthetic=fetch.synthetic,
                request_meta=request_meta,
            )
            try:
                with session.begin_nested():
                    session.add(row)
            except IntegrityError:
                # A concurrent writer stored the same content first.
                existing = self._find(session, source.id, url, body.sha256)
                if existing is None:
                    raise
                return RawSnapshotRef(id=existing, sha256=body.sha256, created=False)
            if kinds:
                log.warning("raw_body_redacted", url=url, kinds=kinds)
            return RawSnapshotRef(id=row.id, sha256=body.sha256, created=True)

    def get(self, snapshot_id: int) -> RawSnapshot:
        with self._sessions() as session:
            found = session.execute(
                select(RawSnapshotRow, Source)
                .join(Source, RawSnapshotRow.source_id == Source.id)
                .where(RawSnapshotRow.id == snapshot_id)
            ).first()
            if found is None:
                raise SnapshotNotFound(snapshot_id)
            return _to_model(found[0], found[1])

    def iter_snapshots(
        self, source_type: SourceType, since: datetime | None = None
    ) -> Iterator[RawSnapshot]:
        """Snapshots of ``source_type`` in fetch order, optionally from ``since`` on."""
        query = (
            select(RawSnapshotRow, Source)
            .join(Source, RawSnapshotRow.source_id == Source.id)
            .where(Source.source_type == source_type)
            .order_by(RawSnapshotRow.fetched_at, RawSnapshotRow.id)
        )
        if since is not None:
            query = query.where(RawSnapshotRow.fetched_at >= since)
        with self._sessions() as session:
            for row, source in session.execute(query):
                yield _to_model(row, source)

    @staticmethod
    def _find(session: Session, source_id: int, url: str, sha256: str) -> int | None:
        return session.scalar(
            select(RawSnapshotRow.id).where(
                RawSnapshotRow.source_id == source_id,
                RawSnapshotRow.url == url,
                RawSnapshotRow.sha256 == sha256,
            )
        )


def _to_model(row: RawSnapshotRow, source: Source) -> RawSnapshot:
    return RawSnapshot(
        id=row.id,
        source_type=source.source_type,
        source_name=source.name,
        url=row.url,
        fetched_at=_aware(row.fetched_at),
        sha256=row.sha256,
        stored_sha256=row.stored_sha256,
        body=row.body,
        size_bytes=row.size_bytes,
        truncated=row.truncated,
        http_status=row.http_status,
        content_type=row.content_type,
        headers=dict(row.headers),
        redacted=row.redacted,
        redaction_kinds=tuple(row.redaction_kinds),
        synthetic=row.synthetic,
        request_meta=dict(row.request_meta),
    )
