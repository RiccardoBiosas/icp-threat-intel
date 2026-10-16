"""Migration 0002: the ``signals_feed`` source type is accepted by migrated databases."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from icp_threat_intel.db.session import make_engine

REPO = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC).isoformat()


def _config(url: str) -> Config:
    cfg = Config(str(REPO / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO / "alembic"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def _insert_source(url: str, source_type: str) -> None:
    engine = make_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO sources (name, source_type, base_url, reliability, status,"
                    " enabled, created_at) VALUES (:n, :t, '', 40, 'active', 1, :c)"
                ),
                {"n": f"src-{source_type}", "t": source_type, "c": NOW},
            )
            source_id = conn.execute(text("SELECT max(id) FROM sources")).scalar_one()
            conn.execute(
                text(
                    "INSERT INTO events (kind, subject_type, subject_id, observed_at, source_id,"
                    " source_type, parser, weight, is_ioc, payload, dedup_key) VALUES"
                    " ('signal.feed_polled', 'signal_feed', 'f', :c, :s, :t, 'p', 40, 0, '{}',"
                    " :k)"
                ),
                {"c": NOW, "s": source_id, "t": source_type, "k": source_type.ljust(64, "x")},
            )
    finally:
        engine.dispose()


def test_head_accepts_signals_feed(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'head.db'}"
    command.upgrade(_config(url), "head")
    _insert_source(url, "signals_feed")
    _insert_source(url, "vendor_rss")


def test_head_still_rejects_unknown_source_types(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'head.db'}"
    command.upgrade(_config(url), "head")
    with pytest.raises(IntegrityError):
        _insert_source(url, "pastebin")


def test_0001_rejected_signals_feed(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'v1.db'}"
    command.upgrade(_config(url), "0001")
    with pytest.raises(IntegrityError):
        _insert_source(url, "signals_feed")


def test_downgrade_to_0001_keeps_existing_rows(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'down.db'}"
    cfg = _config(url)
    command.upgrade(cfg, "head")
    _insert_source(url, "vendor_rss")
    command.downgrade(cfg, "0001")
    engine = make_engine(url)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM events")).scalar_one() == 1
    engine.dispose()
