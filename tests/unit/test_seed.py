"""Seed IOCs: every SPEC section 3 fact is present, and nothing else."""

from collections.abc import Iterator
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session
from typer.testing import CliRunner

from icp_threat_intel.cli.app import app
from icp_threat_intel.core.enums import IocType, SourceType
from icp_threat_intel.db import session as db_session
from icp_threat_intel.db.base import Base
from icp_threat_intel.db.models import Canister, Ioc, Source
from icp_threat_intel.db.seed import DEFAULT_SEED_PATH, SeedFile, apply_seed, load_seed_file
from icp_threat_intel.db.session import make_engine

WORM = "tdtqy-oyaaa-aaaae-af2dq-cai"
SPRAWL = "cjn37-uyaaa-aaaac-qgnva-cai"
TF_URL = "https://threatfox.abuse.ch/ioc/1781006/"
EXPECTED_IOCS = {
    (IocType.CANISTER_ID, WORM),
    (IocType.CANISTER_ID, SPRAWL),
    (IocType.URL, f"https://{WORM}.raw.icp0.io/"),
    (IocType.PACKAGE_VERSION, "npm:@opengov/form-renderer@0.2.20"),
    (IocType.FILE_PATH, "/tmp/pglog"),
    (IocType.SYSTEMD_UNIT, "pgmon.service"),
}


@pytest.fixture(scope="module")
def seed() -> SeedFile:
    return load_seed_file()


@pytest.fixture
def session() -> Iterator[Session]:
    engine = make_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s
    engine.dispose()


def test_seed_file_is_in_the_repo() -> None:
    assert Path(__file__).resolve().parents[2] / "data" / "seed_iocs.yaml" == DEFAULT_SEED_PATH


def test_exactly_the_spec_iocs(seed: SeedFile) -> None:
    assert {(i.ioc_type, i.value) for i in seed.iocs} == EXPECTED_IOCS
    assert len(seed.iocs) == len(EXPECTED_IOCS)


def test_threatfox_1781006_fields(seed: SeedFile) -> None:
    (tf,) = [i for i in seed.iocs if i.ioc_type is IocType.URL]
    assert tf.source_ref == "threatfox:1781006"
    assert tf.source_url == TF_URL
    assert tf.threat_type == "payload_delivery"
    assert tf.malware == "Unknown malware"
    assert tf.confidence == 90
    assert tf.first_seen == datetime(2026, 4, 4, 11, 52, 12, tzinfo=UTC)
    assert tf.last_seen is None
    assert tf.expires_at == datetime(2026, 10, 5, 1, 15, 1, tzinfo=UTC)
    assert tf.reporter == "tipo_deincognito"
    assert set(tf.tags) == {"ICP-C2", "npm-worm", "supply-chain", "systemd-dropper"}
    assert tf.notes is not None
    for fact in ("@opengov/form-renderer 0.2.20", "/tmp/pglog", "pgmon.service", "_authToken"):
        assert fact in tf.notes


def test_campaigns_and_dates(seed: SeedFile) -> None:
    campaigns = {c.name: c for c in seed.campaigns}
    assert set(campaigns) == {"CanisterWorm", "CanisterSprawl"}
    worm, sprawl = campaigns["CanisterWorm"], campaigns["CanisterSprawl"]
    assert (worm.start, worm.end, worm.actor) == (date(2026, 3, 19), date(2026, 3, 22), "TeamPCP")
    assert (sprawl.start, sprawl.end) == (date(2026, 4, 21), date(2026, 4, 23))
    assert sprawl.actor is None
    assert set(worm.publishers) == {"Cloud Security Alliance", "Aikido", "JFrog", "Socket"}
    for fact in ("50 minutes", "update_link", "141 artifacts", "66+ packages", "26 hours"):
        assert fact in worm.summary
    for fact in ("Namastex.ai", ".pth", SPRAWL, "exfiltration"):
        assert fact in sprawl.summary
    canister_campaign = {
        i.value: i.campaign for i in seed.iocs if i.ioc_type is IocType.CANISTER_ID
    }
    assert canister_campaign == {WORM: "CanisterWorm", SPRAWL: "CanisterSprawl"}


# Write-up URLs from docs/sources/vendor-rss.md, each fetched (HTTP 200) on 2026-10-15.
WORM_WRITEUPS = {
    "https://www.aikido.dev/blog/teampcp-deploys-worm-npm-trivy-compromise",
    "https://socket.dev/blog/canisterworm-npm-publisher-compromise-deploys-backdoor-across-29-packages",
    "https://research.jfrog.com/post/canister-worm/",
    "https://labs.cloudsecurityalliance.org/research/csa-research-note-canisterworm-blockchain-c2-supply-chain-20/",
}
SPRAWL_WRITEUPS = {
    "https://socket.dev/blog/namastex-npm-packages-compromised-canisterworm",
    "https://labs.cloudsecurityalliance.org/research/csa-research-note-npm-canistersprawl-supply-chain-worm-20260/",
}


def test_no_invented_urls_or_sources(seed: SeedFile) -> None:
    raw = yaml.safe_load(DEFAULT_SEED_PATH.read_text(encoding="utf-8"))
    text = yaml.safe_dump(raw, width=1000)
    urls = {u for u in text.split() if u.startswith("http")}
    allowed = {TF_URL, "https://threatfox.abuse.ch", f"https://{WORM}.raw.icp0.io/"}
    assert urls <= allowed | WORM_WRITEUPS | SPRAWL_WRITEUPS
    assert {s.source_type for s in seed.sources} == {SourceType.THREATFOX, SourceType.VENDOR_RSS}
    by_name = {c.name: set(c.source_urls) for c in seed.campaigns}
    assert by_name == {"CanisterWorm": WORM_WRITEUPS, "CanisterSprawl": SPRAWL_WRITEUPS}
    assert "H6" not in text
    assert "September" not in text


def test_campaign_canister_iocs_cite_a_writeup(seed: SeedFile) -> None:
    urls = {i.value: i.source_url for i in seed.iocs if i.ioc_type is IocType.CANISTER_ID}
    assert urls[WORM] in WORM_WRITEUPS
    assert urls[SPRAWL] in SPRAWL_WRITEUPS


def test_iocs_keep_their_publisher_source_type(seed: SeedFile) -> None:
    types = {s.name: s.source_type for s in seed.sources}
    for ioc in seed.iocs:
        expected = (
            SourceType.THREATFOX
            if ioc.source_ref.startswith("threatfox:")
            else SourceType.VENDOR_RSS
        )
        assert types[ioc.source] is expected


def test_apply_seed_loads_and_is_idempotent(session: Session, seed: SeedFile) -> None:
    first = apply_seed(session, seed)
    assert (first.sources_created, first.iocs_created, first.canisters_marked) == (2, 6, 2)
    second = apply_seed(session, seed)
    assert (second.sources_created, second.iocs_created, second.iocs_existing) == (0, 0, 6)
    assert len(session.scalars(select(Ioc)).all()) == 6
    assert len(session.scalars(select(Source)).all()) == 2
    canisters = session.scalars(select(Canister)).all()
    assert {c.id for c in canisters} == {WORM, SPRAWL}
    assert all(c.is_ioc for c in canisters)


def test_dry_run_prints_everything_without_a_database(monkeypatch: pytest.MonkeyPatch) -> None:
    def _no_db(*_a: object, **_k: object) -> None:
        raise AssertionError("dry run touched the database")

    monkeypatch.setattr(db_session, "make_engine", _no_db)
    result = CliRunner().invoke(app, ["db", "seed", "--dry-run"])
    assert result.exit_code == 0, result.output
    for _, value in EXPECTED_IOCS:
        assert value in result.output
    for needle in ("1781006", "CanisterWorm", "2026-03-19", "CanisterSprawl", "2026-04-21"):
        assert needle in result.output
    assert "no database was used" in result.output


def test_seed_command_writes_to_the_configured_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = f"sqlite:///{tmp_path / 'seed.db'}"
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    monkeypatch.setenv("ICP_THREAT_INTEL_DATABASE_URL", url)
    runner = CliRunner()
    assert runner.invoke(app, ["db", "seed"]).exit_code == 0
    rerun = runner.invoke(app, ["db", "seed"])
    assert rerun.exit_code == 0
    assert "0 new iocs (6 already present)" in rerun.output
    with Session(engine) as s:
        assert len(s.scalars(select(Ioc)).all()) == 6
    engine.dispose()
