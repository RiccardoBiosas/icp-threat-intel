"""Seed IOC loader for ``data/seed_iocs.yaml`` (SPEC section 3 facts only)."""

from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from icp_threat_intel.core.enums import IocType, SourceType
from icp_threat_intel.db.models import CANISTER_ID_RE, Canister, Ioc, Source
from icp_threat_intel.raw_store.store import DEFAULT_RELIABILITY

DEFAULT_SEED_PATH = Path(__file__).resolve().parents[3] / "data" / "seed_iocs.yaml"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SeedSource(_Strict):
    name: str
    source_type: SourceType
    base_url: str


class SeedCampaign(_Strict):
    name: str
    start: date
    end: date
    actor: str | None
    summary: str
    publishers: list[str]
    source_urls: list[str]


class SeedIoc(_Strict):
    ioc_type: IocType
    value: str
    campaign: str | None
    source: str
    source_ref: str
    source_url: str
    threat_type: str | None = None
    malware: str | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    expires_at: datetime | None = None
    reporter: str | None = None
    tags: list[str] = Field(default_factory=list)
    notes: str | None = None


class SeedFile(_Strict):
    version: Literal[1]
    sources: list[SeedSource]
    campaigns: list[SeedCampaign]
    iocs: list[SeedIoc]

    @model_validator(mode="after")
    def _check_references(self) -> "SeedFile":
        sources = {s.name for s in self.sources}
        campaigns = {c.name for c in self.campaigns}
        for ioc in self.iocs:
            if ioc.source not in sources:
                raise ValueError(f"{ioc.value}: unknown source {ioc.source!r}")
            if ioc.campaign is not None and ioc.campaign not in campaigns:
                raise ValueError(f"{ioc.value}: unknown campaign {ioc.campaign!r}")
            if ioc.ioc_type is IocType.CANISTER_ID and not CANISTER_ID_RE.fullmatch(ioc.value):
                raise ValueError(f"not a canister id: {ioc.value!r}")
        return self

    @property
    def canister_ids(self) -> list[str]:
        return [i.value for i in self.iocs if i.ioc_type is IocType.CANISTER_ID]


@dataclass(frozen=True)
class SeedResult:
    sources_created: int
    iocs_created: int
    iocs_existing: int
    canisters_marked: int


def load_seed_file(path: Path = DEFAULT_SEED_PATH) -> SeedFile:
    with path.open(encoding="utf-8") as handle:
        return SeedFile.model_validate(yaml.safe_load(handle))


def describe(seed: SeedFile) -> list[str]:
    """Human-readable lines for ``db seed --dry-run``."""
    lines = [f"source {s.name} ({s.source_type}) {s.base_url or '-'}" for s in seed.sources]
    for c in seed.campaigns:
        actor = c.actor or "unattributed"
        lines.append(f"campaign {c.name} {c.start}..{c.end} actor={actor}")
    for i in seed.iocs:
        extra = f" campaign={i.campaign}" if i.campaign else ""
        lines.append(f"ioc {i.ioc_type} {i.value} source={i.source} ref={i.source_ref}{extra}")
    lines.extend(f"canister {cid} is_ioc=true" for cid in seed.canister_ids)
    lines.append(
        f"would load: {len(seed.sources)} sources, {len(seed.iocs)} iocs, "
        f"{len(seed.canister_ids)} IOC canisters"
    )
    return lines


def apply_seed(session: Session, seed: SeedFile) -> SeedResult:
    """Insert sources, IOCs and IOC canisters; re-running changes nothing."""
    by_name: dict[str, Source] = {}
    sources_created = 0
    for s in seed.sources:
        row = session.scalar(select(Source).where(Source.name == s.name))
        if row is None:
            row = Source(
                name=s.name,
                source_type=s.source_type,
                base_url=s.base_url,
                reliability=DEFAULT_RELIABILITY,
            )
            session.add(row)
            session.flush()
            sources_created += 1
        by_name[s.name] = row
    created = existing = 0
    for i in seed.iocs:
        found = session.scalar(
            select(Ioc).where(
                Ioc.ioc_type == i.ioc_type, Ioc.value == i.value, Ioc.source_ref == i.source_ref
            )
        )
        if found is not None:
            existing += 1
            continue
        fields = i.model_dump(exclude={"source"})
        session.add(Ioc(**fields, source_id=by_name[i.source].id))
        created += 1
    marked = 0
    for cid in seed.canister_ids:
        canister = session.get(Canister, cid)
        if canister is None:
            session.add(Canister(id=cid, is_ioc=True))
            marked += 1
        elif not canister.is_ioc:
            canister.is_ioc = True
            marked += 1
    session.flush()
    return SeedResult(sources_created, created, existing, marked)
