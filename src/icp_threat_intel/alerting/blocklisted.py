"""Digest summary of ICP canisters named by community blocklists (``signal.canister_listed``).

Low-authority context only: blocklist entries are community-reported and never count as
verification evidence. A canister is listed when it was seen on a list since the window
start; ``first_listed`` covers the whole history. IOC canisters come first.

Listed hosts are phishing or scam sites: the digest shows them as code, never as links.
"""

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from icp_threat_intel.alerting.parses import newest_parse_only
from icp_threat_intel.db.models import EventRow


@dataclass(frozen=True)
class BlocklistedCanister:
    canister_id: str
    feeds: tuple[str, ...]
    hosts: tuple[str, ...]
    is_ioc: bool
    first_listed: datetime

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["first_listed"] = self.first_listed.isoformat()
        data["feeds"], data["hosts"] = list(self.feeds), list(self.hosts)
        return data


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def blocklisted_canisters(
    session: Session, since: datetime, *, ioc_only: bool = False
) -> list[BlocklistedCanister]:
    """One row per canister listed since ``since``; IOC canisters first, then by id."""
    rows = session.scalars(
        select(EventRow)
        .where(EventRow.kind == "signal.canister_listed")
        .order_by(EventRow.observed_at, EventRow.id)
    ).all()
    rows = newest_parse_only(session, rows)
    grouped: dict[str, list[EventRow]] = defaultdict(list)
    for row in rows:
        grouped[str(row.canister_id)].append(row)
    result = []
    for canister_id, events in grouped.items():
        if max(_aware(e.observed_at) for e in events) < since:
            continue
        is_ioc = any(e.is_ioc for e in events)
        if ioc_only and not is_ioc:
            continue
        hosts = {h for e in events for h in e.payload.get("hosts") or [] if isinstance(h, str)}
        result.append(
            BlocklistedCanister(
                canister_id=canister_id,
                feeds=tuple(sorted({str(e.payload.get("feed")) for e in events})),
                hosts=tuple(sorted(hosts)),
                is_ioc=is_ioc,
                first_listed=min(_aware(e.observed_at) for e in events),
            )
        )
    return sorted(result, key=lambda r: (not r.is_ioc, r.canister_id))


def blocklisted_section(rows: Sequence[BlocklistedCanister]) -> list[str]:
    lines = ["", "## Blocklisted ICP canisters (low authority)", "",
             "ICP canisters named by community phishing and scam blocklists. Context only: "
             "they never count as verification evidence. The hosts are phishing or scam "
             "sites: never visit them.", "",
             "| Canister | IOC | Lists | Hosts | First listed |",
             "|---|---|---|---|---|"]  # fmt: skip
    for r in rows:
        hosts = ", ".join(f"`{h}`" for h in r.hosts if "`" not in h and "|" not in h)
        lines.append(
            f"| `{r.canister_id}` | {'**yes**' if r.is_ioc else 'no'} | {', '.join(r.feeds)} | "
            f"{hosts or '-'} | {r.first_listed.astimezone(UTC):%Y-%m-%dT%H:%MZ} |"
        )
    return lines
