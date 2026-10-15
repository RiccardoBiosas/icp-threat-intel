"""Re-apply IOC membership to stored events (``icp-threat-intel enrich``).

Ingest marks events against the IOC set known at parse time. When IOCs are added or
removed later (a re-seed, a new feed), this brings every stored event's ``is_ioc`` flag in
line with the current set. Trust weights are left alone: they are applied at ingest.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from icp_threat_intel.db.models import EventRow
from icp_threat_intel.parsers.ingest import ioc_canisters


def refresh_ioc_flags(session: Session) -> tuple[int, int]:
    """Set ``is_ioc`` from the current IOC set; returns (newly marked, newly unmarked)."""
    iocs = ioc_canisters(session)
    marked = unmarked = 0
    for row in session.scalars(select(EventRow).where(EventRow.canister_id.is_not(None))):
        should = row.canister_id in iocs
        if should and not row.is_ioc:
            row.is_ioc, marked = True, marked + 1
        elif not should and row.is_ioc:
            row.is_ioc, unmarked = False, unmarked + 1
    session.flush()
    return marked, unmarked
