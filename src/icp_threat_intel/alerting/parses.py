"""Keep only events from the newest parse of each raw snapshot.

Re-parsing a snapshot with a newer parser adds events beside the old ones (the dedup key
includes the parser). When the newer parser is stricter, an item it no longer matches would
otherwise keep showing through the older event. For each raw snapshot, the newest parse is the
parser of its most recently stored event (any kind, so a parse that matched nothing still
counts through its ``*_polled`` event); events from other parsers of that snapshot are dropped.
Events without a raw snapshot are kept.
"""

from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from icp_threat_intel.db.models import EventRow


def newest_parse_only(session: Session, rows: Sequence[EventRow]) -> list[EventRow]:
    snapshot_ids = {r.raw_snapshot_id for r in rows if r.raw_snapshot_id is not None}
    if not snapshot_ids:
        return list(rows)
    latest = session.execute(
        select(EventRow.raw_snapshot_id, EventRow.parser, func.max(EventRow.id))
        .where(EventRow.raw_snapshot_id.in_(snapshot_ids))
        .group_by(EventRow.raw_snapshot_id, EventRow.parser)
    ).all()
    newest: dict[int, tuple[int, str]] = {}
    for snapshot_id, parser, max_id in latest:
        if snapshot_id is None:  # excluded by the query; narrows the type
            continue
        if snapshot_id not in newest or max_id > newest[snapshot_id][0]:
            newest[snapshot_id] = (max_id, parser)
    return [
        r for r in rows if r.raw_snapshot_id is None or newest[r.raw_snapshot_id][1] == r.parser
    ]
