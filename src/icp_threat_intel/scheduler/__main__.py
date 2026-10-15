"""Entry point for ``make run``: the APScheduler loop with the default cadences.

Only the digest job runs real work so far; the collector jobs are scheduled as no-ops that
log ``job_not_available`` until they are wired to their collectors.
"""

import contextlib
import sys
from pathlib import Path

from icp_threat_intel.scheduler.jobs import build_scheduler


def _digest() -> None:
    from icp_threat_intel.cli.publishing import digest

    digest(out_dir=Path("digests"), hours=24)


def main() -> int:
    scheduler = build_scheduler({"digest": _digest})
    with contextlib.suppress(KeyboardInterrupt, SystemExit):
        scheduler.start()
    return 0


if __name__ == "__main__":
    sys.exit(main())
