"""APScheduler cadences (SPEC section 6) and the scheduler factory.

Defaults: IOC canister state hourly, raw gateway for IOC canisters every 6 h, registries,
ledger and proposals daily, full census weekly, digest daily. Jobs whose collectors do not
exist yet are scheduled as no-ops that log ``job_not_available``, so the schedule is
visible and complete from the start.
"""

from collections.abc import Callable, Mapping
from datetime import timedelta

import structlog
from apscheduler.schedulers.base import BaseScheduler
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.interval import IntervalTrigger

log = structlog.get_logger(__name__)

DEFAULT_CADENCES: Mapping[str, timedelta] = {
    "ioc_canister_state": timedelta(hours=1),
    "raw_gateway": timedelta(hours=6),
    "registries": timedelta(days=1),
    "ledger": timedelta(days=1),
    "proposals": timedelta(days=1),
    "census": timedelta(weeks=1),
    "digest": timedelta(days=1),
}


def _not_available(name: str) -> Callable[[], None]:
    def job() -> None:
        log.info("job_not_available", job=name)

    return job


def build_scheduler(
    runners: Mapping[str, Callable[[], object]],
    *,
    cadences: Mapping[str, timedelta] | None = None,
    scheduler: BaseScheduler | None = None,
) -> BaseScheduler:
    """Add one interval job per cadence; unknown runner names are refused."""
    unknown = set(runners) - set(DEFAULT_CADENCES)
    if unknown:
        raise ValueError(f"no cadence for jobs {sorted(unknown)}")
    merged = {**DEFAULT_CADENCES, **(cadences or {})}
    sched = scheduler or BlockingScheduler(timezone="UTC")
    for name, every in sorted(merged.items()):
        if every <= timedelta(0):
            raise ValueError(f"cadence for {name} must be positive")
        sched.add_job(
            runners.get(name) or _not_available(name),
            IntervalTrigger(seconds=int(every.total_seconds()), timezone="UTC"),
            id=name,
            name=name,
            max_instances=1,
            coalesce=True,
            replace_existing=True,
        )
    return sched
