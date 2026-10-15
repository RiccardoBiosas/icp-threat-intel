"""Run a collector and store every fetch in the raw store before anything parses it."""

from collections.abc import Sequence

from icp_threat_intel.core.interfaces import Collector, RawStore
from icp_threat_intel.core.models import RawSnapshotRef


def collect_into(
    collector: Collector, store: RawStore, targets: Sequence[str]
) -> list[RawSnapshotRef]:
    """Save each ``RawFetch`` as soon as the collector yields it; return the refs in order."""
    return [store.save(fetch) for fetch in collector.collect(targets)]
