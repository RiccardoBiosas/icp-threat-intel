"""Source reliability weights (0-100) and the weighted-confidence formula.

A source's weight is stored on its ``sources`` row when the row is first registered and is
copied onto every event at ingest (``enrichment/trust.py``). Operators may change a row's
``reliability``; later ingests use the new value, already stored events keep theirs.

Defaults, from most to least direct evidence (rationale in OPEN_QUESTIONS.md, T10):

* IC protocol state (read_state, NNS, ledger): 85-90. read_state stays at 85 until BLS
  certificate verification lands (``unverified:no_bls``).
* Registry metadata (npm, PyPI) and GitHub advisories: 80.
* Dashboard API, an indexer over IC state with undocumented fields: 75.
* Raw gateway bodies, uncertified and canister-controlled: 70.
* Third-party IOC feeds (ThreatFox, URLhaus): 65.
* Vendor blog feeds, prose reporting: 60.
"""

import math
from collections.abc import Iterable, Mapping

from icp_threat_intel.core.enums import SourceType

DEFAULT_RELIABILITY: Mapping[SourceType, int] = {
    SourceType.IC_READ_STATE: 85,
    SourceType.NNS: 90,
    SourceType.ICP_LEDGER: 90,
    SourceType.NPM: 80,
    SourceType.PYPI: 80,
    SourceType.GITHUB_ADVISORIES: 80,
    SourceType.DASHBOARD_API: 75,
    SourceType.RAW_GATEWAY: 70,
    SourceType.THREATFOX: 65,
    SourceType.URLHAUS: 65,
    SourceType.VENDOR_RSS: 60,
}


def default_reliability(source_type: SourceType) -> int:
    return DEFAULT_RELIABILITY[source_type]


def weighted_confidence(evidence: Iterable[tuple[SourceType, int]]) -> float:
    """``1 - prod(1 - w/100)`` over distinct source types (each at its highest weight).

    Several pieces of evidence from one source type count once, so a single source cannot
    raise confidence by repeating itself.
    """
    best: dict[SourceType, int] = {}
    for source_type, weight in evidence:
        if not 0 <= weight <= 100:
            raise ValueError(f"weight {weight} outside 0-100")
        best[source_type] = max(weight, best.get(source_type, 0))
    remaining = math.prod(1 - w / 100 for w in best.values())
    return round(1 - remaining, 6)
