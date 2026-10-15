"""Re-record the Dashboard API cassettes (``make record`` only, SPEC D6).

Marked ``live``; needs ``ICP_THREAT_INTEL_RECORD=1`` and ``ICP_THREAT_INTEL_CONTACT``.
Only the two seed canisters and their subnets, read-only GETs.
"""

from datetime import UTC, datetime

import pytest

from icp_threat_intel.collectors.dashboard import DashboardCollector
from icp_threat_intel.core.config import Settings
from icp_threat_intel.core.http import SafeHttpClient
from tests.collectors import _cassettes as cas
from tests.collectors import _dashboard_cassettes as dash

LIVE_NOTE = "Recorded live by make record against ic-api.internetcomputer.org."


@pytest.mark.live
def test_record_dashboard_cassettes() -> None:
    settings = Settings.from_env()
    if not settings.record or not settings.contact:
        pytest.fail("set ICP_THREAT_INTEL_RECORD=1 and ICP_THREAT_INTEL_CONTACT to record")
    with SafeHttpClient(settings.contact) as http:
        fetches = list(DashboardCollector(http).collect(list(cas.SEED_CANISTERS)))
    assert fetches, "the collector produced nothing"
    now = datetime.now(UTC)
    for fetch in fetches:
        meta = fetch.request_meta
        dash.write(
            meta["canister_id"],
            meta["request"],
            url=fetch.url,
            status_code=fetch.http_status or 0,
            headers={"content-type": fetch.content_type or ""},
            body=fetch.body,
            synthetic=False,
            recorded_at=now,
            note=LIVE_NOTE,
        )
