"""Re-record the read_state cassettes against icp-api.io (``make record`` only, SPEC D6).

Marked ``live``, so ``make test`` deselects it. It reads only the two seed canisters,
through the query-only client and the allowlisted HTTP client, and needs
``ICP_THREAT_INTEL_RECORD=1`` plus ``ICP_THREAT_INTEL_CONTACT`` for the User-Agent.
"""

from datetime import UTC, datetime

import pytest

from icp_threat_intel.collectors.read_state import ReadStateCollector
from icp_threat_intel.core.config import Settings
from icp_threat_intel.core.http import SafeHttpClient
from icp_threat_intel.core.ic_client import IcClient
from tests.collectors import _cassettes as cas

LIVE_NOTE = "Recorded live by make record against icp-api.io (anonymous read_state)."


@pytest.mark.live
def test_record_read_state_cassettes() -> None:
    settings = Settings.from_env()
    if not settings.record or not settings.contact:
        pytest.fail("set ICP_THREAT_INTEL_RECORD=1 and ICP_THREAT_INTEL_CONTACT to record")
    transport = cas.RecordingTransport()
    with SafeHttpClient(settings.contact, transport=transport) as http:
        fetches = list(ReadStateCollector(IcClient(http)).collect(list(cas.SEED_CANISTERS)))
    assert len(fetches) == len(transport.exchanges) == 4
    now = datetime.now(UTC)
    for fetch, (_request, status, headers, body) in zip(fetches, transport.exchanges, strict=True):
        meta = fetch.request_meta
        cas.write(
            meta["canister_id"],
            meta["request"],
            status_code=status,
            body=body,
            synthetic=False,
            recorded_at=now,
            note=LIVE_NOTE,
            headers=headers,
        )
