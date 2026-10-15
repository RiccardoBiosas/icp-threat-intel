"""Re-record the raw-gateway cassettes (``make record`` only, SPEC D6).

Marked ``live``; needs ``ICP_THREAT_INTEL_RECORD=1`` and ``ICP_THREAT_INTEL_CONTACT``.
Only the two seed canisters, only the query pre-check and raw-domain GETs.
"""

from datetime import UTC, datetime

import pytest

from icp_threat_intel.collectors.raw_gateway import DOMAINS, RawGatewayCollector
from icp_threat_intel.core.config import Settings
from icp_threat_intel.core.http import SafeHttpClient
from icp_threat_intel.core.ic_client import IcClient
from tests.collectors import _cassettes as cas
from tests.collectors import _gateway_cassettes as gw

LIVE_NOTE = "Recorded live by make record (anonymous http_request query and raw-domain GETs)."


@pytest.mark.live
def test_record_raw_gateway_cassettes() -> None:
    settings = Settings.from_env()
    if not settings.record or not settings.contact:
        pytest.fail("set ICP_THREAT_INTEL_RECORD=1 and ICP_THREAT_INTEL_CONTACT to record")
    transport = cas.RecordingTransport()
    with SafeHttpClient(settings.contact, transport=transport) as http:
        collector = RawGatewayCollector(http, IcClient(http))
        fetches = list(collector.collect(list(cas.SEED_CANISTERS)))
    assert fetches, "the collector produced nothing"
    now = datetime.now(UTC)
    for request, status, headers, body in transport.exchanges:
        if request.url.host == "icp-api.io":
            canister_id, kind = request.url.path.split("/")[4], gw.PRECHECK
        else:
            canister_id, _, kind = request.url.host.partition(".")
            if kind not in DOMAINS:
                continue  # a followed redirect hop; the first response is kept
        gw.write(
            canister_id,
            kind,
            url=str(request.url),
            method=request.method,
            status_code=status,
            headers=headers,
            body=body,
            synthetic=False,
            recorded_at=now,
            note=LIVE_NOTE,
        )
