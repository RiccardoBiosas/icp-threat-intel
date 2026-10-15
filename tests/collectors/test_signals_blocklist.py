"""Signals blocklists (PhishDestroy): bulk download, ICP gateway hosts -> canister ids."""

from datetime import UTC, datetime

import httpx
import pytest

from icp_threat_intel.collectors.signals_blocklist import (
    DEFAULT_BLOCKLISTS,
    MAX_BLOCKLIST_BYTES,
    PHISHDESTROY,
    BlocklistFeed,
    SignalsBlocklistCollector,
    blocklist_http,
    canister_from_host,
    extract_domains,
)
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.http import ALLOWLIST, MAX_BODY_BYTES, HostNotAllowed, SafeHttpClient
from icp_threat_intel.core.interfaces import Collector
from icp_threat_intel.core.ratelimit import HostRateLimiter
from tests.collectors import _blocklist_fixtures as fx

T0 = datetime(2026, 10, 16, 6, 0, tzinfo=UTC)


def _limiter() -> HostRateLimiter:
    return HostRateLimiter(rate_per_second=1000.0, burst=1000, sleep=lambda _s: None)


def _collector(body: bytes = fx.LIST, status: int = 200) -> SignalsBlocklistCollector:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, content=body, headers={"content-type": "text/plain"})

    http = blocklist_http(
        "test@example.invalid",
        transport=httpx.MockTransport(handler),
        limiter=_limiter(),
        sleep=lambda _s: None,
    )
    return SignalsBlocklistCollector(http, clock=lambda: T0, synthetic=True)


def test_phishdestroy_is_the_default_blocklist() -> None:
    assert DEFAULT_BLOCKLISTS == (PHISHDESTROY,)
    assert PHISHDESTROY.name == "phishdestroy"
    assert PHISHDESTROY.url == "https://gitlab.com/phishdestroy/destroylist/-/raw/main/list.json"
    assert PHISHDESTROY.host == "gitlab.com"


def test_gitlab_is_not_in_the_global_allowlist() -> None:
    assert not any("gitlab" in host for host in ALLOWLIST)


def test_only_bulk_downloads_no_per_domain_api() -> None:
    """Per-domain lookups would reveal what is tracked; only the full list is fetched."""
    hosts = {f.host for f in DEFAULT_BLOCKLISTS}
    assert "api.destroy.tools" not in hosts and "phishdestroy.io" not in hosts


def test_feed_validation() -> None:
    with pytest.raises(ValueError):
        BlocklistFeed("bad", "http://gitlab.com/x.json")
    with pytest.raises(ValueError):
        BlocklistFeed("Bad Name", "https://gitlab.com/x.json")


def test_client_has_a_larger_cap_than_gateway_bodies() -> None:
    assert MAX_BLOCKLIST_BYTES > 5_730_568 * 2  # list.json was 5.7 MB on 2026-10-16
    assert MAX_BODY_BYTES == 1024 * 1024  # the shared default is unchanged


def test_plain_client_refuses_gitlab() -> None:
    plain = SafeHttpClient(
        "test@example.invalid",
        transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"[]")),
        limiter=_limiter(),
        sleep=lambda _s: None,
    )
    with pytest.raises(HostNotAllowed):
        list(SignalsBlocklistCollector(plain, clock=lambda: T0).collect([]))


def test_collects_the_list() -> None:
    collector = _collector()
    assert isinstance(collector, Collector)
    assert collector.source_type is SourceType.SIGNALS_FEED
    (fetch,) = list(collector.collect([]))
    assert fetch.source_name == "phishdestroy" and fetch.url == PHISHDESTROY.url
    assert fetch.http_status == 200 and fetch.body == fx.LIST and fetch.synthetic
    assert fetch.request_meta == {
        "feed": "phishdestroy",
        "platform": "blocklist",
        "request": "blocklist",
        "format": "json_domains",
        "redirects": [],
    }


def test_unknown_blocklist_refused() -> None:
    with pytest.raises(ValueError, match="unknown blocklist"):
        list(_collector().collect(["nope"]))


def test_extract_domains_is_defensive() -> None:
    assert extract_domains(b"nope") is None
    assert extract_domains(b'{"a": 1}') is None
    assert extract_domains(b'["A.example", 3, "", "b.example "]') == ["a.example", "b.example"]


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        (f"{fx.CAN_A}.icp0.io", fx.CAN_A),
        (f"{fx.CAN_A}.raw.icp0.io", fx.CAN_A),
        (f"{fx.CAN_B}.ic0.app", fx.CAN_B),
        (f"{fx.CAN_B}.raw.ic0.app", fx.CAN_B),
        (fx.CAN_C.replace("-", "") + ".icp0.io", fx.CAN_C),  # hyphens restored
        ("zzzzzzzzzzzzzzzzzzzzcai.icp0.io", None),  # bad checksum
        ("custom-name.icp0.io", None),
        ("icp0.io", None),
        ("icp0.io.evil.example", None),
        (f"{fx.CAN_A}.icp0.io.evil.example", None),
        ("a.b." + f"{fx.CAN_A}.icp0.io", None),  # only <id>[.raw].<gateway>
    ],
)
def test_canister_from_host(host: str, expected: str | None) -> None:
    assert canister_from_host(host) == expected
