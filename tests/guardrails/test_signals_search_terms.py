"""Forum searches never reveal what is tracked.

Discourse logs every search server-side. The signals search may therefore only send the
curated generic threat terms in ``SEARCH_TERMS``: never a canister id, principal, hash,
URL, domain, path, package name or any value from the ``iocs`` table.
"""

import httpx
import pytest

from icp_threat_intel.collectors.signals_feed import DFINITY_FORUM, signals_http
from icp_threat_intel.collectors.signals_search import SignalsSearchCollector, search_url
from icp_threat_intel.core.http import SafeHttpClient
from icp_threat_intel.core.ratelimit import HostRateLimiter
from icp_threat_intel.parsers.signals_keywords import (
    SEARCH_TERMS,
    UnsafeSearchTerm,
    check_search_term,
)

UNSAFE = [
    "tdtqy-oyaaa-aaaae-af2dq-cai",  # canister id
    "aaaaa-aa",  # management canister principal
    "abcde-fghij-klmno-pqrst-uvwxy-zabcd-efghi-jklmn-opqrs-tuvwx-yza",  # principal shape
    "90" * 32,  # 64-hex hash (shape only)
    "deadbeefcafe0123",  # 16 hex chars
    "https://example.org",
    "evil.example",
    "/tmp/pglog",
    "@opengov/form-renderer",
    "pgmon.service",
    "",
    "x" * 61,
]


def test_curated_terms_are_safe() -> None:
    assert SEARCH_TERMS
    for term in SEARCH_TERMS:
        assert check_search_term(term) == term


@pytest.mark.parametrize("term", UNSAFE)
def test_identifiers_are_refused(term: str) -> None:
    with pytest.raises(UnsafeSearchTerm):
        check_search_term(term)


def test_terms_containing_an_ioc_value_are_refused() -> None:
    with pytest.raises(UnsafeSearchTerm):
        check_search_term("pgserve malware", ioc_values=["npm:pgserve@1.1.11", "pgserve"])


def test_short_ioc_values_do_not_block_generic_words() -> None:
    assert check_search_term("malware", ioc_values=["mal"]) == "malware"


def _http() -> SafeHttpClient:
    limiter = HostRateLimiter(rate_per_second=1000.0, burst=1000, sleep=lambda _s: None)
    return signals_http(
        "test@example.invalid",
        transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"{}")),
        limiter=limiter,
        sleep=lambda _s: None,
    )


def test_collector_refuses_terms_outside_the_curated_list() -> None:
    with pytest.raises(UnsafeSearchTerm, match="not a curated"):
        SignalsSearchCollector(_http(), terms=["cjn37 exfiltration"])


def test_collector_refuses_curated_terms_that_match_an_ioc() -> None:
    with pytest.raises(UnsafeSearchTerm):
        SignalsSearchCollector(_http(), terms=[SEARCH_TERMS[0]], ioc_values=[SEARCH_TERMS[0]])


def test_search_url_refuses_unsafe_terms() -> None:
    with pytest.raises(UnsafeSearchTerm):
        search_url(DFINITY_FORUM, "tdtqy-oyaaa-aaaae-af2dq-cai")
