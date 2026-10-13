"""Guardrail 3: the shared HTTP client refuses any host outside ALLOWLIST and logs it."""

import httpx
import pytest
from structlog.testing import capture_logs

from icp_threat_intel.core.http import ALLOWLIST, HostNotAllowed, is_allowed
from tests.guardrails._support import imported_modules, make_client, source_files


def _ok(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, text="ok")


@pytest.mark.parametrize(
    "host",
    [
        "icp-api.io",
        "ic-api.internetcomputer.org",
        "tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io",
        "cjn37-uyaaa-aaaac-qgnva-cai.raw.ic0.app",
        "tdtqy-oyaaa-aaaae-af2dq-cai.icp0.io",
        "TDTQY-OYAAA-AAAAE-AF2DQ-CAI.RAW.ICP0.IO.",
    ],
)
def test_ic_hosts_are_allowed(host: str) -> None:
    assert is_allowed(host)


@pytest.mark.parametrize(
    "host",
    [
        "example.com",
        "evil.example",
        "icp0.io.evil.example",
        "evilicp0.io",
        "raw.icp0.io-evil.example",
        "127.0.0.1",
        "169.254.169.254",
        "[::1]",
        "localhost",
        "",
    ],
)
def test_other_hosts_are_refused(host: str) -> None:
    assert not is_allowed(host)


def test_allowlist_is_immutable() -> None:
    assert isinstance(ALLOWLIST, frozenset)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/",
        "https://icp0.io@evil.example/",
        "https://169.254.169.254/latest/meta-data/",
        "http://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/",
        "ftp://icp-api.io/",
    ],
)
def test_client_refuses_before_any_request_and_logs(url: str) -> None:
    client, recorder = make_client(_ok)
    with capture_logs() as logs, pytest.raises(HostNotAllowed):
        client.get(url)
    assert recorder.requests == []
    assert any(entry["event"] == "host_refused" for entry in logs)


def test_client_refuses_post_off_allowlist() -> None:
    client, recorder = make_client(_ok)
    with pytest.raises(HostNotAllowed):
        client.post("https://example.com/upload", content=b"x")
    assert recorder.requests == []


def test_client_allows_allowlisted_host() -> None:
    client, recorder = make_client(_ok)
    response = client.get("https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/")
    assert response.status_code == 200
    assert recorder.hosts == ["tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io"]


def test_redirect_off_allowlist_is_refused() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://evil.example/payload"})

    client, recorder = make_client(handler)
    with capture_logs() as logs, pytest.raises(HostNotAllowed):
        client.get("https://ic-api.internetcomputer.org/api/v3/canisters")
    assert "evil.example" not in recorder.hosts
    assert any(entry["event"] == "host_refused" for entry in logs)


def test_only_the_shared_client_imports_httpx() -> None:
    offenders = [
        str(path)
        for path in source_files()
        if path.name != "http.py"
        and {"httpx", "requests", "urllib.request", "aiohttp"} & imported_modules(path)
    ]
    assert offenders == []
