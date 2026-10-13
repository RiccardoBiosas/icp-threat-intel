"""Guardrail 4: per-host rate limits with backoff, a configurable census ceiling, and a
User-Agent that names the project and a contact address."""

import httpx
import pytest

from icp_threat_intel import __version__
from icp_threat_intel.core.config import Settings
from icp_threat_intel.core.http import SafeHttpClient
from icp_threat_intel.core.ratelimit import HostRateLimiter
from tests.guardrails._support import CONTACT, Recorder

URL_A = "https://ic-api.internetcomputer.org/api/v3/subnets"
URL_B = "https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/"


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _limiter(clock: FakeClock, rate: float = 2.0, burst: int = 2) -> HostRateLimiter:
    return HostRateLimiter(rate_per_second=rate, burst=burst, clock=clock, sleep=clock.sleep)


def _client(
    handler: Recorder, clock: FakeClock, limiter: HostRateLimiter | None = None, **kw: object
) -> SafeHttpClient:
    return SafeHttpClient(
        contact=CONTACT,
        transport=httpx.MockTransport(handler),
        limiter=limiter or _limiter(clock, rate=1000.0, burst=1000),
        sleep=clock.sleep,
        **kw,  # type: ignore[arg-type]
    )


def test_bucket_delays_once_burst_is_spent() -> None:
    clock = FakeClock()
    limiter = _limiter(clock, rate=2.0, burst=2)
    for _ in range(3):
        limiter.acquire("ic-api.internetcomputer.org")
    assert sum(clock.sleeps) == pytest.approx(0.5)


def test_limits_are_per_host() -> None:
    clock = FakeClock()
    limiter = _limiter(clock, rate=1.0, burst=1)
    limiter.acquire("a.icp0.io")
    limiter.acquire("b.icp0.io")
    assert clock.sleeps == []
    limiter.acquire("a.icp0.io")
    assert sum(clock.sleeps) == pytest.approx(1.0)


def test_client_applies_the_limiter() -> None:
    clock = FakeClock()
    recorder = Recorder(lambda _r: httpx.Response(200))
    client = _client(recorder, clock, limiter=_limiter(clock, rate=1.0, burst=1))
    for _ in range(3):
        client.get(URL_A)
    assert sum(clock.sleeps) == pytest.approx(2.0)


def test_429_honours_retry_after() -> None:
    clock = FakeClock()
    responses = iter([httpx.Response(429, headers={"Retry-After": "3"}), httpx.Response(200)])
    recorder = Recorder(lambda _r: next(responses))
    response = _client(recorder, clock).get(URL_A)
    assert response.status_code == 200
    assert 3.0 in clock.sleeps
    assert len(recorder.requests) == 2


def test_5xx_backs_off_exponentially_then_gives_up() -> None:
    clock = FakeClock()
    recorder = Recorder(lambda _r: httpx.Response(503))
    response = _client(recorder, clock, max_retries=3, backoff_base=1.0).get(URL_A)
    assert response.status_code == 503
    assert len(recorder.requests) == 4
    assert clock.sleeps == [1.0, 2.0, 4.0]


def test_excessive_retry_after_is_not_waited_out() -> None:
    clock = FakeClock()
    recorder = Recorder(lambda _r: httpx.Response(429, headers={"Retry-After": "86400"}))
    response = _client(recorder, clock, max_backoff=60.0).get(URL_A)
    assert response.status_code == 429
    assert len(recorder.requests) == 1
    assert all(s <= 60.0 for s in clock.sleeps)


def test_user_agent_names_project_and_contact() -> None:
    clock = FakeClock()
    recorder = Recorder(lambda _r: httpx.Response(200))
    _client(recorder, clock).get(URL_B)
    agent = recorder.requests[0].headers["User-Agent"]
    assert agent.startswith(f"icp-threat-intel/{__version__}")
    assert CONTACT in agent


@pytest.mark.parametrize("contact", ["", "   "])
def test_client_requires_a_contact(contact: str) -> None:
    with pytest.raises(ValueError, match="contact"):
        SafeHttpClient(contact=contact)


def test_census_ceiling_is_configurable() -> None:
    assert Settings.from_env({}).census_max_canisters > 0
    env = {"ICP_THREAT_INTEL_CENSUS_MAX_CANISTERS": "10"}
    assert Settings.from_env(env).census_max_canisters == 10


@pytest.mark.parametrize("bad", ["0", "-5", "lots"])
def test_census_ceiling_must_be_positive(bad: str) -> None:
    with pytest.raises(ValueError):
        Settings.from_env({"ICP_THREAT_INTEL_CENSUS_MAX_CANISTERS": bad})
