"""The shared HTTP client: the only module that talks HTTP (SPEC guardrails 2, 3, 4).

It refuses hosts outside ``ALLOWLIST`` and logs the refusal, allows https only, re-checks
every redirect target, applies per-host rate limits with backoff on 429 and 5xx, sends a
User-Agent naming the project and a contact address, caps bodies and times out after 10 s.
"""

import ipaddress
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from email.utils import parsedate_to_datetime

import httpx
import structlog

from icp_threat_intel import __version__
from icp_threat_intel.core.bodies import is_ic_domain
from icp_threat_intel.core.ratelimit import HostRateLimiter

log = structlog.get_logger(__name__)

# Exact hosts, plus "*.<suffix>" entries that match any subdomain (never the bare suffix).
ALLOWLIST: frozenset[str] = frozenset(
    {
        "icp-api.io",
        "ic-api.internetcomputer.org",
        "*.icp0.io",
        "*.ic0.app",
    }
)
MAX_BODY_BYTES = 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 10.0
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class HostNotAllowed(Exception):
    """The URL's scheme or host is outside the allowlist; ``target`` is the refused URL."""

    def __init__(self, message: str, *, target: str = "") -> None:
        super().__init__(message)
        self.target = target


class RedirectRefused(HostNotAllowed):
    """A redirect pointed outside the allowlist (or off IC domains for gateway fetches)."""


class TooManyRedirects(Exception):
    """The redirect chain exceeded ``max_redirects``."""


class FetchTimeout(Exception):
    """The request did not complete within the client timeout."""


@dataclass(frozen=True)
class FetchResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    body: bytes
    truncated: bool
    redirects: tuple[str, ...] = ()


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _matches(host: str, patterns: Iterable[str]) -> bool:
    for pattern in patterns:
        if pattern.startswith("*."):
            if host.endswith(pattern[1:]):
                return True
        elif host == pattern:
            return True
    return False


def is_allowed(host: str, extra_hosts: Iterable[str] = ()) -> bool:
    """True when ``host`` matches ``ALLOWLIST`` (or an exact ``extra_hosts`` entry)."""
    host = host.lower().rstrip(".")
    if not host or _is_ip_literal(host):
        return False
    return _matches(host, ALLOWLIST) or host in {h.lower() for h in extra_hosts}


class SafeHttpClient:
    """Allowlisted, rate-limited HTTP client shared by every collector."""

    def __init__(
        self,
        contact: str,
        *,
        transport: httpx.BaseTransport | None = None,
        limiter: HostRateLimiter | None = None,
        sleep: Callable[[float], None] = time.sleep,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_bytes: int = MAX_BODY_BYTES,
        max_redirects: int = 5,
        max_retries: int = 3,
        backoff_base: float = 1.0,
        max_backoff: float = 60.0,
        extra_hosts: Iterable[str] = (),
    ) -> None:
        if not contact or not contact.strip():
            raise ValueError("a contact address is required for the User-Agent")
        extra = tuple(extra_hosts)
        if any(_is_ip_literal(h) or "*" in h for h in extra):
            raise ValueError("extra_hosts must be exact host names")
        self.user_agent = f"icp-threat-intel/{__version__} (+{contact.strip()})"
        self.timeout_seconds = timeout_seconds
        self._extra_hosts = extra
        self._limiter = limiter or HostRateLimiter()
        self._sleep = sleep
        self._max_bytes = max_bytes
        self._max_redirects = max_redirects
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._max_backoff = max_backoff
        self._client = httpx.Client(
            transport=transport,
            timeout=timeout_seconds,
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": self.user_agent},
        )

    def __enter__(self) -> "SafeHttpClient":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def get(
        self, url: str, *, ic_domains_only: bool = False, max_redirects: int | None = None
    ) -> FetchResponse:
        """GET ``url``, following redirects only to permitted hosts.

        With ``ic_domains_only`` (gateway fetches) every hop must stay on IC domains.
        ``max_redirects`` lowers the client's limit for this call.
        """
        limit = (
            self._max_redirects
            if max_redirects is None
            else min(max_redirects, self._max_redirects)
        )
        current = self._check(httpx.URL(url), ic_domains_only=ic_domains_only, redirect=False)
        hops: list[str] = []
        for _ in range(limit + 1):
            response = self._send("GET", current)
            location = response.headers.get("location")
            if response.status_code not in _REDIRECT_STATUSES or not location:
                return replace(response, redirects=tuple(hops))
            target = current.join(location)
            current = self._check(target, ic_domains_only=ic_domains_only, redirect=True)
            hops.append(str(current))
        raise TooManyRedirects(url)

    def post(
        self, url: str, *, content: bytes, headers: Mapping[str, str] | None = None
    ) -> FetchResponse:
        """POST ``content`` to an allowlisted ``url``. Redirects are never followed."""
        target = self._check(httpx.URL(url), ic_domains_only=False, redirect=False)
        return self._send("POST", target, content=content, headers=headers)

    def _check(self, url: httpx.URL, *, ic_domains_only: bool, redirect: bool) -> httpx.URL:
        host = url.host
        reason = None
        if url.scheme != "https":
            reason = "scheme"
        elif not is_allowed(host, self._extra_hosts):
            reason = "host"
        elif ic_domains_only and not is_ic_domain(host):
            reason = "not_ic_domain"
        if reason is None:
            return url
        log.warning("host_refused", host=host, url=str(url), reason=reason, redirect=redirect)
        raise (RedirectRefused if redirect else HostNotAllowed)(f"{reason}: {url}", target=str(url))

    def _send(
        self,
        method: str,
        url: httpx.URL,
        *,
        content: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> FetchResponse:
        attempt = 0
        while True:
            self._limiter.acquire(url.host)
            request = self._client.build_request(method, url, content=content, headers=headers)
            try:
                response = self._client.send(request, stream=True)
                try:
                    body, truncated = self._read_capped(response)
                finally:
                    response.close()
            except httpx.TimeoutException as exc:
                log.warning("http_timeout", host=url.host, timeout=self.timeout_seconds)
                raise FetchTimeout(f"timed out after {self.timeout_seconds} s: {url}") from exc
            result = FetchResponse(
                url=str(url),
                status_code=response.status_code,
                headers=dict(response.headers),
                body=body,
                truncated=truncated,
            )
            retryable = response.status_code == 429 or response.status_code >= 500
            if not retryable or attempt >= self._max_retries:
                return result
            delay = self._retry_delay(response, attempt)
            if delay is None:
                log.warning("retry_after_too_long", host=url.host, status=response.status_code)
                return result
            log.info("http_retry", host=url.host, status=response.status_code, delay=delay)
            self._sleep(delay)
            attempt += 1

    def _read_capped(self, response: httpx.Response) -> tuple[bytes, bool]:
        chunks: list[bytes] = []
        size = 0
        for chunk in response.iter_bytes():
            room = self._max_bytes - size
            if len(chunk) > room:
                chunks.append(chunk[:room])
                return b"".join(chunks), True
            chunks.append(chunk)
            size += len(chunk)
        return b"".join(chunks), False

    def _retry_delay(self, response: httpx.Response, attempt: int) -> float | None:
        """Seconds to wait before retrying; None when the server asks for longer than allowed."""
        header = response.headers.get("retry-after")
        if header:
            wait: float | None
            try:
                wait = float(header)
            except ValueError:
                try:
                    wait = parsedate_to_datetime(header).timestamp() - time.time()
                except (TypeError, ValueError):
                    wait = None
            if wait is not None:
                return None if wait > self._max_backoff else max(0.0, wait)
        return min(self._backoff_base * 2.0**attempt, self._max_backoff)
