"""Helpers shared by guardrail tests (not a test module)."""

import ast
from collections.abc import Callable, Iterator
from pathlib import Path

import httpx

from icp_threat_intel.core.http import SafeHttpClient
from icp_threat_intel.core.ratelimit import HostRateLimiter

SRC = Path(__file__).resolve().parents[2] / "src" / "icp_threat_intel"
CONTACT = "test@example.invalid"

Handler = Callable[[httpx.Request], httpx.Response]


def source_files() -> Iterator[Path]:
    files = sorted(SRC.rglob("*.py"))
    # Guard against a vacuous pass: the static scans must see the real package.
    assert len(files) > 10, f"no source files found under {SRC}"
    assert (SRC / "core" / "http.py") in files
    yield from files


def imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


class Recorder:
    """A mock transport that records every request it receives."""

    def __init__(self, handler: Handler) -> None:
        self.requests: list[httpx.Request] = []
        self._handler = handler

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._handler(request)

    @property
    def hosts(self) -> list[str]:
        return [r.url.host for r in self.requests]


def make_client(handler: Handler, **kwargs: object) -> tuple[SafeHttpClient, Recorder]:
    recorder = Recorder(handler)
    sleeps: list[float] = []
    limiter = kwargs.pop("limiter", None) or HostRateLimiter(
        rate_per_second=1000.0, burst=1000, sleep=sleeps.append
    )
    client = SafeHttpClient(
        contact=CONTACT,
        transport=httpx.MockTransport(recorder),
        limiter=limiter,  # type: ignore[arg-type]
        sleep=sleeps.append,
        **kwargs,  # type: ignore[arg-type]
    )
    return client, recorder
