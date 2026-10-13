"""Secret redaction before storage (SPEC guardrail 5).

Each matching span is replaced by ``[REDACTED:<kind>:<sha256-prefix>]``. The rest of the body
is kept, because it is evidence. The caller stores ``sha256`` of the original bytes,
``stored_sha256`` of the stored bytes and ``redacted=True``.
"""

import hashlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from mnemonic import Mnemonic

HASH_PREFIX_LEN = 12
SEED_MIN_WORDS = 12

_BIP39_WORDS = frozenset(w.encode("ascii") for w in Mnemonic("english").wordlist)
_PEM_RE = re.compile(
    rb"-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY-----"
    rb"(?:.*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|.*\Z)",
    re.DOTALL,
)
_TOKEN_RES = tuple(
    re.compile(p)
    for p in (
        rb"sk-ant-[A-Za-z0-9_\-]{20,}",
        rb"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}",
        rb"\bgh[pousr]_[A-Za-z0-9]{36,}",
        rb"\bgithub_pat_[A-Za-z0-9_]{22,}",
        rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        rb"\bnpm_[A-Za-z0-9]{36,}",
        rb"\bpypi-AgE[A-Za-z0-9_\-]{50,}",
        rb"\bxox[abprs]-[A-Za-z0-9\-]{10,}",
        rb"\bAIza[0-9A-Za-z_\-]{35}",
    )
)
_NPM_AUTH_RE = re.compile(rb"_auth(?:Token)?\s*=\s*([^\s'\"]+)")
_WORD_RE = re.compile(rb"\S+")
_SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "auth-key",
        "api-key",
        "x-api-key",
        "x-auth-token",
        "private-token",
    }
)

Span = tuple[int, int, str]


@dataclass(frozen=True)
class Redaction:
    body: bytes
    redacted: bool
    kinds: tuple[str, ...]
    sha256: str
    stored_sha256: str


def _marker(kind: str, span: bytes) -> bytes:
    prefix = hashlib.sha256(span).hexdigest()[:HASH_PREFIX_LEN]
    return f"[REDACTED:{kind}:{prefix}]".encode("ascii")


def _pem_spans(data: bytes) -> list[Span]:
    spans = []
    for m in _PEM_RE.finditer(data):
        kind = "identity_pem" if m.group(1).strip() == b"EC" else "private_key_pem"
        spans.append((m.start(), m.end(), kind))
    return spans


def _npm_auth_spans(data: bytes) -> list[Span]:
    return [(m.start(1), m.end(1), "npm_auth_token") for m in _NPM_AUTH_RE.finditer(data)]


def _token_spans(data: bytes) -> list[Span]:
    return [(m.start(), m.end(), "api_token") for r in _TOKEN_RES for m in r.finditer(data)]


def _seed_spans(data: bytes) -> list[Span]:
    spans: list[Span] = []
    run: list[re.Match[bytes]] = []
    for m in [*_WORD_RE.finditer(data), None]:
        if m is not None and m.group() in _BIP39_WORDS:
            run.append(m)
            continue
        if len(run) >= SEED_MIN_WORDS:
            spans.append((run[0].start(), run[-1].end(), "seed_phrase"))
        run = []
    return spans


# Earlier detectors win when spans overlap.
_DETECTORS: tuple[Callable[[bytes], list[Span]], ...] = (
    _pem_spans,
    _npm_auth_spans,
    _token_spans,
    _seed_spans,
)


def redact(data: bytes) -> Redaction:
    """Replace every secret-shaped span in ``data`` and report what was found."""
    chosen: list[Span] = []
    for detector in _DETECTORS:
        for start, end, kind in detector(data):
            if all(end <= s or start >= e for s, e, _ in chosen):
                chosen.append((start, end, kind))
    chosen.sort()
    out = bytearray()
    cursor = 0
    for start, end, kind in chosen:
        out += data[cursor:start] + _marker(kind, data[start:end])
        cursor = end
    out += data[cursor:]
    body = bytes(out)
    return Redaction(
        body=body,
        redacted=bool(chosen),
        kinds=tuple(sorted({kind for _, _, kind in chosen})),
        sha256=hashlib.sha256(data).hexdigest(),
        stored_sha256=hashlib.sha256(body).hexdigest(),
    )


def redact_headers(headers: Mapping[str, str]) -> tuple[dict[str, str], tuple[str, ...]]:
    """Redact sensitive header values entirely and scan the rest like a body."""
    cleaned: dict[str, str] = {}
    kinds: set[str] = set()
    for name, value in headers.items():
        raw = value.encode("utf-8", "surrogateescape")
        if name.lower() in _SENSITIVE_HEADERS:
            cleaned[name] = _marker("header", raw).decode("ascii")
            kinds.add("header")
            continue
        result = redact(raw)
        cleaned[name] = result.body.decode("utf-8", "surrogateescape")
        kinds.update(result.kinds)
    return cleaned, tuple(sorted(kinds))
