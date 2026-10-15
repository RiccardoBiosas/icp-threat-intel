"""Minimal Candid binary codec: encode the ``http_request`` argument, decode any reply.

Decoding is generic (type table, records, variants, opt, vec, func, service, principal,
all primitives) and returns plain Python values: records and variants keyed by field
hash. Encoding covers only the fixed ``HttpRequest`` record the raw-gateway pre-check
sends. Reference: https://github.com/dfinity/candid/blob/master/spec/Candid.md
"""

import struct
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

MAGIC = b"DIDL"
NULL, BOOL, NAT, INT = -1, -2, -3, -4
NAT8, NAT16, NAT32, NAT64 = -5, -6, -7, -8
INT8, INT16, INT32, INT64 = -9, -10, -11, -12
FLOAT32, FLOAT64, TEXT, RESERVED, EMPTY = -13, -14, -15, -16, -17
OPT, VEC, RECORD, VARIANT, FUNC, SERVICE, PRINCIPAL = -18, -19, -20, -21, -22, -23, -24
_FIXED = {
    NAT8: "<B", NAT16: "<H", NAT32: "<I", NAT64: "<Q",
    INT8: "<b", INT16: "<h", INT32: "<i", INT64: "<q", FLOAT32: "<f", FLOAT64: "<d",
}  # fmt: skip


class CandidDecodeError(ValueError):
    """Bytes are not a well-formed Candid message."""


def field_hash(name: str) -> int:
    h = 0
    for byte in name.encode("utf-8"):
        h = (h * 223 + byte) % 2**32
    return h


def uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte, value = value & 0x7F, value >> 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def sleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte, value = value & 0x7F, value >> 7
        done = (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40)
        out.append(byte | (0 if done else 0x80))
        if done:
            return bytes(out)


def _text(value: str) -> bytes:
    raw = value.encode("utf-8")
    return uleb(len(raw)) + raw


def encode_http_request(
    method: str, url: str, headers: Sequence[tuple[str, str]], body: bytes = b""
) -> bytes:
    """Candid for ``(record { method; url; headers : vec record {text;text}; body : blob })``."""
    fields = sorted(
        [("method", TEXT), ("url", TEXT), ("headers", 1), ("body", 2)],
        key=lambda f: field_hash(f[0]),
    )
    table = [
        sleb(RECORD) + uleb(len(fields))
        + b"".join(uleb(field_hash(n)) + sleb(t) for n, t in fields),
        sleb(VEC) + sleb(3),
        sleb(VEC) + sleb(NAT8),
        sleb(RECORD) + uleb(2) + uleb(0) + sleb(TEXT) + uleb(1) + sleb(TEXT),
    ]  # fmt: skip
    values = {
        "method": _text(method),
        "url": _text(url),
        "headers": uleb(len(headers)) + b"".join(_text(k) + _text(v) for k, v in headers),
        "body": uleb(len(body)) + body,
    }
    return (
        MAGIC
        + uleb(len(table))
        + b"".join(table)
        + uleb(1)
        + sleb(0)
        + b"".join(values[n] for n, _ in fields)
    )


@dataclass
class _Reader:
    data: bytes
    pos: int = 0
    table: list[tuple[int, Any]] = field(default_factory=list)

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise CandidDecodeError("unexpected end of message")
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def uleb(self) -> int:
        value, shift = 0, 0
        while True:
            byte = self.take(1)[0]
            value |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                return value

    def sleb(self) -> int:
        value, shift = 0, 0
        while True:
            byte = self.take(1)[0]
            value |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                return value - (1 << shift) if byte & 0x40 else value

    def text(self) -> str:
        try:
            return self.take(self.uleb()).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CandidDecodeError("invalid utf-8 text") from exc


def _read_type_entry(r: _Reader) -> tuple[int, Any]:
    op = r.sleb()
    if op in (OPT, VEC):
        return op, r.sleb()
    if op in (RECORD, VARIANT):
        return op, [(r.uleb(), r.sleb()) for _ in range(r.uleb())]
    if op == FUNC:
        args = [r.sleb() for _ in range(r.uleb())]
        rets = [r.sleb() for _ in range(r.uleb())]
        anns = r.take(r.uleb())
        return op, (args, rets, anns)
    if op == SERVICE:
        return op, [(r.text(), r.sleb()) for _ in range(r.uleb())]
    raise CandidDecodeError(f"unsupported type opcode {op}")


def _principal(r: _Reader) -> bytes | None:
    if r.take(1) != b"\x01":
        return None  # opaque reference
    return r.take(r.uleb())


def _value(r: _Reader, t: int, depth: int = 0) -> Any:
    if depth > 100:
        raise CandidDecodeError("value nesting too deep")
    if t >= 0:
        if t >= len(r.table):
            raise CandidDecodeError(f"type index {t} out of range")
        op, info = r.table[t]
        if op == OPT:
            return _value(r, info, depth + 1) if r.take(1) == b"\x01" else None
        if op == VEC:
            if info == NAT8:
                return r.take(r.uleb())
            return [_value(r, info, depth + 1) for _ in range(r.uleb())]
        if op == RECORD:
            return {h: _value(r, ft, depth + 1) for h, ft in info}
        if op == VARIANT:
            idx = r.uleb()
            if idx >= len(info):
                raise CandidDecodeError("variant index out of range")
            h, ft = info[idx]
            return {h: _value(r, ft, depth + 1)}
        if op == FUNC:
            if r.take(1) != b"\x01":
                return None
            return (_principal(r), r.text())
        return _principal(r)  # SERVICE
    if t in _FIXED:
        fmt = _FIXED[t]
        return struct.unpack(fmt, r.take(struct.calcsize(fmt)))[0]
    if t in (NULL, RESERVED):
        return None
    if t == BOOL:
        return r.take(1) == b"\x01"
    if t == NAT:
        return r.uleb()
    if t == INT:
        return r.sleb()
    if t == TEXT:
        return r.text()
    if t == PRINCIPAL:
        return _principal(r)
    raise CandidDecodeError(f"cannot decode type {t}")


def decode(data: bytes) -> list[Any]:
    """Decode a Candid message into its argument values."""
    if not data.startswith(MAGIC):
        raise CandidDecodeError("missing DIDL magic")
    r = _Reader(data, len(MAGIC))
    r.table = [_read_type_entry(r) for _ in range(r.uleb())]
    types = [r.sleb() for _ in range(r.uleb())]
    return [_value(r, t) for t in types]
