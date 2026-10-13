"""Request envelopes and principal text encoding for the query-only IC client.

Only ``query`` and ``read_state`` envelopes can be built (SPEC guardrail 1). Requests are
sent by the anonymous principal and carry no signature. Reference: the IC interface spec,
https://internetcomputer.org/docs/references/ic-interface-spec
"""

import base64
import binascii
import time
import zlib
from collections.abc import Mapping
from typing import Any

import cbor2

ALLOWED_REQUEST_TYPES: frozenset[str] = frozenset({"query", "read_state"})
ANONYMOUS_PRINCIPAL = b"\x04"
SELF_DESCRIBE_TAG = 55799
INGRESS_EXPIRY_SECONDS = 4 * 60
_MAX_PRINCIPAL_BYTES = 29
_REQUIRED_FIELDS = {"query": ("method_name", "arg"), "read_state": ("paths",)}


class ForbiddenRequestType(ValueError):
    """Raised for any request type other than query or read_state."""


def principal_to_text(raw: bytes) -> str:
    """Textual form: base32(crc32 || bytes), lowercase, grouped by five with dashes."""
    checksum = zlib.crc32(raw).to_bytes(4, "big")
    encoded = base64.b32encode(checksum + raw).decode("ascii").lower().rstrip("=")
    return "-".join(encoded[i : i + 5] for i in range(0, len(encoded), 5))


def principal_from_text(text: str) -> bytes:
    """Parse a textual principal, checking its checksum and canonical form."""
    compact = text.replace("-", "").upper()
    try:
        data = base64.b32decode(compact + "=" * (-len(compact) % 8))
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"not a principal: {text!r}") from exc
    if len(data) < 4 or len(data) - 4 > _MAX_PRINCIPAL_BYTES:
        raise ValueError(f"not a principal: {text!r}")
    raw = data[4:]
    if principal_to_text(raw) != text.lower():
        raise ValueError(f"not a canonical principal: {text!r}")
    return raw


def ingress_expiry_ns(now_ns: int | None = None) -> int:
    base = time.time_ns() if now_ns is None else now_ns
    return base + INGRESS_EXPIRY_SECONDS * 1_000_000_000


def build_envelope(
    request_type: str,
    *,
    canister_id: str,
    fields: Mapping[str, Any],
    expiry_ns: int | None = None,
) -> dict[str, Any]:
    """Build an unsigned anonymous envelope; only query and read_state are possible."""
    if request_type not in ALLOWED_REQUEST_TYPES:
        raise ForbiddenRequestType(f"request type {request_type!r} is not allowed")
    missing = [name for name in _REQUIRED_FIELDS[request_type] if name not in fields]
    if missing:
        raise ValueError(f"{request_type} envelope is missing {missing}")
    content: dict[str, Any] = {
        "request_type": request_type,
        "sender": ANONYMOUS_PRINCIPAL,
        "ingress_expiry": expiry_ns if expiry_ns is not None else ingress_expiry_ns(),
    }
    if request_type == "query":
        content["canister_id"] = principal_from_text(canister_id)
    for name in _REQUIRED_FIELDS[request_type]:
        content[name] = fields[name]
    return {"content": content}


def encode_cbor(value: Any) -> bytes:
    return cbor2.dumps(cbor2.CBORTag(SELF_DESCRIBE_TAG, value))


def decode_cbor(data: bytes) -> Any:
    value = cbor2.loads(data)
    while isinstance(value, cbor2.CBORTag) and value.tag == SELF_DESCRIBE_TAG:
        value = value.value
    return value
