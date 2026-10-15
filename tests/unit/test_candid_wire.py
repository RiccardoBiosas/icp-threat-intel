"""Candid binary codec used by the raw-gateway pre-check."""

import pytest

from icp_threat_intel.core.candid_wire import (
    CandidDecodeError,
    decode,
    encode_http_request,
    field_hash,
    sleb,
    uleb,
)
from tests.collectors._gateway_cassettes import encode_http_response


def test_field_hash_matches_spec_examples() -> None:
    # hash(id) = sum(utf8(id)[i] * 223^(k-1-i)) mod 2^32 (Candid spec, "Records").
    assert field_hash("") == 0
    assert field_hash("a") == 97
    assert field_hash("ab") == 97 * 223 + 98
    assert field_hash("x" * 10) < 2**32


def test_leb_roundtrip_edges() -> None:
    assert uleb(0) == b"\x00" and uleb(624485) == b"\xe5\x8e\x26"
    assert sleb(-123456) == b"\xc0\xbb\x78" and sleb(-1) == b"\x7f" and sleb(63) == b"\x3f"
    assert sleb(64) == b"\xc0\x00"


def test_http_request_roundtrip() -> None:
    data = encode_http_request("GET", "/", [("host", "x.raw.icp0.io")])
    (record,) = decode(data)
    assert record[field_hash("method")] == "GET"
    assert record[field_hash("url")] == "/"
    assert record[field_hash("headers")] == [{0: "host", 1: "x.raw.icp0.io"}]
    assert record[field_hash("body")] == b""


@pytest.mark.parametrize("upgrade", [None, True, False])
def test_http_response_upgrade_field(upgrade: bool | None) -> None:
    (record,) = decode(encode_http_response(418, [("a", "b")], b"body", upgrade))
    assert record[field_hash("upgrade")] is upgrade
    assert record[field_hash("status_code")] == 418
    assert record[field_hash("body")] == b"body"


def test_decodes_primitives_variants_and_references() -> None:
    # (nat, int, bool, text, null, principal, variant { b : nat8 }, func, opt service)
    table = (
        uleb(4)
        + sleb(-21) + uleb(2) + uleb(field_hash("a")) + sleb(-1) + uleb(field_hash("b")) + sleb(-5)
        + sleb(-22) + uleb(0) + uleb(0) + uleb(1) + b"\x01"
        + sleb(-23) + uleb(0)
        + sleb(-18) + sleb(2)
    )  # fmt: skip
    types = uleb(9) + b"".join(sleb(t) for t in (-3, -4, -2, -15, -1, -24, 0, 1, 3))
    values = (
        uleb(300) + sleb(-5) + b"\x01" + uleb(2) + b"hi"
        + b"\x01" + uleb(1) + b"\x04"
        + uleb(1) + b"\x07"
        + b"\x01" + b"\x01" + uleb(1) + b"\x09" + uleb(1) + b"m"
        + b"\x01" + b"\x01" + uleb(0)
    )  # fmt: skip
    decoded = decode(b"DIDL" + table + types + values)
    assert decoded == [
        300,
        -5,
        True,
        "hi",
        None,
        b"\x04",
        {field_hash("b"): 7},
        (b"\x09", "m"),
        b"",
    ]


@pytest.mark.parametrize(
    "data",
    [
        b"NOPE",
        b"DIDL\x00\x01\x71\x05ab",  # text shorter than its length
        b"DIDL\x01\x6d",  # truncated type table
        b"DIDL\x01\x55\x00",  # unknown opcode
        b"DIDL\x00\x01\x05",  # type index out of range
        b"DIDL\x00\x01\x71\x01\xff",  # invalid utf-8
        b"DIDL\x01\x6b\x01\x00\x7f\x01\x00\x05",  # variant index out of range
    ],
)
def test_malformed_messages_raise(data: bytes) -> None:
    with pytest.raises(CandidDecodeError):
        decode(data)
