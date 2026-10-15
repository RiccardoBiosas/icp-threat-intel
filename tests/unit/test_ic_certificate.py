"""Hash-tree lookup, root-hash reconstruction and certificate decoding."""

import hashlib

import cbor2
import pytest

from icp_threat_intel.core.ic_certificate import (
    UNVERIFIED_NO_BLS,
    CertificateError,
    Lookup,
    decode_certificate,
    decode_leb128,
    decode_principal_list,
    lookup_path,
    reconstruct,
)
from tests.collectors._cassettes import fork_all, labeled, leb128


def _leaf(value: bytes) -> list[object]:
    return [3, value]


TREE = fork_all(
    [
        labeled(b"b", _leaf(b"vb")),
        labeled(b"d", labeled(b"x", _leaf(b"vx"))),
        labeled(b"f", _leaf(b"vf")),
    ]
)


def test_lookup_found_absent_and_inner() -> None:
    assert lookup_path([b"b"], TREE).value == b"vb"
    assert lookup_path([b"d", b"x"], TREE).value == b"vx"
    for missing in ([b"a"], [b"c"], [b"e"], [b"g"], [b"d", b"y"]):
        assert lookup_path(missing, TREE).status is Lookup.ABSENT
    with pytest.raises(CertificateError):
        lookup_path([b"d"], TREE)
    assert lookup_path([], [0]).status is Lookup.ABSENT
    assert lookup_path([b"a"], [0]).status is Lookup.ABSENT


def test_pruned_subtrees_give_unknown_and_keep_the_root_hash() -> None:
    pruned_d = [4, reconstruct(labeled(b"d", labeled(b"x", _leaf(b"vx"))))]
    tree = fork_all([labeled(b"b", _leaf(b"vb")), pruned_d, labeled(b"f", _leaf(b"vf"))])
    assert reconstruct(tree) == reconstruct(TREE)
    assert lookup_path([b"d", b"x"], tree).status is Lookup.UNKNOWN
    assert lookup_path([b"c"], tree).status is Lookup.UNKNOWN
    assert lookup_path([b"a"], tree).status is Lookup.ABSENT
    assert lookup_path([], [4, b"\x00" * 32]).status is Lookup.UNKNOWN


def test_reconstruct_uses_spec_domain_separators() -> None:
    def h(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    leaf = h(b"\x10ic-hashtree-leaf" + b"v")
    assert reconstruct(_leaf(b"v")) == leaf
    assert reconstruct([0]) == h(b"\x11ic-hashtree-empty")
    assert reconstruct(labeled(b"k", _leaf(b"v"))) == h(b"\x13ic-hashtree-labeled" + b"k" + leaf)
    empty = h(b"\x11ic-hashtree-empty")
    assert reconstruct([1, [0], [0]]) == h(b"\x10ic-hashtree-fork" + empty + empty)


@pytest.mark.parametrize("bad", [[], [9], [1, [0]], [3], "x", [2, b"k"]])
def test_malformed_nodes_are_rejected(bad: object) -> None:
    with pytest.raises(CertificateError):
        reconstruct(bad)


def test_leb128() -> None:
    for value in (0, 1, 127, 128, 300, 1_760_486_400_000_000_000):
        assert decode_leb128(leb128(value)) == value
    with pytest.raises(CertificateError):
        decode_leb128(b"\x80")


def test_decode_certificate_reports_unverified_and_time() -> None:
    tree = fork_all([labeled(b"time", _leaf(leb128(42)))])
    data = cbor2.dumps(cbor2.CBORTag(55799, {"tree": tree, "signature": b"\x00" * 48}))
    cert = decode_certificate(data)
    assert cert.verification == UNVERIFIED_NO_BLS
    assert cert.time_ns() == 42
    assert cert.has_delegation is False
    assert cert.delegation_subnet is None
    assert cert.root_hash == reconstruct(tree)


def test_decode_certificate_reads_delegation_subnet() -> None:
    body = {"tree": [0], "signature": b"", "delegation": {"subnet_id": b"\x01", "certificate": b""}}
    cert = decode_certificate(cbor2.dumps(body))
    assert cert.has_delegation and cert.delegation_subnet == b"\x01"
    assert cert.time_ns() is None


@pytest.mark.parametrize("data", [b"\xff\xff", cbor2.dumps([1, 2]), cbor2.dumps({"tree": [0]})])
def test_decode_certificate_rejects_garbage(data: bytes) -> None:
    with pytest.raises(CertificateError):
        decode_certificate(data)


def test_decode_principal_list() -> None:
    assert decode_principal_list(cbor2.dumps([b"\x01", b"\x02"])) == [b"\x01", b"\x02"]
    assert decode_principal_list(cbor2.dumps([])) == []
    with pytest.raises(CertificateError):
        decode_principal_list(cbor2.dumps(["text"]))
