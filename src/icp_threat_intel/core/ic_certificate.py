"""Decode read_state certificates: hash-tree lookup, root-hash reconstruction, time.

Written against docs/sources/read-state.md and the IC interface spec (Certification):
https://docs.internetcomputer.org/references/ic-interface-spec/certification.md

BLS signature verification is not implemented yet (no BLS backend chosen, see
OPEN_QUESTIONS.md T06). Every decoded certificate therefore reports
``verification="unverified:no_bls"``; callers must not treat its contents as verified.
"""

import hashlib
import itertools
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import cbor2

from icp_threat_intel.core.ic_encoding import decode_cbor

UNVERIFIED_NO_BLS = "unverified:no_bls"

EMPTY, FORK, LABELED, LEAF, PRUNED = 0, 1, 2, 3, 4


class CertificateError(ValueError):
    """The bytes are not a well-formed certificate or hash tree."""


class Lookup(StrEnum):
    FOUND = "found"
    ABSENT = "absent"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class LookupResult:
    status: Lookup
    value: bytes | None = None


@dataclass(frozen=True)
class Certificate:
    tree: Any
    signature: bytes
    has_delegation: bool
    delegation_subnet: bytes | None
    root_hash: bytes
    verification: str = UNVERIFIED_NO_BLS

    def lookup(self, path: Sequence[bytes]) -> LookupResult:
        return lookup_path(path, self.tree)

    def time_ns(self) -> int | None:
        found = self.lookup([b"time"])
        return decode_leb128(found.value) if found.value is not None else None


def _ds(tag: str) -> bytes:
    raw = tag.encode("ascii")
    return bytes([len(raw)]) + raw


def _node(tree: Any) -> list[Any]:
    if not isinstance(tree, list) or not tree or not isinstance(tree[0], int):
        raise CertificateError(f"malformed hash-tree node: {tree!r:.80}")
    arity = {EMPTY: 1, FORK: 3, LABELED: 3, LEAF: 2, PRUNED: 2}.get(tree[0])
    if arity != len(tree):
        raise CertificateError(f"malformed hash-tree node of type {tree[0]}")
    return tree


def reconstruct(tree: Any) -> bytes:
    """Root hash of a hash tree (spec ``reconstruct``)."""
    node = _node(tree)
    kind = node[0]
    if kind == EMPTY:
        return hashlib.sha256(_ds("ic-hashtree-empty")).digest()
    if kind == FORK:
        return hashlib.sha256(
            _ds("ic-hashtree-fork") + reconstruct(node[1]) + reconstruct(node[2])
        ).digest()
    if kind == LABELED:
        return hashlib.sha256(
            _ds("ic-hashtree-labeled") + bytes(node[1]) + reconstruct(node[2])
        ).digest()
    if kind == LEAF:
        return hashlib.sha256(_ds("ic-hashtree-leaf") + bytes(node[1])).digest()
    return bytes(node[1])


def _flatten(tree: Any) -> list[list[Any]]:
    node = _node(tree)
    if node[0] == EMPTY:
        return []
    if node[0] == FORK:
        return _flatten(node[1]) + _flatten(node[2])
    return [node]


def _find_label(label: bytes, nodes: list[list[Any]]) -> tuple[Lookup, Any]:
    labels = [bytes(n[1]) if n[0] == LABELED else None for n in nodes]
    for node, current in zip(nodes, labels, strict=True):
        if current == label:
            return Lookup.FOUND, node[2]
    if not nodes:
        return Lookup.ABSENT, None
    if labels[0] is not None and label < labels[0]:
        return Lookup.ABSENT, None
    if labels[-1] is not None and labels[-1] < label:
        return Lookup.ABSENT, None
    for left, right in itertools.pairwise(labels):
        if left is not None and right is not None and left < label < right:
            return Lookup.ABSENT, None
    return Lookup.UNKNOWN, None


def lookup_path(path: Sequence[bytes], tree: Any) -> LookupResult:
    """Spec ``lookup_path``: Found, Absent (provably missing) or Unknown (pruned)."""
    node = _node(tree)
    if not path:
        if node[0] == LEAF:
            return LookupResult(Lookup.FOUND, bytes(node[1]))
        if node[0] == EMPTY:
            return LookupResult(Lookup.ABSENT)
        if node[0] == PRUNED:
            return LookupResult(Lookup.UNKNOWN)
        raise CertificateError("path ends at an inner node")
    status, subtree = _find_label(bytes(path[0]), _flatten(node))
    if status is not Lookup.FOUND:
        return LookupResult(status)
    return lookup_path(path[1:], subtree)


def decode_leb128(data: bytes) -> int:
    value, shift = 0, 0
    for byte in data:
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value
    raise CertificateError("truncated LEB128 value")


def decode_certificate(data: bytes) -> Certificate:
    """Decode certificate CBOR and reconstruct its root hash (no signature check)."""
    try:
        cert = decode_cbor(data)
    except (cbor2.CBORDecodeError, ValueError) as exc:
        raise CertificateError(f"certificate is not CBOR: {exc}") from exc
    if not isinstance(cert, Mapping) or "tree" not in cert or "signature" not in cert:
        raise CertificateError("certificate lacks tree or signature")
    tree = _normalise(cert["tree"])
    delegation = cert.get("delegation")
    subnet = None
    if isinstance(delegation, Mapping) and "subnet_id" in delegation:
        subnet = bytes(delegation["subnet_id"])
    return Certificate(
        tree=tree,
        signature=bytes(cert["signature"]),
        has_delegation=delegation is not None,
        delegation_subnet=subnet,
        root_hash=reconstruct(tree),
    )


def _normalise(tree: Any) -> Any:
    """Turn cbor2 tuples and frozen containers into plain lists, bytes stay bytes."""
    if isinstance(tree, list | tuple):
        return [_normalise(item) for item in tree]
    return tree


def decode_principal_list(data: bytes) -> list[bytes]:
    """Decode the ``controllers`` leaf: a CBOR array of principal blobs."""
    value = decode_cbor(data)
    if not isinstance(value, list | tuple) or not all(isinstance(v, bytes) for v in value):
        raise CertificateError("controllers leaf is not an array of principals")
    return [bytes(v) for v in value]
