"""Guardrail 6: package tarballs are hashed and stored locally; nothing is uploaded unless
an explicit flag allows it."""

import ast
import hashlib
from pathlib import Path

import pytest

from icp_threat_intel.collectors.registry_common import (
    UploadNotAllowed,
    ensure_upload_allowed,
    store_artifact,
)
from tests.guardrails._support import source_files


def test_artifact_is_hashed_and_stored_locally(tmp_path: Path) -> None:
    data = b"\x1f\x8b fake tarball bytes"
    stored = store_artifact(data, tmp_path, suffix=".tgz")
    digest = hashlib.sha256(data).hexdigest()
    assert stored.sha256 == digest
    assert stored.size_bytes == len(data)
    assert stored.path.parent == tmp_path
    assert stored.path.name == f"{digest}.tgz"
    assert stored.path.read_bytes() == data


def test_storing_twice_is_idempotent(tmp_path: Path) -> None:
    first = store_artifact(b"same", tmp_path)
    second = store_artifact(b"same", tmp_path)
    assert first == second
    assert len(list(tmp_path.iterdir())) == 1


@pytest.mark.parametrize("suffix", ["/../x", "../evil", ".tgz/..", "a\\b"])
def test_suffix_cannot_escape_the_store(tmp_path: Path, suffix: str) -> None:
    with pytest.raises(ValueError):
        store_artifact(b"data", tmp_path, suffix=suffix)


def test_upload_needs_explicit_flag() -> None:
    with pytest.raises(UploadNotAllowed):
        ensure_upload_allowed()
    with pytest.raises(UploadNotAllowed):
        ensure_upload_allowed(allow_upload=False)
    ensure_upload_allowed(allow_upload=True)


def test_every_upload_or_submit_function_requires_the_flag() -> None:
    offenders: list[str] = []
    for path in source_files():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if not any(word in node.name.lower() for word in ("upload", "submit")):
                continue
            kwonly = {
                arg.arg: default
                for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True)
            }
            default = kwonly.get("allow_upload")
            ok = (
                "allow_upload" in kwonly
                and isinstance(default, ast.Constant)
                and default.value is False
            )
            if not ok:
                offenders.append(f"{path}:{node.lineno}: {node.name}")
    assert offenders == []
