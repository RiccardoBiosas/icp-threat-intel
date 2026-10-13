"""Package artifact handling shared by registry collectors (SPEC guardrail 6).

Tarballs are hashed and stored locally under their sha256. Nothing is uploaded anywhere:
any future upload or submit function must take a keyword-only ``allow_upload=False`` flag
and call ``ensure_upload_allowed`` first.
"""

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

_SUFFIX_RE = re.compile(r"^(?:\.[A-Za-z0-9]+)*$")


class UploadNotAllowed(PermissionError):
    """An upload was attempted without the explicit ``allow_upload=True`` flag."""


@dataclass(frozen=True)
class StoredArtifact:
    sha256: str
    path: Path
    size_bytes: int


def store_artifact(data: bytes, dest_dir: Path, *, suffix: str = "") -> StoredArtifact:
    """Write ``data`` to ``dest_dir/<sha256><suffix>`` (idempotent) and return its record."""
    if not _SUFFIX_RE.match(suffix):
        raise ValueError(f"invalid artifact suffix: {suffix!r}")
    digest = hashlib.sha256(data).hexdigest()
    dest_dir.mkdir(parents=True, exist_ok=True)
    path = dest_dir / f"{digest}{suffix}"
    if not path.exists():
        tmp = path.with_name(path.name + ".part")
        tmp.write_bytes(data)
        tmp.replace(path)
    return StoredArtifact(sha256=digest, path=path, size_bytes=len(data))


def ensure_upload_allowed(*, allow_upload: bool = False) -> None:
    """Raise ``UploadNotAllowed`` unless the caller passed ``allow_upload=True``."""
    if allow_upload is not True:
        raise UploadNotAllowed("uploads need an explicit allow_upload=True flag")
