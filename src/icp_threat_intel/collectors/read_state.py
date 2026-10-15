"""read_state collector: module hash, controllers and ``candid:service`` per canister.

Written against docs/sources/read-state.md. Each canister gets two anonymous read_state
requests through the query-only ``IcClient``:

* ``state``: ``/canister/<id>/module_hash`` and ``/canister/<id>/controllers``;
* ``candid``: ``/canister/<id>/metadata/candid:service``, sent alone because a private
  section can make the boundary node reject the whole request.

The body of each ``RawFetch`` is the certificate exactly as returned. A non-200 answer is
recorded too (status and body), so "candid not readable" is evidence, not a gap.
Certificates are not BLS-verified yet; the parser marks them ``unverified:no_bls``.
"""

from collections.abc import Callable, Iterator, Sequence
from datetime import UTC, datetime

from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.ic_client import DEFAULT_BOUNDARY, IcClient, IcHttpError
from icp_threat_intel.core.ic_encoding import principal_from_text
from icp_threat_intel.core.models import RawFetch

CBOR_CONTENT_TYPE = "application/cbor"
REQUESTS: dict[str, tuple[tuple[bytes, ...], ...]] = {
    "state": ((b"module_hash",), (b"controllers",)),
    "candid": ((b"metadata", b"candid:service"),),
}


def canister_paths(canister_id: str, request: str) -> list[list[bytes]]:
    """Full state-tree paths of ``request`` for ``canister_id``."""
    raw = principal_from_text(canister_id)
    return [[b"canister", raw, *suffix] for suffix in REQUESTS[request]]


def path_names(request: str) -> list[str]:
    return ["/".join(label.decode() for label in suffix) for suffix in REQUESTS[request]]


def _now() -> datetime:
    return datetime.now(UTC)


class ReadStateCollector:
    """Collector for ``SourceType.IC_READ_STATE``; query-only by construction."""

    name = "ic_read_state"
    source_type = SourceType.IC_READ_STATE

    def __init__(
        self,
        client: IcClient,
        *,
        boundary: str = DEFAULT_BOUNDARY,
        clock: Callable[[], datetime] = _now,
        synthetic: bool = False,
    ) -> None:
        self._client = client
        self._boundary = boundary.rstrip("/")
        self._clock = clock
        self._synthetic = synthetic

    def collect(self, targets: Sequence[str]) -> Iterator[RawFetch]:
        for canister_id in targets:
            for request in REQUESTS:
                yield self._fetch(canister_id, request)

    def _fetch(self, canister_id: str, request: str) -> RawFetch:
        # The fragment keeps the two requests apart in the raw store's (source, url, sha256) key.
        url = f"{self._boundary}/api/v3/canister/{canister_id}/read_state#{request}"
        meta = {"canister_id": canister_id, "request": request, "paths": path_names(request)}
        try:
            body = self._client.read_state(canister_id, canister_paths(canister_id, request))
            status = 200
        except IcHttpError as exc:
            if exc.status_code is None:
                raise
            body, status = exc.body, exc.status_code
            meta["error"] = str(exc)
        return RawFetch(
            source_type=self.source_type,
            source_name=self.name,
            url=url,
            fetched_at=self._clock(),
            body=body,
            http_status=status,
            content_type=CBOR_CONTENT_TYPE if status == 200 else None,
            synthetic=self._synthetic,
            request_meta=meta,
        )
