"""Raw gateway fetcher: ``GET https://<id>.raw.icp0.io/`` and ``https://<id>.raw.ic0.app/``.

Written against docs/sources/raw-gateway.md. Fetch policy (SPEC section 5): GET only,
1 MB cap, 10 s timeout, no redirect off IC domains (at most one hop), no JavaScript, body
stored verbatim and hashed by the raw store. Nothing in a body is executed or followed.

Query-only pre-check (OPEN_QUESTIONS.md T06): the gateway upgrades a GET to an
``http_request_update`` *update call* when the canister's ``http_request`` reply sets
``upgrade = opt true``. Before any GET we therefore run ``http_request`` ourselves as an
anonymous query and skip both GETs unless it replied without asking for an upgrade. The
pre-check reply is stored as evidence too. Residual risk: a canister can answer our query
differently from the gateway's; recorded in the note's open questions.
"""

from collections.abc import Callable, Iterator, Sequence
from datetime import UTC, datetime
from typing import Any

from icp_threat_intel.core.candid_wire import (
    CandidDecodeError,
    decode,
    encode_http_request,
    field_hash,
)
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.http import (
    FetchTimeout,
    RedirectRefused,
    SafeHttpClient,
    TooManyRedirects,
)
from icp_threat_intel.core.ic_client import DEFAULT_BOUNDARY, IcClient, IcHttpError, IcReject
from icp_threat_intel.core.ic_encoding import principal_from_text
from icp_threat_intel.core.models import RawFetch

DOMAINS = ("raw.icp0.io", "raw.ic0.app")
MAX_REDIRECT_HOPS = 1
_UPGRADE = field_hash("upgrade")
_STATUS_CODE = field_hash("status_code")


def _now() -> datetime:
    return datetime.now(UTC)


class RawGatewayCollector:
    """Collector for ``SourceType.RAW_GATEWAY``."""

    name = "raw_gateway"
    source_type = SourceType.RAW_GATEWAY

    def __init__(
        self,
        http: SafeHttpClient,
        ic: IcClient,
        *,
        boundary: str = DEFAULT_BOUNDARY,
        clock: Callable[[], datetime] = _now,
        synthetic: bool = False,
    ) -> None:
        self._http = http
        self._ic = ic
        self._boundary = boundary.rstrip("/")
        self._clock = clock
        self._synthetic = synthetic

    def collect(self, targets: Sequence[str]) -> Iterator[RawFetch]:
        for canister_id in targets:
            if principal_from_text(canister_id) == b"":
                raise ValueError("the management canister is not a gateway target")
            fetch, proceed = self._precheck(canister_id)
            yield fetch
            if proceed:
                for domain in DOMAINS:
                    yield self._get(canister_id, domain)

    def _fetch(self, url: str, body: bytes, meta: dict[str, Any], **kw: Any) -> RawFetch:
        return RawFetch(
            source_type=self.source_type,
            source_name=self.name,
            url=url,
            fetched_at=self._clock(),
            body=body,
            synthetic=self._synthetic,
            request_meta=meta,
            **kw,
        )

    def _precheck(self, canister_id: str) -> tuple[RawFetch, bool]:
        url = f"{self._boundary}/api/v2/canister/{canister_id}/query#http_request"
        meta: dict[str, Any] = {"canister_id": canister_id, "request": "http_request_query"}
        arg = encode_http_request("GET", "/", [("host", f"{canister_id}.{DOMAINS[0]}")])
        try:
            reply = self._ic.query(canister_id, "http_request", arg)
        except IcReject as exc:
            meta |= {"outcome": "rejected", "reject_code": exc.code}
            return self._fetch(url, exc.message.encode(), meta, http_status=200), False
        except IcHttpError as exc:
            if exc.status_code is None:
                raise
            meta["outcome"] = "http_error"
            return self._fetch(url, exc.body, meta, http_status=exc.status_code), False
        try:
            (record, *_rest) = decode(reply)
            upgrade = record.get(_UPGRADE) if isinstance(record, dict) else None
            status_code = record.get(_STATUS_CODE) if isinstance(record, dict) else None
        except (CandidDecodeError, ValueError) as exc:
            meta |= {"outcome": "undecodable", "error": str(exc)}
            return self._fetch(url, reply, meta, http_status=200), False
        meta |= {"upgrade": upgrade, "response_status_code": status_code}
        meta["outcome"] = "upgrade_requested" if upgrade is True else "ok"
        fetch = self._fetch(url, reply, meta, http_status=200, content_type="application/candid")
        return fetch, upgrade is not True

    def _get(self, canister_id: str, domain: str) -> RawFetch:
        url = f"https://{canister_id}.{domain}/"
        meta: dict[str, Any] = {"canister_id": canister_id, "request": "get", "domain": domain}
        try:
            response = self._http.get(url, ic_domains_only=True, max_redirects=MAX_REDIRECT_HOPS)
        except RedirectRefused as exc:
            meta |= {"outcome": "redirect_refused", "location": exc.target}
            return self._fetch(url, b"", meta)
        except TooManyRedirects:
            meta["outcome"] = "too_many_redirects"
            return self._fetch(url, b"", meta)
        except FetchTimeout:
            meta |= {"outcome": "timeout", "timeout_seconds": self._http.timeout_seconds}
            return self._fetch(url, b"", meta)
        meta |= {"outcome": "ok", "final_url": response.url, "redirects": list(response.redirects)}
        return self._fetch(
            url,
            response.body,
            meta,
            truncated=response.truncated,
            http_status=response.status_code,
            content_type=response.headers.get("content-type"),
            headers=response.headers,
        )
