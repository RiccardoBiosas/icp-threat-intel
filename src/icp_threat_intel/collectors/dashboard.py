"""IC Dashboard API collector: canister metadata, subnet membership, controllers.

EXPERIMENTAL, written against docs/sources/dashboard-api.md (Status: EXPERIMENTAL).
TODO: confirm the ``/api/v3/canisters/{id}`` response fields against
https://ic-api.internetcomputer.org/api/v3/swagger or the first ``make record`` cassette;
the OpenAPI spec documents no response schema for it.

Per canister: ``GET /api/v3/canisters/{id}``, then, when a subnet id is found,
``GET /api/v4/subnets/{subnet_id}`` (schema ``Subnet`` is documented). Bodies are stored
verbatim through the raw store; non-200 answers are kept as evidence. Only the allowlisted
``ic-api.internetcomputer.org`` host is contacted, through the shared HTTP client.

``extract_canister`` and ``extract_subnet`` read the fields defensively: anything absent
or of an unexpected type stays ``None`` rather than being guessed.
"""

import json
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.http import SafeHttpClient
from icp_threat_intel.core.ic_encoding import principal_from_text
from icp_threat_intel.core.models import RawFetch

BASE_URL = "https://ic-api.internetcomputer.org"


def canisters_list_url() -> str:
    return f"{BASE_URL}/api/v4/canisters"


def subnets_list_url() -> str:
    return f"{BASE_URL}/api/v4/subnets"


def canister_url(canister_id: str) -> str:
    return f"{BASE_URL}/api/v3/canisters/{canister_id}"


def subnet_url(subnet_id: str) -> str:
    return f"{BASE_URL}/api/v4/subnets/{subnet_id}"


@dataclass(frozen=True)
class DashboardCanister:
    canister_id: str
    subnet_id: str | None
    controllers: tuple[str, ...] | None
    module_hash: str | None
    canister_type: str | None
    language: str | None
    name: str | None
    updated_at: str | None
    status: str | None = None


@dataclass(frozen=True)
class DashboardSubnet:
    subnet_id: str
    subnet_type: str | None
    total_canisters: int | None
    running_canisters: int | None
    stopped_canisters: int | None


def _json(body: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _str(data: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _int(data: dict[str, Any], key: str) -> int | None:
    value = data.get(key)  # the Subnet schema types counts as strings
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _principal(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        principal_from_text(value)
    except ValueError:
        return None
    return value


def extract_canister(body: bytes) -> DashboardCanister | None:
    """Map a ``/api/v3/canisters/{id}`` body to known fields, or ``None`` if unusable."""
    data = _json(body)
    return None if data is None else canister_from_dict(data)


def canister_from_dict(data: dict[str, Any]) -> DashboardCanister | None:
    """Map one canister object (detail body or list item) to known fields."""
    canister_id = _principal(data.get("canister_id"))
    if canister_id is None:
        return None
    raw_controllers = data.get("controllers")
    controllers: tuple[str, ...] | None = None
    if isinstance(raw_controllers, list):
        parsed = [_principal(c) for c in raw_controllers]
        controllers = tuple(c for c in parsed if c is not None)
    module_hash = _str(data, "module_hash")
    if module_hash is not None:
        module_hash = module_hash.lower().removeprefix("0x")
    status = _str(data, "status")
    return DashboardCanister(
        canister_id=canister_id,
        subnet_id=_principal(data.get("subnet_id")),
        controllers=controllers,
        module_hash=module_hash,
        canister_type=_str(data, "canister_type"),
        language=_str(data, "language"),
        name=_str(data, "name"),
        updated_at=_str(data, "updated_at"),
        status=status.lower() if status else None,
    )


def extract_subnet(body: bytes) -> DashboardSubnet | None:
    """Map a ``/api/v4/subnets/{id}`` body (schema ``Subnet``) to the fields we use."""
    data = _json(body)
    subnet_id = _principal(data.get("subnet_id")) if data else None
    if data is None or subnet_id is None:
        return None
    return DashboardSubnet(
        subnet_id=subnet_id,
        subnet_type=_str(data, "subnet_type"),
        total_canisters=_int(data, "total_canisters"),
        running_canisters=_int(data, "running_canisters"),
        stopped_canisters=_int(data, "stopped_canisters"),
    )


def _now() -> datetime:
    return datetime.now(UTC)


class DashboardCollector:
    """Collector for ``SourceType.DASHBOARD_API`` (read-only GETs)."""

    name = "dashboard_api"
    source_type = SourceType.DASHBOARD_API

    def __init__(
        self,
        http: SafeHttpClient,
        *,
        clock: Callable[[], datetime] = _now,
        synthetic: bool = False,
    ) -> None:
        self._http = http
        self._clock = clock
        self._synthetic = synthetic

    def collect(self, targets: Sequence[str]) -> Iterator[RawFetch]:
        for canister_id in targets:
            principal_from_text(canister_id)  # refuses anything that is not a principal
            fetch = self._get(canister_url(canister_id), {"canister_id": canister_id})
            yield fetch
            meta = extract_canister(fetch.body) if fetch.http_status == 200 else None
            if meta is not None and meta.subnet_id is not None:
                yield self._get(
                    subnet_url(meta.subnet_id),
                    {"canister_id": canister_id, "subnet_id": meta.subnet_id},
                )

    def _get(self, url: str, meta: dict[str, Any]) -> RawFetch:
        response = self._http.get(url)
        kind = "subnet" if "subnet_id" in meta else "canister"
        return RawFetch(
            source_type=self.source_type,
            source_name=self.name,
            url=url,
            fetched_at=self._clock(),
            body=response.body,
            truncated=response.truncated,
            http_status=response.status_code,
            content_type=response.headers.get("content-type"),
            headers=response.headers,
            synthetic=self._synthetic,
            request_meta={**meta, "request": kind, "redirects": list(response.redirects)},
        )
