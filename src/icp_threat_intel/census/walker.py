"""Census walk: every subnet, every canister, via the Dashboard API (PLAN steps 1-4).

EXPERIMENTAL like the Dashboard client it uses (docs/sources/dashboard-api.md): v4 list
endpoints, cursor pagination (``next_cursor`` in, ``after`` out), page size 100. Every page
is stored verbatim in the raw store before it is read. A subnet counts as complete only if
all its pages were fetched without error and before the ceiling; neither an error nor the
ceiling aborts the run.
"""

import json
import urllib.parse
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

from icp_threat_intel.census.diff import CanisterState
from icp_threat_intel.collectors.dashboard import (
    canister_from_dict,
    canisters_list_url,
    subnets_list_url,
)
from icp_threat_intel.core.enums import CanisterStatus, SourceType
from icp_threat_intel.core.http import (
    FetchTimeout,
    HostNotAllowed,
    SafeHttpClient,
    TooManyRedirects,
)
from icp_threat_intel.core.interfaces import RawStore
from icp_threat_intel.core.models import RawFetch

log = structlog.get_logger(__name__)
PAGE_LIMIT = 100
MAX_PAGES = 10_000  # per listing; guards against a cursor that never ends
_STATUSES = {s.value: s for s in CanisterStatus}


@dataclass
class WalkResult:
    run_id: str
    started_at: datetime
    states: dict[str, CanisterState] = field(default_factory=dict)
    complete_subnets: set[str] = field(default_factory=set)
    incomplete_subnets: set[str] = field(default_factory=set)
    ceiling_hit: bool = False
    pages: int = 0


def _now() -> datetime:
    return datetime.now(UTC)


def _new_run_id() -> str:
    return str(uuid.uuid4())


class CensusWalker:
    def __init__(
        self,
        http: SafeHttpClient,
        store: RawStore,
        *,
        ceiling: int,
        clock: Callable[[], datetime] = _now,
        run_id: Callable[[], str] = _new_run_id,
        synthetic: bool = False,
    ) -> None:
        if ceiling <= 0:
            raise ValueError("the census ceiling must be positive")
        self._http = http
        self._store = store
        self._ceiling = ceiling
        self._clock = clock
        self._run_id = run_id
        self._synthetic = synthetic

    def walk(self) -> WalkResult:
        result = WalkResult(run_id=self._run_id(), started_at=self._clock())
        subnets = self._subnet_ids(result)
        for subnet in subnets:
            if result.ceiling_hit:
                result.incomplete_subnets.add(subnet)
                continue
            complete = self._walk_subnet(subnet, result)
            (result.complete_subnets if complete else result.incomplete_subnets).add(subnet)
        log.info(
            "census_walk_done",
            run_id=result.run_id,
            canisters=len(result.states),
            complete=len(result.complete_subnets),
            incomplete=len(result.incomplete_subnets),
            ceiling_hit=result.ceiling_hit,
        )
        return result

    def _subnet_ids(self, result: WalkResult) -> list[str]:
        ids: set[str] = set()
        for item in self._pages(subnets_list_url(), {}, result, "census_subnets") or []:
            subnet = item.get("subnet_id")
            if isinstance(subnet, str) and subnet:
                ids.add(subnet)
        return sorted(ids)  # deterministic order

    def _walk_subnet(self, subnet: str, result: WalkResult) -> bool:
        params = {"subnet_id": subnet}
        items = self._pages(canisters_list_url(), params, result, "census_canisters", subnet)
        return items is not None and not result.ceiling_hit

    def _pages(
        self,
        url: str,
        params: dict[str, str],
        result: WalkResult,
        request: str,
        subnet: str | None = None,
    ) -> list[dict[str, Any]] | None:
        """All items of a cursor-paged listing; ``None`` if any page failed."""
        items: list[dict[str, Any]] = []
        cursor: Any = None
        for _ in range(MAX_PAGES):
            query: dict[str, Any] = {**params, "limit": PAGE_LIMIT}
            if cursor is not None:
                query["after"] = cursor
            data = self._page(f"{url}?{urllib.parse.urlencode(query, doseq=True)}", request, result)
            if data is None:
                return None
            page = [i for i in data.get("data") or [] if isinstance(i, dict)]
            items.extend(page)
            if subnet is not None and self._record(page, subnet, result):
                return items  # ceiling reached; the caller sees ceiling_hit
            cursor = data.get("next_cursor")
            if not page or cursor in (None, "", []):
                return items
        log.warning("census_page_limit", url=url, pages=MAX_PAGES)
        return None

    def _page(self, url: str, request: str, result: WalkResult) -> dict[str, Any] | None:
        meta = {"request": request, "census_run_id": result.run_id}
        try:
            response = self._http.get(url)
        except (FetchTimeout, HostNotAllowed, TooManyRedirects) as exc:
            log.warning("census_page_failed", url=url, error=str(exc))
            return None
        self._store.save(
            RawFetch(
                source_type=SourceType.DASHBOARD_API,
                source_name="dashboard_api",
                url=url,
                fetched_at=self._clock(),
                body=response.body,
                truncated=response.truncated,
                http_status=response.status_code,
                content_type=response.headers.get("content-type"),
                headers=response.headers,
                synthetic=self._synthetic,
                request_meta=meta,
            )
        )
        result.pages += 1
        if response.status_code != 200 or response.truncated:
            return None
        try:
            data = json.loads(response.body)
        except (UnicodeDecodeError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def _record(self, page: list[dict[str, Any]], subnet: str, result: WalkResult) -> bool:
        """Add canisters from one page; True once the ceiling is reached."""
        for item in page:
            if len(result.states) >= self._ceiling:
                result.ceiling_hit = True
                return True
            found = canister_from_dict(item)
            if found is None:
                continue
            result.states[found.canister_id] = CanisterState(
                canister_id=found.canister_id,
                subnet=found.subnet_id or subnet,
                controllers=found.controllers,
                module_hash=found.module_hash,
                status=_STATUSES.get(found.status or "", CanisterStatus.UNKNOWN),
            )
        if len(result.states) >= self._ceiling:
            result.ceiling_hit = True
            return True
        return False
