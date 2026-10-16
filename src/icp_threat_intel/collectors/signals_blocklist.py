"""Signals blocklists: community-maintained phishing/scam domain lists, ICP hosts extracted.

Written against docs/sources/phishdestroy.md (Status: VERIFIED, checked 2026-10-16). The
only feed is PhishDestroy's ``list.json`` on GitLab: a JSON array of every hostname the
project has listed (append-only, about 222,000 entries, 5.7 MB). It held 48 ICP gateway
hosts on 2026-10-16, each naming a canister.

* **Bulk download only.** The full list is fetched; PhishDestroy's per-domain API is never
  used, since lookups would reveal which domains or canisters are tracked. Only GitLab is
  contacted, through ``blocklist_http`` (``SafeHttpClient(extra_hosts=...)``).
* **Data only.** Hostnames are never resolved or visited. ``canister_from_host`` keeps only
  ``<canister id>[.raw].icp0.io|ic0.app`` hosts whose id passes the principal checksum.
* **Low authority.** Entries are community-reported and the operators are anonymous, so the
  feed is ``signals_feed`` (reliability 40, never counted by the two-signal rule).
* **Larger bodies.** The list exceeds the shared 1 MB cap, so this client alone allows
  ``MAX_BLOCKLIST_BYTES``; each changed list is stored verbatim in the raw store.
"""

import json
import re
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from icp_threat_intel.collectors.signals_feed import _now
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.http import SafeHttpClient
from icp_threat_intel.core.ic_encoding import principal_from_text
from icp_threat_intel.core.models import RawFetch

MAX_BLOCKLIST_BYTES = 32 * 1024 * 1024
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_GATEWAY_HOST = re.compile(r"^(?P<label>[a-z0-9-]+)(?:\.raw)?\.(?:icp0\.io|ic0\.app)$")
_HYPHENATED_ID = re.compile(r"^(?:[a-z2-7]{5}-){4}cai$")
_COMPACT_ID = re.compile(r"^[a-z2-7]{20}cai$")


@dataclass(frozen=True)
class BlocklistFeed:
    name: str  # also the ``sources`` row name
    url: str  # https URL of the full list
    format: str = "json_domains"  # a JSON array of hostnames

    def __post_init__(self) -> None:
        parts = urlsplit(self.url)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError(f"blocklist url must be https: {self.url!r}")
        if not _NAME_RE.match(self.name):
            raise ValueError(f"blocklist name must be lowercase kebab-case: {self.name!r}")

    @property
    def host(self) -> str:
        return str(urlsplit(self.url).hostname)


PHISHDESTROY = BlocklistFeed(
    "phishdestroy", "https://gitlab.com/phishdestroy/destroylist/-/raw/main/list.json"
)
DEFAULT_BLOCKLISTS: tuple[BlocklistFeed, ...] = (PHISHDESTROY,)


def blocklist_http(
    contact: str, feeds: Sequence[BlocklistFeed] = DEFAULT_BLOCKLISTS, **kwargs: Any
) -> SafeHttpClient:
    """A shared-client instance for exactly the lists' hosts, with the larger body cap."""
    hosts = tuple(dict.fromkeys(f.host for f in feeds))
    kwargs.setdefault("max_bytes", MAX_BLOCKLIST_BYTES)
    return SafeHttpClient(contact, extra_hosts=hosts, **kwargs)


def extract_domains(body: bytes) -> list[str] | None:
    """Lowercased hostnames of a JSON-array list, or ``None`` if the body is unusable."""
    try:
        data = json.loads(body)
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(data, list):
        return None
    return [d.strip().lower() for d in data if isinstance(d, str) and d.strip()]


def canister_from_host(host: str) -> str | None:
    """The canister id of an ICP gateway host, checksum-verified, else ``None``.

    Accepts ``<id>.icp0.io``, ``<id>.raw.icp0.io``, ``<id>.ic0.app`` and ``<id>.raw.ic0.app``.
    Some lists strip the hyphens from the id; they are restored before the checksum check.
    """
    match = _GATEWAY_HOST.match(host.strip().lower())
    if match is None:
        return None
    label = match["label"]
    if _COMPACT_ID.match(label):
        label = "-".join(label[i : i + 5] for i in range(0, 20, 5)) + "-cai"
    if not _HYPHENATED_ID.match(label):
        return None
    try:
        principal_from_text(label)
    except ValueError:
        return None
    return label


class SignalsBlocklistCollector:
    """Collector for ``SourceType.SIGNALS_FEED`` blocklists (one GET each). Targets: names."""

    name = "signals_blocklist"
    source_type = SourceType.SIGNALS_FEED

    def __init__(
        self,
        http: SafeHttpClient,
        *,
        feeds: Sequence[BlocklistFeed] = DEFAULT_BLOCKLISTS,
        clock: Callable[[], datetime] = _now,
        synthetic: bool = False,
    ) -> None:
        self._http = http
        self._feeds = {f.name: f for f in feeds}
        self._clock = clock
        self._synthetic = synthetic

    def collect(self, targets: Sequence[str]) -> Iterator[RawFetch]:
        """Download each named list (all lists when ``targets`` is empty)."""
        unknown = [t for t in targets if t not in self._feeds]
        if unknown:
            raise ValueError(f"unknown blocklist(s): {unknown}")
        for name in targets or list(self._feeds):
            feed = self._feeds[name]
            response = self._http.get(feed.url)
            yield RawFetch(
                source_type=self.source_type,
                source_name=feed.name,
                url=feed.url,
                fetched_at=self._clock(),
                body=response.body,
                truncated=response.truncated,
                http_status=response.status_code,
                content_type=response.headers.get("content-type"),
                headers=response.headers,
                synthetic=self._synthetic,
                request_meta={
                    "feed": feed.name,
                    "platform": "blocklist",
                    "request": "blocklist",
                    "format": feed.format,
                    "redirects": list(response.redirects),
                },
            )
