"""H3: supply-chain references to IC canisters in registry artifacts."""

import re
from collections.abc import Sequence
from typing import Any, ClassVar

from icp_threat_intel.core.models import Event
from icp_threat_intel.rules.base import CANISTER_ID_RE, BaseRule

# A host position: after "//" (URL authority) or not preceded by a host or path character.
GATEWAY_HOST_RE = re.compile(
    r"(?:(?<=//)|(?<![a-z0-9./_-]))(?:[a-z0-9-]+\.)*(?:icp0\.io|ic0\.app|icp-api\.io)"
    r"(?!\.?[a-z0-9_-])",
    re.I,
)
# ThreatFox 1781006 host indicators; matched as text, never used as a path.
HOST_INDICATOR_RE = re.compile(
    r"/tmp/pglog\b|\bpgmon\.service\b"  # noqa: S108
    r"|\.config/systemd/user/[\w@.-]+\.service|\bsystemctl\s+--user\b",
    re.I,
)
INSTALL_LOCATIONS = frozenset({"preinstall", "install", "postinstall", "setup.py", ".pth"})


def ic_references(text: str) -> dict[str, list[str]]:
    """Canister IDs, gateway hosts and host indicators found in ``text`` (data only)."""
    found = {
        "canister_ids": CANISTER_ID_RE.findall(text.lower()),
        "gateway_hosts": [m.lower() for m in GATEWAY_HOST_RE.findall(text)],
        "host_indicators": HOST_INDICATOR_RE.findall(text),
    }
    return {k: sorted(set(v)) for k, v in found.items() if v}


def _texts(payload: dict[str, Any]) -> list[str]:
    texts = payload.get("texts")
    out = [t for t in texts if isinstance(t, str)] if isinstance(texts, list) else []
    if isinstance(payload.get("text"), str):
        out.append(payload["text"])
    return out


def event_references(event: Event) -> dict[str, list[str]]:
    merged: dict[str, set[str]] = {}
    for text in _texts(event.payload):
        for key, values in ic_references(text).items():
            merged.setdefault(key, set()).update(values)
    return {k: sorted(v) for k, v in sorted(merged.items())}


class H3SupplyChainReference(BaseRule):
    """Supply-chain references: a package version that points at IC infrastructure.

    Precedents (SPEC section 3):

    * CanisterWorm (March 2026): compromised npm packages polled canister
      ``tdtqy-oyaaa-aaaae-af2dq-cai`` as a dead-drop resolver.
    * ThreatFox IOC 1781006: npm ``@opengov/form-renderer`` 0.2.20 used that canister's
      ``raw.icp0.io`` URL to fetch a binary to ``/tmp/pglog``, run by a systemd user
      service ``pgmon.service``.
    * CanisterSprawl (April 2026): npm and PyPI packages spread through ``.pth`` injection
      and exfiltrated to canister ``cjn37-uyaaa-aaaac-qgnva-cai``.

    Signals (both required, for one package version as subject):

    * ``registry_artifact``: a ``package.version_published`` event.
    * ``ic_reference``: a ``package.canister_reference`` event whose ``text``/``texts``
      (install hooks, ``.pth`` lines, setup.py, decoded strings) match the canister-ID
      regex, an IC gateway host (``icp0.io``, ``ic0.app``, ``raw.icp0.io``,
      ``icp-api.io``) or a host indicator (``/tmp/pglog``, ``pgmon.service``, systemd
      user units). The rule only pattern-matches the stored text; it never fetches it.
    """

    id: ClassVar[str] = "H3"
    hypothesis: ClassVar[str] = "Supply-chain references"
    required_signals: ClassVar[frozenset[str]] = frozenset({"registry_artifact", "ic_reference"})

    def signals(self, events: Sequence[Event]) -> dict[str, list[Event]]:
        return {
            "registry_artifact": [e for e in events if e.kind == "package.version_published"],
            "ic_reference": [
                e for e in events if e.kind == "package.canister_reference" and event_references(e)
            ],
        }

    def assess(self, support: dict[str, list[Event]]) -> tuple[float, str]:
        refs: dict[str, set[str]] = {}
        locations: set[str] = set()
        for event in support["ic_reference"]:
            for key, values in event_references(event).items():
                refs.setdefault(key, set()).update(values)
            if isinstance(event.payload.get("location"), str):
                locations.add(event.payload["location"])
        score = 0.6
        score += 0.2 if "canister_ids" in refs else 0.0
        score += 0.1 if "gateway_hosts" in refs else 0.0
        score += 0.1 if "host_indicators" in refs else 0.0
        score += 0.1 if locations & INSTALL_LOCATIONS else 0.0
        found = "; ".join(f"{k}: {', '.join(sorted(v))}" for k, v in sorted(refs.items()))
        where = f" in {', '.join(sorted(locations))}" if locations else ""
        return score, f"Package version references IC infrastructure{where} ({found})."
