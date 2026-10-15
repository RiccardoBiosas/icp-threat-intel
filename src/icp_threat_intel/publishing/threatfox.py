"""ThreatFox ``submit_ioc`` bodies, written to a file for a human to review (never sent).

Format from docs/sources/threatfox.md. A canister ID is not a ThreatFox IOC type, so it is
exported as its gateway domains. File paths, systemd units, package versions and accounts
have no ThreatFox type and are listed under ``skipped``. Every batch carries the ``ICP-C2``
tag. Nothing here talks to the network.
"""

import json
from collections import defaultdict
from typing import Any

from icp_threat_intel.core.enums import IocType
from icp_threat_intel.core.models import Case, Ioc
from icp_threat_intel.publishing.case import GatedExporter, gateway_hosts

DEFAULT_MALWARE = "unknown"  # exact ThreatFox value to confirm with malware_list (note)
DEFAULT_THREAT_TYPE = "payload_delivery"
_TAG_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.- ")


def _tags(ioc: Ioc) -> list[str]:
    tags = {"ICP-C2", *ioc.tags}
    return sorted(t for t in tags if t and set(t) <= _TAG_OK)


def _entries(ioc: Ioc) -> list[tuple[str, str]]:
    if ioc.ioc_type is IocType.URL:
        return [("url", ioc.value)]
    if ioc.ioc_type is IocType.DOMAIN:
        return [("domain", ioc.value)]
    if ioc.ioc_type is IocType.CANISTER_ID:
        return [("domain", host) for host in gateway_hosts(ioc.value)]
    return []


class ThreatFoxExporter(GatedExporter):
    format = "threatfox"

    def render(self, case: Case) -> bytes:
        groups: dict[tuple[Any, ...], list[str]] = defaultdict(list)
        refs: dict[tuple[Any, ...], set[str]] = defaultdict(set)
        skipped = []
        for ioc in case.iocs:
            entries = _entries(ioc)
            if not entries:
                skipped.append({"ioc_type": ioc.ioc_type.value, "value": ioc.value})
                continue
            for ioc_type, value in entries:
                threat = ioc.threat_type or DEFAULT_THREAT_TYPE
                malware = ioc.malware or DEFAULT_MALWARE
                key = (ioc_type, threat, malware, ioc.confidence or 50, tuple(_tags(ioc)))
                if value not in groups[key]:
                    groups[key].append(value)
                if ioc.source_url:
                    refs[key].add(ioc.source_url)
        submissions = []
        for key in sorted(groups):
            ioc_type, threat_type, malware, confidence, tags = key
            submissions.append(
                {
                    "query": "submit_ioc",
                    "threat_type": threat_type,
                    "ioc_type": ioc_type,
                    "malware": malware,
                    "confidence_level": min(max(int(confidence), 0), 100),
                    "is_compromised": False,
                    "anonymous": 0,
                    "reference": sorted(refs[key])[0] if refs[key] else "",
                    "tags": list(tags),
                    "comment": f"{case.title} (case {case.case_id})",
                    "iocs": sorted(groups[key]),
                }
            )
        doc = {
            "format": "threatfox submit_ioc",
            "review_required": "Review against the ThreatFox submission policy, then submit "
            "by hand. This file was not sent anywhere.",
            "case_id": case.case_id,
            "submissions": submissions,
            "skipped": skipped,
        }
        return json.dumps(doc, indent=2, sort_keys=True).encode() + b"\n"
