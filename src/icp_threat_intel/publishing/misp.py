"""MISP event JSON (``{"Event": {...}}``), unpublished and limited to your organisation.

``distribution`` is 0 and ``published`` is false: sharing further is a human decision in
MISP after review. Canister IDs are exported as a text attribute plus their gateway
domains; attribute UUIDs are deterministic.
"""

import json
from pathlib import PurePosixPath
from typing import Any

from icp_threat_intel.core.enums import IocType
from icp_threat_intel.core.models import Case, Ioc
from icp_threat_intel.publishing.case import GatedExporter, gateway_hosts, stable_uuid
from icp_threat_intel.publishing.gate import DisclosureRequired


def _attributes(ioc: Ioc) -> list[tuple[str, str, str]]:
    """(category, type, value) triples for one IOC."""
    if ioc.ioc_type is IocType.URL:
        return [("Network activity", "url", ioc.value)]
    if ioc.ioc_type is IocType.DOMAIN:
        return [("Network activity", "domain", ioc.value)]
    if ioc.ioc_type is IocType.CANISTER_ID:
        return [("Network activity", "text", ioc.value)] + [
            ("Network activity", "domain", host) for host in gateway_hosts(ioc.value)
        ]
    if ioc.ioc_type is IocType.FILE_PATH:
        return [("Artifacts dropped", "filename", ioc.value)]
    if ioc.ioc_type is IocType.SYSTEMD_UNIT:
        return [("Persistence mechanism", "filename", PurePosixPath(ioc.value).name)]
    if ioc.ioc_type is IocType.PACKAGE_VERSION:
        return [("Payload delivery", "text", ioc.value)]
    return [("Other", "text", ioc.value)]


class MispExporter(GatedExporter):
    format = "misp"

    def render(self, case: Case) -> bytes:
        if case.disclosed_at is None:  # export() checked already; render() may be called alone
            raise DisclosureRequired(f"case {case.case_id} has no disclosed_at")
        attributes: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for ioc in case.iocs:
            for category, attr_type, value in _attributes(ioc):
                if (attr_type, value) in seen:
                    continue
                seen.add((attr_type, value))
                comment = " | ".join(
                    p for p in (f"{ioc.source_type.value}:{ioc.source_ref}", ioc.source_url) if p
                )
                attributes.append(
                    {
                        "uuid": stable_uuid("misp-attr", case.case_id, attr_type, value),
                        "category": category,
                        "type": attr_type,
                        "value": value,
                        "to_ids": attr_type in ("url", "domain"),
                        "distribution": "5",  # inherit the event's distribution
                        "comment": comment,
                    }
                )
        event = {
            "uuid": stable_uuid("misp-event", case.case_id),
            "info": case.title,
            "date": case.disclosed_at.date().isoformat(),
            "threat_level_id": "2",
            "analysis": "2",
            "distribution": "0",
            "published": False,
            "Tag": [{"name": "ICP-C2"}, {"name": "tlp:amber"}],
            "Attribute": attributes,
        }
        return json.dumps({"Event": event}, indent=2).encode() + b"\n"
