"""STIX 2.1 bundle: identity, one indicator per IOC, and a report tying them together.

IDs are deterministic (UUID5), so re-exporting a case gives the same bundle. Patterns use
the STIX patterning language with quotes and backslashes escaped; IOC types without a
standard cyber-observable (accounts) are left out of the indicators and named in the
report description.
"""

import json
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any

from icp_threat_intel.core.enums import IocType
from icp_threat_intel.core.models import Case, Ioc
from icp_threat_intel.publishing.case import GatedExporter, gateway_hosts, stable_uuid
from icp_threat_intel.publishing.gate import DisclosureRequired

PRODUCER = "icp-threat-intel"


def _ts(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _q(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def pattern(ioc: Ioc) -> str | None:
    if ioc.ioc_type is IocType.URL:
        return f"[url:value = {_q(ioc.value)}]"
    if ioc.ioc_type is IocType.DOMAIN:
        return f"[domain-name:value = {_q(ioc.value)}]"
    if ioc.ioc_type is IocType.CANISTER_ID:
        hosts = " OR ".join(f"domain-name:value = {_q(h)}" for h in gateway_hosts(ioc.value))
        return f"[{hosts}]"
    if ioc.ioc_type in (IocType.FILE_PATH, IocType.SYSTEMD_UNIT):
        name = PurePosixPath(ioc.value).name
        return f"[file:name = {_q(name)}]"
    if ioc.ioc_type is IocType.PACKAGE_VERSION:
        name, _, version = ioc.value.rpartition("@")
        if name and version:
            return f"[software:name = {_q(name)} AND software:version = {_q(version)}]"
        return f"[software:name = {_q(ioc.value)}]"
    return None


class StixExporter(GatedExporter):
    format = "stix"

    def render(self, case: Case) -> bytes:
        if case.disclosed_at is None:  # export() checked already; render() may be called alone
            raise DisclosureRequired(f"case {case.case_id} has no disclosed_at")
        created = _ts(case.created_at)
        identity_id = f"identity--{stable_uuid('identity', PRODUCER)}"
        objects: list[dict[str, Any]] = [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": identity_id,
                "created": created,
                "modified": created,
                "name": PRODUCER,
                "identity_class": "system",
            }
        ]
        omitted = []
        for ioc in case.iocs:
            pat = pattern(ioc)
            if pat is None:
                omitted.append(f"{ioc.ioc_type.value}:{ioc.value}")
                continue
            valid_from = _ts(ioc.first_seen or case.created_at)
            indicator: dict[str, Any] = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--"
                + stable_uuid("indicator", case.case_id, ioc.ioc_type, ioc.value),
                "created": created,
                "modified": created,
                "created_by_ref": identity_id,
                "name": f"{ioc.ioc_type.value}: {ioc.value}",
                "indicator_types": ["malicious-activity"],
                "pattern": pat,
                "pattern_type": "stix",
                "pattern_version": "2.1",
                "valid_from": valid_from,
                "labels": sorted({"ICP-C2", *ioc.tags}),
            }
            if ioc.expires_at:
                indicator["valid_until"] = _ts(ioc.expires_at)
            if ioc.confidence is not None:
                indicator["confidence"] = ioc.confidence
            if ioc.source_url:
                indicator["external_references"] = [
                    {"source_name": ioc.source_type.value, "url": ioc.source_url,
                     "external_id": ioc.source_ref}
                ]  # fmt: skip
            objects.append(indicator)
        description = case.summary or case.title
        if omitted:
            description += f"\n\nNot expressible as STIX indicators: {', '.join(omitted)}"
        objects.append(
            {
                "type": "report",
                "spec_version": "2.1",
                "id": f"report--{stable_uuid('report', case.case_id)}",
                "created": created,
                "modified": created,
                "created_by_ref": identity_id,
                "name": case.title,
                "description": description,
                "report_types": ["threat-report"],
                "published": _ts(case.disclosed_at),
                "object_refs": [o["id"] for o in objects[1:]] or [identity_id],
            }
        )
        bundle = {
            "type": "bundle",
            "id": f"bundle--{stable_uuid('bundle', case.case_id)}",
            "objects": objects,
        }
        return json.dumps(bundle, indent=2).encode() + b"\n"
