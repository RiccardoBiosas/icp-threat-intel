"""MISP event export."""

import json
import uuid

import pytest

from icp_threat_intel.core.models import Case
from icp_threat_intel.publishing.gate import DisclosureRequired
from icp_threat_intel.publishing.misp import MispExporter
from tests.exporters.conftest import TDTQY


def test_refuses_undisclosed_case(undisclosed: Case) -> None:
    with pytest.raises(DisclosureRequired):
        MispExporter().export(undisclosed)


def test_event_shape(case: Case) -> None:
    event = json.loads(MispExporter().export(case))["Event"]
    uuid.UUID(event["uuid"])
    assert event["info"] == case.title and event["date"] == "2026-10-14"
    assert event["distribution"] == "0" and event["published"] is False
    assert {t["name"] for t in event["Tag"]} >= {"ICP-C2"}
    attrs = event["Attribute"]
    pairs = {(a["type"], a["value"]) for a in attrs}
    assert len(pairs) == len(attrs)  # no duplicate attributes
    assert ("text", TDTQY) in pairs and ("domain", f"{TDTQY}.raw.icp0.io") in pairs
    assert ("filename", "/tmp/pglog") in pairs and ("filename", "pgmon.service") in pairs
    for a in attrs:
        uuid.UUID(a["uuid"])
        assert a["category"] and a["to_ids"] == (a["type"] in ("url", "domain"))


def test_deterministic(case: Case) -> None:
    assert MispExporter().export(case) == MispExporter().export(case)
