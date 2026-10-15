"""ThreatFox submit_ioc export."""

import json

import pytest

from icp_threat_intel.core.models import Case
from icp_threat_intel.publishing.gate import DisclosureRequired
from icp_threat_intel.publishing.threatfox import ThreatFoxExporter
from tests.exporters.conftest import TDTQY

REQUIRED = {"query", "threat_type", "ioc_type", "malware", "iocs"}


def test_refuses_undisclosed_case(undisclosed: Case) -> None:
    with pytest.raises(DisclosureRequired):
        ThreatFoxExporter().export(undisclosed)


def test_submission_bodies(case: Case) -> None:
    doc = json.loads(ThreatFoxExporter().export(case))
    assert doc["case_id"] == case.case_id and "not sent" in doc["review_required"]
    subs = doc["submissions"]
    assert subs
    for sub in subs:
        assert set(sub) >= REQUIRED and sub["query"] == "submit_ioc"
        assert sub["ioc_type"] in {"url", "domain"}
        assert "ICP-C2" in sub["tags"]
        assert all(
            set(t) <= set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.- ")
            for t in sub["tags"]
        )
        assert 0 <= sub["confidence_level"] <= 100 and sub["is_compromised"] is False
        assert len({sub["ioc_type"]}) == 1 and sub["iocs"] == sorted(set(sub["iocs"]))
    urls = [i for s in subs if s["ioc_type"] == "url" for i in s["iocs"]]
    assert f"https://{TDTQY}.raw.icp0.io/" in urls  # ThreatFox 1781006
    domains = [i for s in subs if s["ioc_type"] == "domain" for i in s["iocs"]]
    assert f"{TDTQY}.raw.icp0.io" in domains
    skipped = {s["value"] for s in doc["skipped"]}
    assert "/tmp/pglog" in skipped and "pgmon.service" in skipped


def test_deterministic(case: Case) -> None:
    assert ThreatFoxExporter().export(case) == ThreatFoxExporter().export(case)
