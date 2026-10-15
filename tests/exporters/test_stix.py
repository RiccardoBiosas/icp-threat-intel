"""STIX 2.1 bundle export."""

import json
import re

import pytest

from icp_threat_intel.core.enums import IocType, SourceType
from icp_threat_intel.core.models import Case, Ioc
from icp_threat_intel.publishing.gate import DisclosureRequired
from icp_threat_intel.publishing.stix import StixExporter, pattern
from tests.exporters.conftest import TDTQY

ID_RE = re.compile(
    r"^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
TS_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")


def test_refuses_undisclosed_case(undisclosed: Case) -> None:
    with pytest.raises(DisclosureRequired):
        StixExporter().export(undisclosed)
    with pytest.raises(DisclosureRequired):
        StixExporter().render(undisclosed)


def test_bundle_shape(case: Case) -> None:
    bundle = json.loads(StixExporter().export(case))
    assert bundle["type"] == "bundle" and ID_RE.match(bundle["id"])
    objects = bundle["objects"]
    ids = {o["id"] for o in objects}
    assert len(ids) == len(objects)
    for obj in objects:
        assert obj["spec_version"] == "2.1" and ID_RE.match(obj["id"])
        assert obj["id"].startswith(obj["type"] + "--")
        assert TS_RE.match(obj["created"]) and TS_RE.match(obj["modified"])
    indicators = [o for o in objects if o["type"] == "indicator"]
    assert indicators
    for ind in indicators:
        assert ind["pattern_type"] == "stix" and ind["pattern"].startswith("[")
        assert ind["created_by_ref"] in ids and TS_RE.match(ind["valid_from"])
        assert ind["indicator_types"] == ["malicious-activity"]
    (report,) = [o for o in objects if o["type"] == "report"]
    assert set(report["object_refs"]) == {i["id"] for i in indicators}
    assert report["published"] == "2026-10-14T09:00:00.000Z"
    patterns = " ".join(i["pattern"] for i in indicators)
    assert f"domain-name:value = '{TDTQY}.raw.icp0.io'" in patterns
    assert "file:name = 'pglog'" in patterns


def test_pattern_escaping_and_types() -> None:
    def ioc(t: IocType, v: str) -> Ioc:
        return Ioc(
            ioc_type=t, value=v, source_type=SourceType.THREATFOX, source_ref="r", source_url=""
        )

    assert pattern(ioc(IocType.URL, "https://x/'a\\b")) == "[url:value = 'https://x/\\'a\\\\b']"
    assert pattern(ioc(IocType.PACKAGE_VERSION, "@opengov/form-renderer@0.2.20")) == (
        "[software:name = '@opengov/form-renderer' AND software:version = '0.2.20']"
    )
    assert pattern(ioc(IocType.PACKAGE_VERSION, "noversion")) == "[software:name = 'noversion']"
    assert pattern(ioc(IocType.ACCOUNT, "abc")) is None


def test_deterministic(case: Case) -> None:
    assert StixExporter().export(case) == StixExporter().export(case)
