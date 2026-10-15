"""Webhook notifier, mocked with respx; plus scheduler cadences."""

import json
from datetime import timedelta

import httpx
import pytest
import respx
from apscheduler.schedulers.background import BackgroundScheduler

from icp_threat_intel.alerting.digest import verified_alert
from icp_threat_intel.alerting.webhook import WebhookFailed, WebhookNotifier, webhook_host
from icp_threat_intel.core.http import HostNotAllowed, SafeHttpClient
from icp_threat_intel.scheduler.jobs import DEFAULT_CADENCES, build_scheduler
from tests.exporters.conftest import verified_h1

HOOK = "https://hooks.example.org/icp-threat-intel"


@respx.mock
def test_webhook_posts_json() -> None:
    route = respx.post(HOOK).mock(return_value=httpx.Response(204))
    notifier = WebhookNotifier.from_settings(HOOK, "test@example.invalid")
    notifier.notify(verified_alert(verified_h1()))
    assert route.called
    request = route.calls.last.request
    assert request.headers["content-type"] == "application/json"
    assert "icp-threat-intel" in request.headers["user-agent"]
    body = json.loads(request.content)
    assert body["kind"] == "alert" and body["title"].startswith("VERIFIED H1")
    assert body["data"]["status"] == "verified"


@respx.mock
def test_webhook_error_status_raises() -> None:
    respx.post(HOOK).mock(return_value=httpx.Response(400))
    with pytest.raises(WebhookFailed):
        WebhookNotifier.from_settings(HOOK, "test@example.invalid").notify(
            verified_alert(verified_h1())
        )


@respx.mock
def test_webhook_host_is_the_only_extra_host() -> None:
    respx.post("https://evil.example/").mock(return_value=httpx.Response(200))
    http = SafeHttpClient("test@example.invalid", extra_hosts=[webhook_host(HOOK)])
    notifier = WebhookNotifier("https://evil.example/", http)
    with pytest.raises(HostNotAllowed):
        notifier.notify(verified_alert(verified_h1()))


@pytest.mark.parametrize("url", ["http://hooks.example.org/x", "not a url", "https:///nohost"])
def test_webhook_url_must_be_https_with_host(url: str) -> None:
    with pytest.raises(ValueError):
        WebhookNotifier.from_settings(url, "test@example.invalid")


def test_scheduler_cadences() -> None:
    assert DEFAULT_CADENCES["ioc_canister_state"] == timedelta(hours=1)
    assert DEFAULT_CADENCES["raw_gateway"] == timedelta(hours=6)
    assert DEFAULT_CADENCES["census"] == timedelta(weeks=1)
    for daily in ("registries", "ledger", "proposals", "digest"):
        assert DEFAULT_CADENCES[daily] == timedelta(days=1)
    calls: list[str] = []
    sched = build_scheduler(
        {"digest": lambda: calls.append("digest")},
        cadences={"census": timedelta(days=2)},
        scheduler=BackgroundScheduler(timezone="UTC"),
    )
    jobs = {j.id: j for j in sched.get_jobs()}
    assert set(jobs) == set(DEFAULT_CADENCES)
    assert jobs["census"].trigger.interval == timedelta(days=2)
    jobs["digest"].func()
    jobs["ledger"].func()  # no-op placeholder
    assert calls == ["digest"]
    with pytest.raises(ValueError):
        build_scheduler({"nope": lambda: None}, scheduler=BackgroundScheduler(timezone="UTC"))
    with pytest.raises(ValueError):
        build_scheduler(
            {}, cadences={"digest": timedelta(0)}, scheduler=BackgroundScheduler(timezone="UTC")
        )
