"""Webhook notifier: POSTs each notification as JSON to one configured https URL.

It goes through the shared ``SafeHttpClient`` with the webhook's host as its only extra
allowed host, so the allowlist, timeout, rate limit and redirect rules still apply.
"""

import json
import urllib.parse

import structlog

from icp_threat_intel.core.http import SafeHttpClient
from icp_threat_intel.core.models import Notification

log = structlog.get_logger(__name__)


class WebhookFailed(RuntimeError):
    """The webhook answered with a non-2xx status."""


def webhook_host(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("the webhook URL must be an https URL with a host")
    return parts.hostname


class WebhookNotifier:
    name = "webhook"

    def __init__(self, url: str, http: SafeHttpClient) -> None:
        webhook_host(url)
        self._url = url
        self._http = http

    @classmethod
    def from_settings(cls, url: str, contact: str) -> "WebhookNotifier":
        return cls(url, SafeHttpClient(contact, extra_hosts=[webhook_host(url)]))

    def notify(self, message: Notification) -> None:
        body = json.dumps(
            {"kind": message.kind, "title": message.title, "markdown": message.markdown,
             "data": message.data},
            sort_keys=True,
        ).encode()  # fmt: skip
        response = self._http.post(
            self._url, content=body, headers={"Content-Type": "application/json"}
        )
        if not 200 <= response.status_code < 300:
            log.warning("webhook_failed", status=response.status_code)
            raise WebhookFailed(f"webhook returned HTTP {response.status_code}")
