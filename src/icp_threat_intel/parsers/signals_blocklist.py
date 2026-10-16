"""Blocklist snapshots (``collectors/signals_blocklist.py``) -> events. No I/O.

* ``signal.blocklist_polled`` (subject: the feed): parse status, entry count, ICP gateway
  hosts, canisters found, and ICP hosts that name no valid canister;
* ``signal.canister_listed`` (subject: the canister), one per canister, with every listed
  host naming it, in canister-id order. IOC enrichment marks the ones already known.

A truncated download is reported as such and yields no canisters, since a cut-off list is
incomplete rather than empty.
"""

from collections import defaultdict
from typing import Any

from icp_threat_intel.collectors.signals_blocklist import canister_from_host, extract_domains
from icp_threat_intel.core.models import Event, RawSnapshot
from icp_threat_intel.parsers.base import canister_event

LIST_KIND = "phishing_and_scam_domains"
_GATEWAY_SUFFIXES = (".icp0.io", ".ic0.app")


def _polled(snapshot: RawSnapshot, parser_id: str, feed: str, payload: dict[str, Any]) -> Event:
    return Event(
        kind="signal.blocklist_polled",
        subject_type="signal_feed",
        subject_id=feed,
        observed_at=snapshot.fetched_at,
        source_type=snapshot.source_type,
        parser=parser_id,
        raw_snapshot_id=snapshot.id,
        payload={
            "http_status": snapshot.http_status,
            "feed": feed,
            **payload,
            "synthetic": snapshot.synthetic,
        },
    )


def blocklist_events(snapshot: RawSnapshot, parser_id: str, feed: str) -> tuple[Event, ...]:
    if snapshot.http_status != 200:
        return (_polled(snapshot, parser_id, feed, {"status": "error"}),)
    if snapshot.truncated:
        return (_polled(snapshot, parser_id, feed, {"status": "truncated"}),)
    domains = extract_domains(snapshot.body)
    if domains is None:
        return (_polled(snapshot, parser_id, feed, {"status": "unusable_body"}),)
    ic_hosts = sorted({d for d in domains if d.endswith(_GATEWAY_SUFFIXES)})
    hosts_by_canister: dict[str, list[str]] = defaultdict(list)
    for host in ic_hosts:
        canister_id = canister_from_host(host)
        if canister_id is not None:
            hosts_by_canister[canister_id].append(host)
    mapped = sum(len(h) for h in hosts_by_canister.values())
    summary = {
        "status": "ok",
        "entries": len(domains),
        "ic_hosts": len(ic_hosts),
        "canisters": len(hosts_by_canister),
        "unmapped_ic_hosts": len(ic_hosts) - mapped,
    }
    listed = [
        canister_event(
            snapshot,
            parser_id,
            "signal.canister_listed",
            canister_id,
            {"feed": feed, "list": LIST_KIND, "hosts": hosts_by_canister[canister_id]},
        )
        for canister_id in sorted(hosts_by_canister)
    ]
    return (_polled(snapshot, parser_id, feed, summary), *listed)
