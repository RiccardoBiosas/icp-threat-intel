"""Parse raw-gateway snapshots (``collectors/raw_gateway.py``) into events. No I/O.

* the ``http_request`` query pre-check gives ``gateway.http_request_queried`` (outcome,
  ``upgrade`` flag, the canister's own status code and its body, classified);
* each raw-domain GET gives ``gateway.body_observed`` (outcome, HTTP status, gateway error
  cause, size, sha256, truncation and the body class from ``core/bodies.py``).

Bodies are data (guardrail 2): they are only classified by pattern matching, and a short
text excerpt is kept for rules. A 451 ``denylisted`` answer is flagged, because it is how
the gateway reports a policy takedown (docs/sources/raw-gateway.md).
"""

import hashlib
from typing import Any

from icp_threat_intel.core.bodies import BodyClass, classify_body
from icp_threat_intel.core.candid_wire import CandidDecodeError, decode, field_hash
from icp_threat_intel.core.enums import SourceType
from icp_threat_intel.core.models import ParseResult, RawSnapshot
from icp_threat_intel.parsers.base import canister_event

PARSER_NAME = "raw_gateway"
EXCERPT_CHARS = 512
_TEXT_CLASSES = {BodyClass.URL, BodyClass.BASE64_BLOB, BodyClass.SHELL_FRAGMENT, BodyClass.OTHER}
_BODY, _STATUS = field_hash("body"), field_hash("status_code")


def describe_body(body: bytes, *, truncated: bool = False) -> dict[str, Any]:
    """Size, hash, class and (for text classes) a short excerpt of ``body``."""
    body_class = classify_body(body)
    out: dict[str, Any] = {
        "size": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_class": body_class.value,
        "truncated": truncated,
    }
    if body_class in _TEXT_CLASSES:
        out["excerpt"] = body.decode("utf-8")[:EXCERPT_CHARS]
    return out


def _header(headers: dict[str, Any], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name:
            return str(value)
    return None


class RawGatewayParser:
    source_type = SourceType.RAW_GATEWAY
    version = "1"

    @property
    def parser_id(self) -> str:
        return f"{PARSER_NAME}@{self.version}"

    def parse(self, snapshot: RawSnapshot) -> ParseResult:
        meta = snapshot.request_meta
        canister_id = str(meta["canister_id"])
        if meta.get("request") == "http_request_query":
            payload = self._precheck(snapshot)
            kind = "gateway.http_request_queried"
        else:
            payload = self._get(snapshot)
            kind = "gateway.body_observed"
        event = canister_event(snapshot, self.parser_id, kind, canister_id, payload)
        return ParseResult(events=(event,))

    @staticmethod
    def _precheck(snapshot: RawSnapshot) -> dict[str, Any]:
        meta = snapshot.request_meta
        payload: dict[str, Any] = {
            "outcome": meta.get("outcome"),
            "upgrade": meta.get("upgrade"),
            "http_status": snapshot.http_status,
        }
        if meta.get("outcome") not in ("ok", "upgrade_requested"):
            payload["reject_code"] = meta.get("reject_code")
            return payload
        try:
            (record, *_rest) = decode(snapshot.body)
        except (CandidDecodeError, ValueError):
            return payload | {"outcome": "undecodable"}
        if isinstance(record, dict):
            payload["response_status_code"] = record.get(_STATUS)
            body = record.get(_BODY)
            if isinstance(body, bytes):
                payload |= describe_body(body)
        return payload

    @staticmethod
    def _get(snapshot: RawSnapshot) -> dict[str, Any]:
        meta = snapshot.request_meta
        error_cause = _header(snapshot.headers, "x-ic-error-cause")
        payload: dict[str, Any] = {
            "domain": meta.get("domain"),
            "url": snapshot.url,
            "outcome": meta.get("outcome"),
            "http_status": snapshot.http_status,
            "content_type": snapshot.content_type,
            "error_cause": error_cause,
            "denylisted": snapshot.http_status == 451 or error_cause == "denylisted",
            "redirects": list(meta.get("redirects", [])),
        }
        if meta.get("outcome") == "redirect_refused":
            payload["location"] = meta.get("location")  # data, never followed
        if meta.get("outcome") == "ok":
            payload |= describe_body(snapshot.body, truncated=snapshot.truncated)
            payload["body_sha256"] = snapshot.sha256  # hash of the bytes as fetched
        return payload
