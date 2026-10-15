"""Query-only IC client (SPEC guardrail 1).

The public surface is exactly ``query`` and ``read_state``, sent as the anonymous principal
over the shared allowlisted HTTP client. No method exists that changes canister state,
installs code, creates canisters or moves ICP or cycles, and the envelope builder rejects
every other request type.

The read_state certificate is returned as received; ``core/ic_certificate.py`` decodes it.
read_state uses the v3 endpoint (v2 is deprecated, see docs/sources/read-state.md).
"""

import re
from collections.abc import Mapping, Sequence
from typing import Any

from icp_threat_intel.core.http import FetchResponse, SafeHttpClient
from icp_threat_intel.core.ic_encoding import (
    build_envelope,
    decode_cbor,
    encode_cbor,
    principal_from_text,
)

DEFAULT_BOUNDARY = "https://icp-api.io"
_CBOR_HEADERS = {"Content-Type": "application/cbor"}
# Method-name words that indicate a state change. Such methods are refused outright, even
# though a query execution would discard any state change.
_DENIED_WORDS = frozenset(
    {
        "install", "reinstall", "upgrade", "uninstall", "create", "delete", "update", "set",
        "put", "transfer", "top", "topup", "deposit", "withdraw", "mint", "burn", "approve",
        "send", "notify", "stop", "start", "provisional", "sign", "claim", "stake", "disburse",
    }
)  # fmt: skip
_WORD_SPLIT = re.compile(r"[^a-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")


class IcRequestRefused(ValueError):
    """The requested target or method is not permitted for a read-only client."""


class IcReject(Exception):
    """The replica rejected the query."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"reject {code}: {message}")
        self.code = code
        self.message = message


class IcHttpError(Exception):
    """The boundary node answered with a non-200 status (or an unusable body)."""

    def __init__(self, message: str, *, status_code: int | None = None, body: bytes = b"") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


def _method_words(method: str) -> set[str]:
    return {w.lower() for w in _WORD_SPLIT.split(method) if w}


class IcClient:
    """Anonymous, read-only access to the IC: query and read_state only."""

    def __init__(self, http: SafeHttpClient, *, boundary: str = DEFAULT_BOUNDARY) -> None:
        self._http = http
        self._boundary = boundary.rstrip("/")

    def query(self, canister_id: str, method: str, arg: bytes) -> bytes:
        """Run a query method and return the Candid-encoded reply bytes."""
        self._check_target(canister_id)
        denied = _method_words(method) & _DENIED_WORDS
        if denied:
            raise IcRequestRefused(f"method {method!r} looks state-changing: {sorted(denied)}")
        envelope = build_envelope(
            "query", canister_id=canister_id, fields={"method_name": method, "arg": arg}
        )
        reply = self._post(canister_id, "query", envelope)
        status = reply.get("status")
        if status == "replied":
            return bytes(reply["reply"]["arg"])
        if status == "rejected":
            raise IcReject(int(reply.get("reject_code", 0)), str(reply.get("reject_message", "")))
        raise IcHttpError(f"unexpected query status {status!r}")

    def read_state(self, canister_id: str, paths: Sequence[Sequence[bytes]]) -> bytes:
        """Read state paths and return the certificate bytes as received."""
        self._check_target(canister_id)
        envelope = build_envelope(
            "read_state",
            canister_id=canister_id,
            fields={"paths": [[bytes(label) for label in path] for path in paths]},
        )
        reply = self._post(canister_id, "read_state", envelope, version="v3")
        return bytes(reply["certificate"])

    @staticmethod
    def _check_target(canister_id: str) -> None:
        if principal_from_text(canister_id) == b"":
            raise IcRequestRefused("the management canister is not a permitted target")

    def _post(
        self, canister_id: str, endpoint: str, envelope: dict[str, Any], *, version: str = "v2"
    ) -> dict[str, Any]:
        url = f"{self._boundary}/api/{version}/canister/{canister_id}/{endpoint}"
        response: FetchResponse = self._http.post(
            url, content=encode_cbor(envelope), headers=_CBOR_HEADERS
        )
        if response.status_code != 200:
            raise IcHttpError(
                f"{endpoint} returned HTTP {response.status_code}",
                status_code=response.status_code,
                body=response.body,
            )
        decoded = decode_cbor(response.body)
        if not isinstance(decoded, Mapping):
            raise IcHttpError(f"{endpoint} returned a non-map CBOR body")
        return dict(decoded)
